// SPDX-License-Identifier: GPL-3.0-or-later
//! Alternative engine on smoltcp (through `netstack-smoltcp`), for the Spike 1
//! comparison. Same relays and observer as the ipstack engine; only the stack differs.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::dns::DnsCache;
use crate::relay::{self, Ctx};
use crate::{EngineConfig, EngineStats, Observer, Protect, TunDevice};

type FlowKey = (SocketAddr, SocketAddr);
type Sessions = Arc<Mutex<HashMap<FlowKey, (u64, mpsc::Sender<Vec<u8>>)>>>;

/// Datagrams queued per UDP flow before new ones are dropped (UDP may lose packets).
const UDP_QUEUE: usize = 256;

/// Run the engine on smoltcp until the tunnel closes. See [`crate::run`].
pub async fn run_smoltcp(
    device: TunDevice,
    protect: Arc<dyn Protect>,
    observer: Arc<dyn Observer>,
    config: EngineConfig,
    stats: Arc<EngineStats>,
) -> io::Result<()> {
    let mut builder = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(usize::from(config.mtu));
    if let Some(size) = config.tcp_buffer {
        builder = builder
            .tcp_send_buffer_size(size)
            .tcp_recv_buffer_size(size);
    }
    let (stack, runner, udp, tcp) = builder.build()?;
    let missing = |what| io::Error::other(format!("netstack-smoltcp did not create {what}"));
    let runner = runner.ok_or_else(|| missing("the TCP runner"))?;
    let udp = udp.ok_or_else(|| missing("the UDP socket"))?;
    let mut tcp = tcp.ok_or_else(|| missing("the TCP listener"))?;
    tokio::spawn(runner);

    let mtu = usize::from(config.mtu);
    let ctx = Arc::new(Ctx {
        protect,
        observer,
        dns: DnsCache::new(config.dns_cache_capacity),
        config,
        stats,
        next_id: AtomicU64::new(1),
    });

    // Packets between the tunnel and the stack.
    let (mut dev_rx, mut dev_tx) = tokio::io::split(device);
    let (mut stack_tx, mut stack_rx) = stack.split();
    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; mtu + 64];
        loop {
            let n = dev_rx.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), io::Error>(());
            }
            stack_tx.send(buf[..n].to_vec()).await?;
        }
    });
    tokio::spawn(async move {
        while let Some(Ok(packet)) = stack_rx.next().await {
            if dev_tx.write(&packet).await.is_err() {
                break;
            }
        }
    });

    // UDP: one shared socket from the stack; we keep our own flow table.
    let (mut udp_rx, mut udp_tx) = udp.split();
    let (to_app_tx, mut to_app_rx) = mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(1024);
    tokio::spawn(async move {
        while let Some(msg) = to_app_rx.recv().await {
            if udp_tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let next_session = Arc::new(AtomicU64::new(1));
    {
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            while let Some((data, app, remote)) = udp_rx.next().await {
                let key = (app, remote);
                let existing = sessions
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&key).map(|(_, tx)| tx.clone()));
                if let Some(tx) = existing
                    && tx.try_send(data.clone()).is_ok()
                {
                    continue;
                }
                let (tx, rx) = mpsc::channel(UDP_QUEUE);
                let _ = tx.try_send(data);
                let id = next_session.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut map) = sessions.lock() {
                    map.insert(key, (id, tx));
                }
                let flow = UdpFlow {
                    rx,
                    to_app: to_app_tx.clone(),
                    app,
                    remote,
                    sessions: Arc::clone(&sessions),
                    id,
                };
                tokio::spawn(relay::udp(Arc::clone(&ctx), flow, app, remote));
            }
        });
    }

    while let Some((stream, app, remote)) = tcp.next().await {
        tokio::spawn(relay::tcp(Arc::clone(&ctx), stream, app, remote));
    }
    inbound.await.map_err(io::Error::other)?
}

/// One UDP flow from the shared stack socket, as a datagram-per-read stream.
struct UdpFlow {
    rx: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    app: SocketAddr,
    remote: SocketAddr,
    sessions: Sessions,
    id: u64,
}

impl AsyncRead for UdpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                let n = datagram.len().min(buf.remaining());
                buf.put_slice(&datagram[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdpFlow {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Back to the app: from the remote address, to the app's address.
        match self
            .to_app
            .try_send((datagram.to_vec(), self.remote, self.app))
        {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Poll::Ready(Ok(datagram.len())),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        if let Ok(mut map) = self.sessions.lock() {
            // Only remove our own entry; a newer flow may already use the same key.
            if map
                .get(&(self.app, self.remote))
                .is_some_and(|(id, _)| *id == self.id)
            {
                map.remove(&(self.app, self.remote));
            }
        }
    }
}

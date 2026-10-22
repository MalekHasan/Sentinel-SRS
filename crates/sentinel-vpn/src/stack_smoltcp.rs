// SPDX-License-Identifier: GPL-3.0-or-later
//! The engine on smoltcp (through a patched `netstack-smoltcp`): the default stack
//! (ADR-0006). smoltcp has real TCP flow control, so an app is slowed to the speed of
//! the network instead of the engine buffering its data.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::dns::DnsCache;
use crate::engine::heartbeat;
use crate::relay::{self, Ctx, Reset};
use crate::{EngineConfig, EngineStats, Observer, Protect, TunDevice};

type FlowKey = (SocketAddr, SocketAddr);
type Sessions = Arc<Mutex<HashMap<FlowKey, (u64, mpsc::Sender<Vec<u8>>)>>>;

/// Datagrams queued per UDP flow before new ones are dropped (UDP may lose packets).
const UDP_QUEUE: usize = 256;

/// Run the engine until the tunnel closes or the future is dropped.
///
/// Returns an error of kind `BrokenPipe` when the tunnel closes or fails (for example
/// when the user revokes the VPN), so the app can record a monitoring gap (SP-03).
/// Dropping the future (or aborting its task) stops all flows. If this process dies,
/// Android tears down the tunnel and traffic flows outside it: the engine fails open
/// (SRS NF-07), and the app records a monitoring gap.
pub async fn run(
    device: TunDevice,
    protect: Arc<dyn Protect>,
    observer: Arc<dyn Observer>,
    config: EngineConfig,
    stats: Arc<EngineStats>,
) -> io::Result<()> {
    // Audit A-04: the stack's TCP sockets are bounded too, those still closing after
    // their flow ended included, and none closes for longer than `tcp_linger`.
    let mut builder = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(usize::from(config.mtu))
        .tcp_max_sockets(config.max_flows, Arc::clone(&stats.flows_refused))
        .tcp_linger(config.tcp_linger);
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

    // Every task the engine starts belongs to a `JoinSet` owned by this future, so
    // dropping the future aborts them all and releases the tunnel. Each long-lived task
    // returns its name; if one ends, the engine is broken and `run` returns.
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        if let Err(e) = runner.await {
            log::warn!("netstack-smoltcp runner failed: {e}");
        }
        "TCP runner"
    });

    let mtu = usize::from(config.mtu);
    let ctx = Arc::new(Ctx {
        protect,
        observer,
        dns: DnsCache::new(config.dns_cache_capacity),
        config,
        stats,
        next_id: AtomicU64::new(1),
    });
    // SP-03: it reports on a worker thread, as the flows run, while the runtime can
    // still run its tasks.
    {
        let (stats, period) = (Arc::clone(&ctx.stats), ctx.config.heartbeat);
        tasks.spawn(async move {
            heartbeat(stats, period).await;
            "heartbeat"
        });
    }

    // Packets between the tunnel and the stack. A failed tunnel read or write marks
    // the device closed, which `closed` below reports.
    let closed = device.closed();
    let (mut dev_rx, mut dev_tx) = tokio::io::split(device);
    let (mut stack_tx, mut stack_rx) = stack.split();
    tasks.spawn(async move {
        let mut buf = vec![0u8; mtu + 64];
        while let Ok(n) = dev_rx.read(&mut buf).await
            && n > 0
            && stack_tx.send(buf[..n].to_vec()).await.is_ok()
        {}
        "tunnel reader"
    });
    tasks.spawn(async move {
        while let Some(Ok(packet)) = stack_rx.next().await
            && dev_tx.write(&packet).await.is_ok()
        {}
        "tunnel writer"
    });

    // UDP: one shared socket from the stack; we keep our own flow table.
    let (mut udp_rx, mut udp_tx) = udp.split();
    let (to_app_tx, mut to_app_rx) = mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(1024);
    tasks.spawn(async move {
        while let Some(msg) = to_app_rx.recv().await
            && udp_tx.send(msg).await.is_ok()
        {}
        "UDP writer"
    });
    {
        let ctx = Arc::clone(&ctx);
        tasks.spawn(async move {
            let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
            let mut next_session = 1u64;
            // Owned by this task, so aborting it aborts the UDP flows too.
            let mut flows = JoinSet::new();
            loop {
                let (data, app, remote) = tokio::select! {
                    datagram = udp_rx.next() => match datagram {
                        Some(datagram) => datagram,
                        None => break,
                    },
                    Some(_) = flows.join_next(), if !flows.is_empty() => continue,
                };
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
                let id = next_session;
                next_session += 1;
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
                flows.spawn(relay::udp(Arc::clone(&ctx), flow, app, remote));
            }
            "UDP dispatcher"
        });
    }

    let mut relays = JoinSet::new();
    let closed = closed.wait();
    tokio::pin!(closed);
    loop {
        tokio::select! {
            // Report a closed tunnel in preference to the tasks that ended because of it.
            biased;
            reason = &mut closed => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, reason));
            }
            Some(ended) = tasks.join_next() => {
                let name = ended.unwrap_or("engine");
                return Err(io::Error::other(format!("the engine's {name} task stopped")));
            }
            accepted = tcp.next() => match accepted {
                Some((stream, app, remote)) => {
                    relays.spawn(relay::tcp(Arc::clone(&ctx), stream, app, remote));
                }
                None => return Err(io::Error::other("the TCP listener closed")),
            },
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
        }
    }
}

impl Reset for netstack_smoltcp::TcpStream {
    fn reset(self) {
        netstack_smoltcp::TcpStream::reset(self);
    }
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

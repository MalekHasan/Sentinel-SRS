// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-flow relays between the tunnel and protected upstream sockets.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};

use crate::dns::{DnsCache, parse_dns_response};
use crate::engine::{EngineConfig, EngineStats};
use crate::flow::{FlowCounters, FlowInfo, FlowTotals, HostnameSource, Proto, Verdict, now_ms};
use crate::sni::{ClientHelloScan, scan_client_hello};
use crate::{Observer, Protect};

const BUF: usize = 16 * 1024;
const DNS_PORT: u16 = 53;
/// A DNS flow is one query and its answer. Ending it soon after frees the upstream
/// socket; phones make hundreds of lookups a minute.
const DNS_IDLE: Duration = Duration::from_secs(5);

pub(crate) struct Ctx {
    pub protect: Arc<dyn Protect>,
    pub observer: Arc<dyn Observer>,
    pub dns: DnsCache,
    pub config: EngineConfig,
    pub stats: Arc<EngineStats>,
    pub next_id: AtomicU64,
}

impl Ctx {
    fn new_flow(&self, proto: Proto, src: SocketAddr, dst: SocketAddr) -> FlowInfo {
        self.stats.flows_total.fetch_add(1, Ordering::Relaxed);
        let hostname = self.dns.lookup(&dst.ip());
        FlowInfo {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            proto,
            src,
            dst,
            hostname_source: hostname.as_ref().map(|_| HostnameSource::Dns),
            hostname,
            started_ms: now_ms(),
            counters: Arc::new(FlowCounters::default()),
        }
    }

    fn finish(&self, flow: &FlowInfo, verdict: Verdict) {
        if verdict == Verdict::Block {
            self.stats.flows_blocked.fetch_add(1, Ordering::Relaxed);
        }
        self.observer.flow_ended(
            flow,
            FlowTotals {
                bytes_up: flow.counters.bytes_up(),
                bytes_down: flow.counters.bytes_down(),
                ended_ms: now_ms(),
                verdict,
            },
        );
    }
}

/// Decrements the active-flow gauge however the relay ends.
struct ActiveGuard<'a>(&'a EngineStats);

impl<'a> ActiveGuard<'a> {
    fn new(stats: &'a EngineStats) -> Self {
        stats.flows_active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(stats)
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.flows_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Relay one TCP flow. `client` is the app's connection as terminated by the userspace
/// stack; `src` is the app's address and `dst` the original destination.
pub(crate) async fn tcp<S>(ctx: Arc<Ctx>, client: S, src: SocketAddr, dst: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _active = ActiveGuard::new(&ctx.stats);
    let mut flow = ctx.new_flow(Proto::Tcp, src, dst);
    if ctx.observer.flow_started(&flow) == Verdict::Block {
        // Dropping the stream resets the app's connection.
        ctx.finish(&flow, Verdict::Block);
        return;
    }

    // The app already sees its connection as open: ipstack answered the handshake
    // locally. If the upstream connect fails, dropping the stream resets it.
    let upstream = match connect_tcp(&*ctx.protect, flow.dst, ctx.config.connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            log::debug!(
                "flow {} upstream connect to {} failed: {e}",
                flow.id,
                flow.dst
            );
            ctx.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
            ctx.finish(&flow, Verdict::Allow);
            return;
        }
    };

    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let (mut up_rx, mut up_tx) = upstream.into_split();
    let sni: OnceLock<String> = OnceLock::new();
    let blocked = AtomicBool::new(false);

    // Server-to-client starts at once, so server-first protocols (SSH, SMTP) are not
    // delayed. Client-to-server first inspects the ClientHello, then copies.
    let to_client = copy_counted(&mut up_rx, &mut client_tx, |n| flow.counters.add_down(n));
    let to_server = async {
        let first = read_client_hello(&mut client_rx, ctx.config.sni_wait).await?;
        if let ClientHelloScan::Done(Some(name)) = scan_client_hello(&first) {
            let mut named = flow.clone();
            named.hostname = Some(name.clone());
            named.hostname_source = Some(HostnameSource::Sni);
            let verdict = ctx.observer.hostname_seen(&named, &name);
            let _ = sni.set(name);
            if verdict == Verdict::Block {
                blocked.store(true, Ordering::Relaxed);
                // Nothing from the client has reached the server yet.
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
        }
        if first.is_empty() {
            up_tx.shutdown().await.ok();
            return Ok(());
        }
        up_tx.write_all(&first).await?;
        flow.counters.add_up(first.len());
        copy_counted(&mut client_rx, &mut up_tx, |n| flow.counters.add_up(n)).await
    };
    run_both(to_server, to_client).await;

    if let Some(name) = sni.into_inner() {
        flow.hostname = Some(name);
        flow.hostname_source = Some(HostnameSource::Sni);
    }
    let verdict = if blocked.load(Ordering::Relaxed) {
        Verdict::Block
    } else {
        Verdict::Allow
    };
    ctx.finish(&flow, verdict);
}

/// Read the client's first bytes. If they start a TLS ClientHello, keep reading until
/// the whole first record is here (modern ClientHellos span two TCP segments) or
/// `wait` passes. Returns an empty buffer if the client closes without sending.
async fn read_client_hello<R: AsyncRead + Unpin>(
    client: &mut R,
    wait: Duration,
) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BUF];
    let n = client.read(&mut buf).await?;
    buf.truncate(n);
    if n == 0 || !matches!(scan_client_hello(&buf), ClientHelloScan::NeedMore { .. }) {
        return Ok(buf);
    }
    let deadline = Instant::now() + wait;
    let mut chunk = vec![0u8; BUF];
    loop {
        let n = match timeout_at(deadline, client.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_elapsed) => return Ok(buf),
        };
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if !matches!(scan_client_hello(&buf), ClientHelloScan::NeedMore { .. }) {
            return Ok(buf);
        }
    }
}

async fn connect_tcp(
    protect: &dyn Protect,
    dst: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    let socket = match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    protect.protect(socket.as_fd())?;
    socket.set_nodelay(true)?;
    tokio::time::timeout(connect_timeout, socket.connect(dst))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

async fn copy_counted<R, W, F>(reader: &mut R, writer: &mut W, count: F) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Fn(usize),
{
    let mut buf = vec![0u8; BUF];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // Pass the half-close on, so request/response protocols finish cleanly.
            writer.shutdown().await.ok();
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        count(n);
    }
}

/// Run both directions. A clean end of one direction waits for the other; an error in
/// either ends both.
async fn run_both<A, B>(a: A, b: B)
where
    A: Future<Output = io::Result<()>>,
    B: Future<Output = io::Result<()>>,
{
    tokio::pin!(a, b);
    let (mut a_done, mut b_done) = (false, false);
    while !(a_done && b_done) {
        tokio::select! {
            r = &mut a, if !a_done => { a_done = true; if r.is_err() { return; } }
            r = &mut b, if !b_done => { b_done = true; if r.is_err() { return; } }
        }
    }
}

/// Relay one UDP flow. Each read from `client` returns one datagram from the app, and
/// each write sends one datagram back to it.
pub(crate) async fn udp<S>(ctx: Arc<Ctx>, client: S, src: SocketAddr, dst: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _active = ActiveGuard::new(&ctx.stats);
    let flow = ctx.new_flow(Proto::Udp, src, dst);
    if ctx.observer.flow_started(&flow) == Verdict::Block {
        ctx.finish(&flow, Verdict::Block);
        return;
    }
    let upstream = match connect_udp(&*ctx.protect, flow.dst) {
        Ok(s) => s,
        Err(e) => {
            log::debug!("flow {} UDP socket to {} failed: {e}", flow.id, flow.dst);
            ctx.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
            ctx.finish(&flow, Verdict::Allow);
            return;
        }
    };
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let idle = if flow.dst.port() == DNS_PORT {
        DNS_IDLE
    } else {
        ctx.config.udp_idle_timeout
    };
    let to_server = udp_to_server(&mut client_rx, &upstream, &flow.counters, idle);
    let to_client = udp_to_client(&upstream, &mut client_tx, &ctx, &flow);
    // UDP has no half-close: the flow ends when either side stops.
    tokio::select! {
        _ = to_server => {}
        _ = to_client => {}
    }
    ctx.finish(&flow, Verdict::Allow);
}

async fn udp_to_server<R: AsyncRead + Unpin>(
    client: &mut R,
    upstream: &UdpSocket,
    counters: &FlowCounters,
    idle: Duration,
) -> io::Result<()> {
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        // UDP has no close: a flow ends when the app stops sending for `idle`.
        let n = tokio::time::timeout(idle, client.read(&mut buf))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if n == 0 {
            return Ok(());
        }
        upstream.send(&buf[..n]).await?;
        counters.add_up(n);
    }
}

async fn udp_to_client<W: AsyncWrite + Unpin>(
    upstream: &UdpSocket,
    client: &mut W,
    ctx: &Ctx,
    flow: &FlowInfo,
) -> io::Result<()> {
    let is_dns = flow.dst.port() == DNS_PORT;
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        let n = upstream.recv(&mut buf).await?;
        if is_dns && let Some(answer) = parse_dns_response(&buf[..n]) {
            ctx.dns.insert(&answer);
            let ips: Vec<_> = answer.ips.iter().map(|(ip, _)| *ip).collect();
            ctx.observer.dns_answer(flow, &answer.qname, &ips);
        }
        client.write_all(&buf[..n]).await?;
        flow.counters.add_down(n);
    }
}

fn connect_udp(protect: &dyn Protect, dst: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))?;
    protect.protect(socket.as_fd())?;
    socket.set_nonblocking(true)?;
    let unspecified: SocketAddr = match dst {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    socket.bind(&unspecified.into())?;
    socket.connect(&dst.into())?;
    UdpSocket::from_std(socket.into())
}

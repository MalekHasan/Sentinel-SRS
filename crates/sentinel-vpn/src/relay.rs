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
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use crate::dns::{DnsCache, name_error_reply, parse_dns_query, parse_dns_response};
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
            counters: Arc::new(FlowCounters::new(Arc::clone(&self.config.away))),
        }
    }

    /// The real destination for a flow the app sent to `dst` (see [`crate::DnsForward`]).
    fn upstream_for(&self, dst: SocketAddr) -> io::Result<SocketAddr> {
        match &self.config.dns_forward {
            Some(forward) => forward.route(dst),
            None => Ok(dst),
        }
    }

    /// A view of the firewall's changes from now on: taken before a flow is first
    /// decided, so that no change after that decision goes unseen.
    fn firewall_changes(&self) -> Option<watch::Receiver<u64>> {
        let mut changes = self.config.firewall_changes.clone()?;
        changes.mark_unchanged();
        Some(changes)
    }

    /// Whether one flow too many is open (`active` counts this one): it is then refused
    /// before it is a flow at all, so that no observer, history or upstream socket pays
    /// for it (THREAT-MODEL-A D2).
    fn refused(&self) -> bool {
        let over = self.stats.flows_active.load(Ordering::Relaxed) > self.config.max_flows as u64;
        if over {
            self.stats.flows_refused.fetch_add(1, Ordering::Relaxed);
        }
        over
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
                bytes_up_away: flow.counters.bytes_up_away(),
                bytes_down_away: flow.counters.bytes_down_away(),
                ended_ms: now_ms(),
                verdict,
            },
        );
    }
}

/// The app's side of a TCP flow, as the stack gives it.
pub(crate) trait Reset {
    /// End the connection at once with a reset (RST), as the relay does when it refuses
    /// or blocks a flow, or when the flow fails or idles out. Dropping the connection
    /// instead closes it with a FIN, which the app may leave unanswered (audit A-04).
    fn reset(self);
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
    S: AsyncRead + AsyncWrite + Reset + Unpin + Send + 'static,
{
    let _active = ActiveGuard::new(&ctx.stats);
    if ctx.refused() {
        client.reset();
        return;
    }
    let mut flow = ctx.new_flow(Proto::Tcp, src, dst);
    let changes = ctx.firewall_changes();
    if ctx.observer.flow_started(&flow) == Verdict::Block {
        ctx.finish(&flow, Verdict::Block);
        client.reset();
        return;
    }

    // The app already sees its connection as open: the stack answered the handshake
    // locally. If the upstream connect fails, the app's connection is reset.
    let connected = match ctx.upstream_for(flow.dst) {
        Ok(target) => connect_tcp(&*ctx.protect, target, ctx.config.connect_timeout).await,
        Err(e) => Err(e),
    };
    let upstream = match connected {
        Ok(s) => s,
        Err(e) => {
            log::debug!(
                "flow {} upstream connect to {} failed: {e}",
                flow.id,
                flow.dst
            );
            ctx.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
            ctx.finish(&flow, Verdict::Allow);
            client.reset();
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
        let verdict = match scan_client_hello(&first) {
            ClientHelloScan::Done(Some(name)) => {
                let mut named = flow.clone();
                named.hostname = Some(name.clone());
                named.hostname_source = Some(HostnameSource::Sni);
                let verdict = ctx.observer.hostname_seen(&named, &name);
                let _ = sni.set(name);
                verdict
            }
            // A TLS handshake whose name was not read in time, or cannot be: the server
            // may still see one (audit finding A-03). Not a client that sent nothing.
            ClientHelloScan::NeedMore { .. } | ClientHelloScan::Unreadable if !first.is_empty() => {
                ctx.observer.hostname_unreadable(&flow)
            }
            _ => Verdict::Allow,
        };
        if verdict == Verdict::Block {
            blocked.store(true, Ordering::Relaxed);
            // Nothing from the client has reached the server yet.
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if first.is_empty() {
            up_tx.shutdown().await.ok();
            return Ok(());
        }
        up_tx.write_all(&first).await?;
        flow.counters.add_up(first.len());
        copy_counted(&mut client_rx, &mut up_tx, |n| flow.counters.add_up(n)).await
    };
    // A flow that ends cleanly closes the app's connection; one blocked, failed or idle
    // resets it. Dropping the upstream socket closes the server's side.
    let clean = tokio::select! {
        ended = run_both(to_server, to_client) => ended.is_ok(),
        _ = blocked_later(&ctx, &flow, changes) => {
            blocked.store(true, Ordering::Relaxed);
            false
        }
        // Audit A-18: on smoltcp nothing else ends a connection both sides keep open.
        _ = idle(&flow.counters, ctx.config.tcp_idle_timeout) => {
            log::debug!("flow {} idle for {:?}", flow.id, ctx.config.tcp_idle_timeout);
            false
        }
    };
    if !clean {
        client_rx.unsplit(client_tx).reset();
    }

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
/// the whole ClientHello is here (modern ClientHellos span two TCP segments, and may be
/// split into several records) or `wait` passes. The scan bounds what is kept, at
/// [`crate::MAX_HELLO`] bytes and one read more. Returns an empty buffer if the client
/// closes without sending.
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
/// either ends both, and is returned.
async fn run_both<A, B>(a: A, b: B) -> io::Result<()>
where
    A: Future<Output = io::Result<()>>,
    B: Future<Output = io::Result<()>>,
{
    tokio::pin!(a, b);
    let (mut a_done, mut b_done) = (false, false);
    while !(a_done && b_done) {
        tokio::select! {
            r = &mut a, if !a_done => { a_done = true; r?; }
            r = &mut b, if !b_done => { b_done = true; r?; }
        }
    }
    Ok(())
}

/// Resolves once no byte has moved either way for `limit` (audit A-18). It looks four
/// times per `limit`, so a flow ends between `limit` and 1.25 times `limit` after its
/// last byte. Counted on the monotonic clock, which stands still while a phone sleeps.
/// A zero `limit` is no limit.
async fn idle(counters: &FlowCounters, limit: Duration) {
    if limit.is_zero() {
        return std::future::pending().await;
    }
    let step = limit / 4;
    let moved = || counters.bytes_up() + counters.bytes_down();
    let mut last = moved();
    let mut quiet = Duration::ZERO;
    loop {
        tokio::time::sleep(step).await;
        let now = moved();
        if now == last {
            quiet += step;
            if quiet >= limit {
                return;
            }
        } else {
            last = now;
            quiet = Duration::ZERO;
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
    if ctx.refused() {
        // The datagram is dropped; UDP may lose packets.
        return;
    }
    let flow = ctx.new_flow(Proto::Udp, src, dst);
    let changes = ctx.firewall_changes();
    if ctx.observer.flow_started(&flow) == Verdict::Block {
        ctx.finish(&flow, Verdict::Block);
        return;
    }
    let upstream = match ctx
        .upstream_for(flow.dst)
        .and_then(|target| connect_udp(&*ctx.protect, target))
    {
        Ok(s) => s,
        Err(e) => {
            log::debug!("flow {} UDP socket to {} failed: {e}", flow.id, flow.dst);
            ctx.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
            ctx.finish(&flow, Verdict::Allow);
            return;
        }
    };
    let (mut client_rx, mut client_tx) = tokio::io::split(client);
    let is_dns = flow.dst.port() == DNS_PORT;
    let idle = if is_dns {
        DNS_IDLE
    } else {
        ctx.config.udp_idle_timeout
    };
    // Answers the engine writes itself: "no such name" for a blocked lookup.
    let (replies_tx, replies_rx) = tokio::sync::mpsc::channel(16);
    let lookups = is_dns.then(|| Lookups {
        ctx: &ctx,
        flow: &flow,
        replies: replies_tx,
    });
    let to_server = udp_to_server(&mut client_rx, &upstream, &flow.counters, idle, lookups);
    let to_client = udp_to_client(&upstream, &mut client_tx, &ctx, &flow, replies_rx);
    // UDP has no half-close: the flow ends when either side stops.
    let verdict = tokio::select! {
        _ = to_server => Verdict::Allow,
        _ = to_client => Verdict::Allow,
        _ = blocked_later(&ctx, &flow, changes) => Verdict::Block,
    };
    ctx.finish(&flow, verdict);
}

/// Resolves once a firewall change makes the observer block `flow`; never resolves
/// without changes to watch.
async fn blocked_later(ctx: &Ctx, flow: &FlowInfo, changes: Option<watch::Receiver<u64>>) {
    let Some(mut changes) = changes else {
        return std::future::pending().await;
    };
    // Ends with an error only when the firewall is gone, and then nothing changes.
    while changes.changed().await.is_ok() {
        if ctx.observer.recheck(flow) == Verdict::Block {
            return;
        }
    }
    std::future::pending().await
}

/// The lookups of a DNS flow, each asked about before it is sent.
struct Lookups<'a> {
    ctx: &'a Ctx,
    flow: &'a FlowInfo,
    replies: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl Lookups<'_> {
    /// True if the query was blocked: it was answered "no such name" and must not be
    /// sent.
    fn blocked(&self, query: &[u8]) -> bool {
        let Some(asked) = parse_dns_query(query) else {
            return false;
        };
        if self
            .ctx
            .observer
            .dns_query(self.flow, &asked.name, asked.qtype)
            != Verdict::Block
        {
            return false;
        }
        if let Some(reply) = name_error_reply(query) {
            // A full queue means the app is not reading: its resolver retries.
            let _ = self.replies.try_send(reply);
        }
        true
    }
}

async fn udp_to_server<R: AsyncRead + Unpin>(
    client: &mut R,
    upstream: &UdpSocket,
    counters: &FlowCounters,
    idle: Duration,
    lookups: Option<Lookups<'_>>,
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
        if lookups.as_ref().is_some_and(|l| l.blocked(&buf[..n])) {
            continue;
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
    mut replies: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let is_dns = flow.dst.port() == DNS_PORT;
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        tokio::select! {
            // Both are cancel-safe: a datagram is either received whole or not at all.
            received = upstream.recv(&mut buf) => {
                let n = received?;
                if is_dns && let Some(answer) = parse_dns_response(&buf[..n]) {
                    ctx.dns.insert(&answer);
                    let ips: Vec<_> = answer.ips.iter().map(|(ip, _)| *ip).collect();
                    ctx.observer.dns_answer(flow, &answer.qname, &ips);
                }
                client.write_all(&buf[..n]).await?;
                flow.counters.add_down(n);
            }
            Some(reply) = replies.recv() => {
                // Written here, not sent upstream: nothing crossed the network.
                client.write_all(&reply).await?;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::NoProtect;
    use crate::sni::tests::{client_hello, in_records, sni_ext};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// Blocks one server name, and, if asked, every name it cannot read; notes what the
    /// relay asked.
    struct Names {
        blocked: &'static str,
        block_unreadable: bool,
        seen: Mutex<Vec<String>>,
        unreadable: AtomicU64,
    }

    impl Names {
        fn new(blocked: &'static str, block_unreadable: bool) -> Arc<Names> {
            Arc::new(Names {
                blocked,
                block_unreadable,
                seen: Mutex::new(Vec::new()),
                unreadable: AtomicU64::new(0),
            })
        }
    }

    impl Observer for Names {
        fn hostname_seen(&self, _flow: &FlowInfo, hostname: &str) -> Verdict {
            self.seen.lock().unwrap().push(hostname.to_owned());
            if hostname == self.blocked {
                Verdict::Block
            } else {
                Verdict::Allow
            }
        }

        fn hostname_unreadable(&self, _flow: &FlowInfo) -> Verdict {
            self.unreadable.fetch_add(1, Ordering::Relaxed);
            if self.block_unreadable {
                Verdict::Block
            } else {
                Verdict::Allow
            }
        }
    }

    impl Reset for tokio::io::DuplexStream {
        fn reset(self) {}
    }

    /// An app sends `pieces` to a server on loopback through the relay, `pause` apart,
    /// with the relay waiting 100 ms for a ClientHello's rest. Returns what the server
    /// received.
    async fn relay(names: Arc<Names>, pieces: &[Vec<u8>], pause: Duration) -> Vec<u8> {
        let ctx = Arc::new(Ctx {
            protect: Arc::new(NoProtect),
            observer: names,
            dns: DnsCache::new(16),
            config: EngineConfig {
                sni_wait: Duration::from_millis(100),
                ..EngineConfig::default()
            },
            stats: Arc::new(EngineStats::default()),
            next_id: AtomicU64::new(1),
        });
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        let received = tokio::spawn(async move {
            let (mut socket, _) = server.accept().await.unwrap();
            let mut got = Vec::new();
            // Ends when the relay closes its side, cleanly or not.
            let _ = socket.read_to_end(&mut got).await;
            got
        });
        let (app, engine_side) = tokio::io::duplex(64 * 1024);
        let relayed = tokio::spawn(tcp(
            ctx,
            engine_side,
            "10.0.0.2:40000".parse().unwrap(),
            dst,
        ));
        let (mut app_rx, mut app_tx) = tokio::io::split(app);
        for (i, piece) in pieces.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(pause).await;
            }
            if app_tx.write_all(piece).await.is_err() {
                break;
            }
        }
        let _ = app_tx.shutdown().await;
        let _ = app_rx.read_to_end(&mut Vec::new()).await;
        relayed.await.unwrap();
        received.await.unwrap()
    }

    fn hello(name: &str) -> Vec<u8> {
        client_hello(&[(0x0033, vec![0xAB; 1300]), sni_ext(name)])
    }

    /// Audit finding A-03: a ClientHello split into small records still gives its name,
    /// and a blocked name reaches nothing.
    #[tokio::test]
    async fn a_name_in_a_split_client_hello_is_still_blocked() {
        let names = Names::new("blocked.example", false);
        let split = in_records(&hello("blocked.example"), &[1, 1, 1, 50]);
        let got = relay(Arc::clone(&names), &[split], Duration::ZERO).await;
        assert!(got.is_empty(), "the server got {} bytes", got.len());
        assert_eq!(*names.seen.lock().unwrap(), ["blocked.example"]);

        let names = Names::new("blocked.example", false);
        let allowed = in_records(&hello("allowed.example"), &[1, 1, 1, 50]);
        let got = relay(
            Arc::clone(&names),
            std::slice::from_ref(&allowed),
            Duration::ZERO,
        )
        .await;
        assert_eq!(got, allowed, "a name not blocked passes, every byte");
    }

    /// Audit finding A-03: a ClientHello sent too slowly to be read is not let through
    /// unread when the observer says so; otherwise every byte passes, as before.
    #[tokio::test]
    async fn a_client_hello_too_slow_to_read_is_put_to_the_observer() {
        let slow = hello("blocked.example");
        let pieces = [slow[..100].to_vec(), slow[100..].to_vec()];

        let names = Names::new("blocked.example", true);
        let got = relay(Arc::clone(&names), &pieces, Duration::from_millis(400)).await;
        assert!(got.is_empty(), "the server got {} bytes", got.len());
        assert_eq!(names.unreadable.load(Ordering::Relaxed), 1);
        assert!(names.seen.lock().unwrap().is_empty());

        let names = Names::new("blocked.example", false);
        let got = relay(Arc::clone(&names), &pieces, Duration::from_millis(400)).await;
        assert_eq!(got, slow);
        assert_eq!(names.unreadable.load(Ordering::Relaxed), 1);
    }

    /// Only a TLS handshake whose name cannot be read is put to the observer: not one
    /// without a name, not another protocol, not a client that sends nothing.
    #[tokio::test]
    async fn only_an_unreadable_handshake_is_put_to_the_observer() {
        let no_name = client_hello(&[(0x000a, vec![0, 2, 0, 29])]);
        let http = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n".to_vec();
        for first in [no_name, http, Vec::new()] {
            let names = Names::new("blocked.example", true);
            let got = relay(
                Arc::clone(&names),
                std::slice::from_ref(&first),
                Duration::ZERO,
            )
            .await;
            assert_eq!(got, first);
            assert_eq!(names.unreadable.load(Ordering::Relaxed), 0);
        }
    }
}

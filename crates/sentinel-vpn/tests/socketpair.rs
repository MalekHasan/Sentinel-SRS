// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end engine tests without root: a SEQPACKET socket pair stands in for the TUN
//! device (it keeps packet boundaries, like a TUN descriptor). The test writes raw IP
//! packets into one end; the engine relays them to real sockets on this host.
//!
//! Covers SRS CM-01 groundwork (UDP over IPv4 and IPv6), blocking (RA-01 groundwork),
//! and ending cleanly when the tunnel closes (NF-07, SP-03).

#![allow(clippy::unwrap_used)]

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use sentinel_vpn::{
    DnsForward, EngineConfig, EngineStats, FlowInfo, FlowTotals, NoProtect, Observer, TunDevice,
    Verdict, run,
};
use socket2::{Domain, Socket, Type};

const APP_V4: Ipv4Addr = Ipv4Addr::new(10, 111, 0, 1);
const APP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const APP_PORT: u16 = 40_000;

#[derive(Default)]
struct Recorder {
    block_port: Option<u16>,
    block_name: Option<&'static str>,
    /// Blocks every flow, new or open, while set.
    block_all: AtomicBool,
    /// How long deciding a new flow takes, as a slow observer would.
    slow_start: Duration,
    rechecks: AtomicUsize,
    started: Mutex<Vec<FlowInfo>>,
    ended: Mutex<Vec<(FlowInfo, FlowTotals)>>,
}

impl Observer for Recorder {
    fn flow_started(&self, flow: &FlowInfo) -> Verdict {
        std::thread::sleep(self.slow_start);
        self.started.lock().unwrap().push(flow.clone());
        if Some(flow.dst.port()) == self.block_port || self.block_all.load(Ordering::SeqCst) {
            Verdict::Block
        } else {
            Verdict::Allow
        }
    }

    fn recheck(&self, _flow: &FlowInfo) -> Verdict {
        self.rechecks.fetch_add(1, Ordering::SeqCst);
        if self.block_all.load(Ordering::SeqCst) {
            Verdict::Block
        } else {
            Verdict::Allow
        }
    }

    fn dns_query(&self, _flow: &FlowInfo, qname: &str, _qtype: u16) -> Verdict {
        if Some(qname) == self.block_name {
            Verdict::Block
        } else {
            Verdict::Allow
        }
    }

    fn flow_ended(&self, flow: &FlowInfo, totals: FlowTotals) {
        self.ended.lock().unwrap().push((flow.clone(), totals));
    }
}

/// A UDP echo server on loopback, answering every datagram once.
fn udp_echo(addr: IpAddr) -> SocketAddr {
    udp_echo_tagged(addr, b"")
}

/// A UDP echo server that puts `tag` in front of every reply, to tell servers apart.
fn udp_echo_tagged(addr: IpAddr, tag: &'static [u8]) -> SocketAddr {
    let socket = UdpSocket::bind((addr, 0)).unwrap();
    let local = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&[tag, &buf[..n]].concat(), from);
        }
    });
    local
}

fn udp_packet(src: IpAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    udp_packet_from(SocketAddr::new(src, APP_PORT), dst, payload)
}

fn udp_packet_from(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let builder = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), 64),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), 64),
        _ => panic!("mixed address families"),
    }
    .udp(src.port(), dst.port());
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).unwrap();
    packet
}

/// (source, destination, payload) of a UDP packet the engine wrote into the tunnel.
fn parse_udp(packet: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    let sliced = SlicedPacket::from_ip(packet).unwrap();
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net.unwrap() {
        NetSlice::Ipv4(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
        NetSlice::Ipv6(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
        _ => panic!("not IP"),
    };
    let Some(TransportSlice::Udp(udp)) = sliced.transport else {
        panic!("not UDP");
    };
    (
        SocketAddr::new(src_ip, udp.source_port()),
        SocketAddr::new(dst_ip, udp.destination_port()),
        udp.payload().to_vec(),
    )
}

struct Harness {
    peer: Socket,
    stats: Arc<EngineStats>,
    recorder: Arc<Recorder>,
    engine: tokio::task::JoinHandle<io::Result<()>>,
}

fn start(recorder: Recorder) -> Harness {
    start_with(recorder, EngineConfig::default())
}

fn start_with(recorder: Recorder, config: EngineConfig) -> Harness {
    let (tun_end, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let device = TunDevice::new(OwnedFd::from(tun_end)).unwrap();
    let stats = Arc::new(EngineStats::default());
    let recorder = Arc::new(recorder);
    let engine = tokio::spawn(run(
        device,
        Arc::new(NoProtect),
        Arc::clone(&recorder) as Arc<dyn Observer>,
        config,
        Arc::clone(&stats),
    ));
    Harness {
        peer,
        stats,
        recorder,
        engine,
    }
}

impl Harness {
    fn send(&self, packet: &[u8]) {
        self.peer.send(packet).unwrap();
    }

    /// Next packet from the engine, or `None` after the read timeout.
    async fn recv(&self) -> Option<Vec<u8>> {
        let peer = self.peer.try_clone().unwrap();
        tokio::task::spawn_blocking(move || {
            // On a SEQPACKET socket one read returns exactly one packet.
            let mut buf = vec![0u8; 65_536];
            let n = (&peer).read(&mut buf).ok()?;
            buf.truncate(n);
            Some(buf)
        })
        .await
        .unwrap()
    }
}

/// Send one UDP datagram through the engine and check the echoed reply.
async fn assert_udp_round_trip(h: &Harness, app: IpAddr, server: SocketAddr) {
    h.send(&udp_packet(app, server, b"ping"));
    let reply = h.recv().await.expect("no reply through the engine");
    let (src, dst, payload) = parse_udp(&reply);
    assert_eq!(src, server, "reply must come from the server's address");
    assert_eq!(dst, SocketAddr::new(app, APP_PORT));
    assert_eq!(payload, b"ping");
}

/// True if this machine has IPv6. Some containers boot with `ipv6.disable=1`; CI sets
/// `SENTINEL_REQUIRE_IPV6=1` so that IPv6 tests can never pass by being skipped there.
fn ipv6_available() -> bool {
    let ok = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    if !ok {
        assert!(
            std::env::var_os("SENTINEL_REQUIRE_IPV6").is_none(),
            "IPv6 is required here (SENTINEL_REQUIRE_IPV6) but unavailable"
        );
        eprintln!("SKIPPED: this machine has no IPv6");
    }
    ok
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_round_trip_over_ipv4() {
    let h = start(Recorder::default());
    assert_udp_round_trip(&h, APP_V4.into(), udp_echo(Ipv4Addr::LOCALHOST.into())).await;
    assert_eq!(h.stats.flows_total(), 1);
    assert_eq!(h.stats.upstream_failures(), 0);
    h.engine.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_round_trip_over_ipv6() {
    if !ipv6_available() {
        return;
    }
    let h = start(Recorder::default());
    assert_udp_round_trip(&h, APP_V6.into(), udp_echo(Ipv6Addr::LOCALHOST.into())).await;
    assert_eq!(h.stats.flows_total(), 1);
    assert_eq!(h.stats.upstream_failures(), 0);
    h.engine.abort();
}

/// A blocked UDP flow is not relayed. Audit A-12: it is remembered, so the app's next
/// datagrams to the same place are dropped without a flow each, decided and recorded
/// once rather than once each. After the idle time the next datagram is decided again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_flow_gets_no_reply() {
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    let h = start_with(
        Recorder {
            block_port: Some(server.port()),
            ..Recorder::default()
        },
        EngineConfig {
            udp_idle_timeout: Duration::from_secs(1),
            ..EngineConfig::default()
        },
    );
    // A datagram every 50 ms, as a call or a game sends them: each after the first
    // was decided.
    for _ in 0..10 {
        h.send(&udp_packet(APP_V4.into(), server, b"secret"));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        h.recv().await.is_none(),
        "a blocked flow must not be relayed"
    );
    h.ended(1).await;
    assert_eq!(h.recorder.started.lock().unwrap().len(), 1, "decided once");
    assert_eq!(h.stats.flows_total(), 1);
    assert_eq!(h.stats.flows_blocked(), 1);
    let ended = h.recorder.ended.lock().unwrap().clone();
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].1.verdict, Verdict::Block);
    assert_eq!(ended[0].1.bytes_up, 0);

    tokio::time::sleep(Duration::from_millis(500)).await;
    h.send(&udp_packet(APP_V4.into(), server, b"later"));
    h.ended(2).await;
    assert_eq!(h.recorder.started.lock().unwrap().len(), 2, "decided again");
    h.engine.abort();
}

/// Audit A-12: a blocked flow is decided again at the next datagram once the firewall
/// changes, so that allowing the app takes effect at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_flow_is_decided_again_when_the_firewall_changes() {
    let (changes, watched) = tokio::sync::watch::channel(0u64);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            firewall_changes: Some(watched),
            ..EngineConfig::default()
        },
    );
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    h.recorder.block_all.store(true, Ordering::SeqCst);
    h.send(&udp_packet(APP_V4.into(), server, b"blocked"));
    h.ended(1).await;
    h.recorder.block_all.store(false, Ordering::SeqCst);
    h.send(&udp_packet(APP_V4.into(), server, b"still blocked"));
    assert!(
        h.recv().await.is_none(),
        "blocked until the firewall changes"
    );
    assert_eq!(h.recorder.started.lock().unwrap().len(), 1);

    changes.send_modify(|version| *version += 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_udp_round_trip(&h, APP_V4.into(), server).await;
    assert_eq!(h.recorder.started.lock().unwrap().len(), 2);
    h.engine.abort();
}

/// Audit A-13: datagrams the flow cannot take yet, while it is still being decided, are
/// dropped. A second flow to the same place would reach the server from a new source
/// port, and be decided and recorded twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_flow_drops_datagrams_rather_than_opening_another() {
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    let h = start(Recorder {
        slow_start: Duration::from_millis(500),
        ..Recorder::default()
    });
    for i in 0..600u32 {
        h.send(&udp_packet(APP_V4.into(), server, &i.to_be_bytes()));
    }
    // The first flow is decided, and its queued datagrams echoed.
    assert!(h.recv().await.is_some(), "relayed once decided");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(h.recorder.started.lock().unwrap().len(), 1, "one flow");
    assert_eq!(h.stats.flows_total(), 1);
    h.engine.abort();
}

/// THREAT-MODEL-A D2: beyond `max_flows` open flows, a new one is refused before it
/// reaches the observer, and the open ones go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flows_beyond_the_cap_are_refused() {
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            max_flows: 2,
            ..EngineConfig::default()
        },
    );
    let from = |port| SocketAddr::new(APP_V4.into(), port);
    for port in [41_000, 41_001] {
        h.send(&udp_packet_from(from(port), server, b"open"));
        let (_, to, _) = parse_udp(&h.recv().await.expect("an open flow is relayed"));
        assert_eq!(to, from(port));
    }
    h.send(&udp_packet_from(from(41_002), server, b"one too many"));
    assert!(h.recv().await.is_none(), "a flow beyond the cap is refused");
    assert_eq!(h.stats.flows_refused(), 1);
    assert_eq!(h.stats.flows_total(), 2, "a refused flow is no flow");
    assert_eq!(h.stats.flows_active(), 2);
    // The flows already open still work.
    h.send(&udp_packet_from(from(41_000), server, b"still open"));
    let (_, _, payload) = parse_udp(&h.recv().await.expect("an open flow goes on"));
    assert_eq!(payload, b"still open");
    assert!(h.recorder.ended.lock().unwrap().is_empty());
    h.engine.abort();
}

/// SP-03: the engine reports every `heartbeat` while it runs, and once it stops, the time
/// since its last report grows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_engine_reports_while_it_runs() {
    let period = Duration::from_millis(100);
    let mut h = start_with(
        Recorder::default(),
        EngineConfig {
            heartbeat: period,
            ..EngineConfig::default()
        },
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let running = h.stats.since_heartbeat();
    assert!(running < period * 5, "no report for {running:?}");
    h.engine.abort();
    let _ = (&mut h.engine).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let stopped = h.stats.since_heartbeat();
    assert!(stopped >= Duration::from_millis(600), "{stopped:?}");
}

/// Audit A-52: a packet the stack cannot read is dropped, as a network drops it, and the
/// engine goes on. Before, the first one stopped the whole engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packet_the_stack_cannot_read_is_dropped() {
    let h = start(Recorder::default());
    // IPv4 claiming 100 bytes in 20, a header shorter than IPv4's, and no IP version.
    let mut short = vec![0u8; 20];
    short[0] = 0x45;
    short[3] = 100;
    for garbage in [short, vec![0x45; 8], vec![0x70; 40]] {
        h.send(&garbage);
    }
    assert_udp_round_trip(&h, APP_V4.into(), udp_echo(Ipv4Addr::LOCALHOST.into())).await;
    assert!(!h.engine.is_finished(), "the engine stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_ends_when_the_tunnel_closes() {
    let h = start(Recorder::default());
    drop(h.peer);
    let result = tokio::time::timeout(Duration::from_secs(5), h.engine)
        .await
        .expect("engine did not notice the closed tunnel")
        .unwrap();
    let err = result.expect_err("a closed tunnel must end the engine with an error");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

/// Dropping the engine (here: aborting its task) must stop every task it started and
/// release the tunnel, not leave flows running in the background.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborting_the_engine_releases_the_tunnel() {
    let h = start(Recorder::default());
    assert_udp_round_trip(&h, APP_V4.into(), udp_echo(Ipv4Addr::LOCALHOST.into())).await;
    h.engine.abort();
    // Once nothing holds the tunnel end, the peer reads end-of-file (0 bytes).
    for _ in 0..10 {
        if h.recv().await.is_some_and(|packet| packet.is_empty()) {
            return;
        }
    }
    panic!("the tunnel is still open after the engine was dropped");
}

/// DNS sent to the tunnel's resolver address reaches the network's current resolver,
/// and follows it when it changes (a switch from Wi-Fi to mobile data).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_to_the_tunnel_resolver_follows_the_network() {
    let tunnel_dns = SocketAddr::new(Ipv4Addr::new(10, 111, 0, 53).into(), 53);
    let forward = Arc::new(DnsForward::new(vec![tunnel_dns.ip()]));
    forward.set_upstream(vec![udp_echo_tagged(Ipv4Addr::LOCALHOST.into(), b"A")]);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            dns_forward: Some(Arc::clone(&forward)),
            ..EngineConfig::default()
        },
    );

    // Resolvers use a new source port per query, so each query is a new flow. Only
    // queries are sent on from the tunnel's resolver (audit A-39).
    let app = SocketAddr::new(APP_V4.into(), 40_001);
    let q1 = dns_query(1, "one.example");
    h.send(&udp_packet_from(app, tunnel_dns, &q1));
    let (src, dst, payload) = parse_udp(&h.recv().await.expect("no answer"));
    assert_eq!(
        src, tunnel_dns,
        "the answer must come from the address the app asked"
    );
    assert_eq!(dst, app);
    assert_eq!(payload, [b"A".as_slice(), &q1].concat());

    forward.set_upstream(vec![udp_echo_tagged(Ipv4Addr::LOCALHOST.into(), b"B")]);
    let app = SocketAddr::new(APP_V4.into(), 40_002);
    let q2 = dns_query(2, "two.example");
    h.send(&udp_packet_from(app, tunnel_dns, &q2));
    let (src, _, payload) = parse_udp(&h.recv().await.expect("no answer after the change"));
    assert_eq!(src, tunnel_dns);
    assert_eq!(payload, [b"B".as_slice(), &q2].concat());
    assert_eq!(h.stats.upstream_failures(), 0);

    // Only DNS is served at the resolver address.
    let dot = SocketAddr::new(tunnel_dns.ip(), 853);
    h.send(&udp_packet_from(
        SocketAddr::new(APP_V4.into(), 40_003),
        dot,
        b"q3",
    ));
    assert!(h.recv().await.is_none(), "port 853 must not be relayed");
    assert_eq!(h.stats.upstream_failures(), 1);
    h.engine.abort();
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = simple_dns::Packet::new_query(id);
    packet.questions.push(simple_dns::Question::new(
        simple_dns::Name::new_unchecked(name),
        simple_dns::TYPE::A.into(),
        simple_dns::CLASS::IN.into(),
        false,
    ));
    packet.build_bytes_vec().unwrap()
}

/// A lookup the observer blocks is answered "no such name" by the engine at once and
/// never reaches the resolver; other lookups are forwarded as before (ADR-0015).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_lookup_is_answered_no_such_name() {
    let tunnel_dns = SocketAddr::new(Ipv4Addr::new(10, 111, 0, 53).into(), 53);
    let forward = Arc::new(DnsForward::new(vec![tunnel_dns.ip()]));
    // The resolver echoes what it gets after "R", so a forwarded query shows.
    forward.set_upstream(vec![udp_echo_tagged(Ipv4Addr::LOCALHOST.into(), b"R")]);
    let h = start_with(
        Recorder {
            block_name: Some("ads.example"),
            ..Recorder::default()
        },
        EngineConfig {
            dns_forward: Some(Arc::clone(&forward)),
            ..EngineConfig::default()
        },
    );

    let app = SocketAddr::new(APP_V4.into(), 40_010);
    h.send(&udp_packet_from(
        app,
        tunnel_dns,
        &dns_query(7, "ads.example"),
    ));
    let (src, dst, payload) = parse_udp(&h.recv().await.expect("no answer"));
    assert_eq!((src, dst), (tunnel_dns, app));
    let answer = simple_dns::Packet::parse(&payload).expect("a DNS answer, not the echo");
    assert_eq!(answer.id(), 7);
    assert_eq!(answer.rcode(), simple_dns::RCODE::NameError);
    assert!(
        h.recv().await.is_none(),
        "nothing came back from the resolver"
    );

    let other = SocketAddr::new(APP_V4.into(), 40_011);
    let allowed = dns_query(8, "chat.example");
    h.send(&udp_packet_from(other, tunnel_dns, &allowed));
    let (_, _, payload) = parse_udp(&h.recv().await.expect("no answer"));
    assert_eq!(payload, [b"R".as_slice(), &allowed].concat(), "forwarded");
    h.engine.abort();
}

/// RA-01, RA-03: when the firewall changes, every open flow is asked again, and one it
/// now blocks ends at once: nothing more reaches the server, and it is reported as
/// blocked. Without a change, open flows are not asked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_flow_ends_when_the_firewall_now_blocks_it() {
    let (changes, watched) = tokio::sync::watch::channel(0u64);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            firewall_changes: Some(watched),
            ..EngineConfig::default()
        },
    );
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    assert_udp_round_trip(&h, APP_V4.into(), server).await;
    assert_udp_round_trip(&h, APP_V4.into(), server).await;
    assert_eq!(
        h.recorder.rechecks.load(Ordering::SeqCst),
        0,
        "nothing changed"
    );

    // A change that still allows the flow leaves it open.
    changes.send_modify(|version| *version += 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.recorder.rechecks.load(Ordering::SeqCst), 1);
    assert_udp_round_trip(&h, APP_V4.into(), server).await;
    assert!(h.recorder.ended.lock().unwrap().is_empty());

    h.recorder.block_all.store(true, Ordering::SeqCst);
    changes.send_modify(|version| *version += 1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while h.recorder.ended.lock().unwrap().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the flow did not end within a second"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (flow, totals) = h.recorder.ended.lock().unwrap()[0].clone();
    assert_eq!(flow.dst, server);
    assert_eq!(totals.verdict, Verdict::Block);
    assert_eq!(h.stats.flows_blocked(), 1);
    // The next datagram starts a new flow, which is blocked when it starts.
    h.send(&udp_packet(APP_V4.into(), server, b"after"));
    assert!(h.recv().await.is_none(), "nothing came back once blocked");
    h.engine.abort();
}

/// The app's end of one TCP connection over IPv4, by hand: a handshake, a FIN, and no
/// more than the tests below need. Its own sequence numbers start at [`TcpApp::ISN`].
struct TcpApp {
    from: SocketAddr,
    to: SocketAddr,
}

impl TcpApp {
    const ISN: u32 = 1_000;

    fn new(port: u16, to: SocketAddr) -> TcpApp {
        TcpApp {
            from: SocketAddr::new(APP_V4.into(), port),
            to,
        }
    }

    fn segment(&self, seq: u32, ack: Option<u32>, syn: bool, fin: bool) -> Vec<u8> {
        let (IpAddr::V4(from), IpAddr::V4(to)) = (self.from.ip(), self.to.ip()) else {
            panic!("IPv4 only");
        };
        let mut builder = PacketBuilder::ipv4(from.octets(), to.octets(), 64).tcp(
            self.from.port(),
            self.to.port(),
            seq,
            64_240,
        );
        if syn {
            builder = builder.syn();
        }
        if fin {
            builder = builder.fin();
        }
        if let Some(ack) = ack {
            builder = builder.ack(ack);
        }
        let mut packet = Vec::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();
        packet
    }

    fn syn(&self) -> Vec<u8> {
        self.segment(Self::ISN, None, true, false)
    }

    /// Acknowledges the engine's SYN.
    fn ack(&self, syn_ack: &Seg) -> Vec<u8> {
        self.segment(
            Self::ISN + 1,
            Some(syn_ack.seq.wrapping_add(1)),
            false,
            false,
        )
    }

    /// Closes the app's side without data, acknowledging the engine's SYN only: never
    /// its FIN.
    fn fin(&self, syn_ack: &Seg) -> Vec<u8> {
        self.segment(
            Self::ISN + 1,
            Some(syn_ack.seq.wrapping_add(1)),
            false,
            true,
        )
    }
}

/// A TCP segment the engine wrote into the tunnel.
#[derive(Debug)]
struct Seg {
    to: SocketAddr,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    seq: u32,
}

fn parse_tcp(packet: &[u8]) -> Option<Seg> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let Some(NetSlice::Ipv4(ip)) = sliced.net else {
        return None;
    };
    let Some(TransportSlice::Tcp(tcp)) = sliced.transport else {
        return None;
    };
    Some(Seg {
        to: SocketAddr::new(
            ip.header().destination_addr().into(),
            tcp.destination_port(),
        ),
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        seq: tcp.sequence_number(),
    })
}

/// Closes the connection once the other side has closed its own: after the app's FIN
/// came through the engine, so the engine's FIN to the app follows the handshake.
fn close_after_the_app(mut stream: std::net::TcpStream) {
    let _ = stream.read_to_end(&mut Vec::new());
}

/// A TCP server on loopback that hands each connection it accepts to `then`, on a
/// thread of its own.
fn tcp_server(then: fn(std::net::TcpStream)) -> SocketAddr {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || then(stream));
        }
    });
    local
}

impl Harness {
    /// The TCP segments the engine sends to `to` within `within`, until one is `last`.
    async fn tcp_until(
        &self,
        to: SocketAddr,
        within: Duration,
        last: fn(&Seg) -> bool,
    ) -> Vec<Seg> {
        let deadline = std::time::Instant::now() + within;
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            let Some(segment) = self.recv().await.as_deref().and_then(parse_tcp) else {
                continue;
            };
            if segment.to != to {
                continue;
            }
            let done = last(&segment);
            seen.push(segment);
            if done {
                break;
            }
        }
        seen
    }

    /// Opens `app`'s connection: its SYN, the engine's SYN-ACK, its ACK. Returns the
    /// SYN-ACK.
    async fn handshake(&self, app: &TcpApp) -> Seg {
        self.send(&app.syn());
        let syn_ack = self
            .tcp_until(app.from, Duration::from_secs(2), |s| s.syn && s.ack)
            .await
            .into_iter()
            .find(|s| s.syn && s.ack)
            .expect("no SYN-ACK");
        self.send(&app.ack(&syn_ack));
        syn_ack
    }

    /// Waits up to two seconds for `n` flows to have ended.
    async fn ended(&self, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while self.recorder.ended.lock().unwrap().len() < n {
            assert!(
                std::time::Instant::now() < deadline,
                "{n} flows did not end"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Audit A-04: a blocked connection is reset. A close instead would leave the stack's
/// socket to an app that need never answer it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_connection_is_reset() {
    let server = tcp_server(drop);
    let h = start(Recorder {
        block_port: Some(server.port()),
        ..Recorder::default()
    });
    let app = TcpApp::new(41_100, server);
    h.send(&app.syn());
    let seen = h
        .tcp_until(app.from, Duration::from_secs(3), |s| s.rst)
        .await;
    assert!(seen.last().is_some_and(|s| s.rst), "reset: {seen:?}");
    assert!(!seen.iter().any(|s| s.fin), "never closed: {seen:?}");
    assert_eq!(h.stats.flows_blocked(), 1);
    h.engine.abort();
}

/// Audit A-04: once a flow ended, the app's side has `tcp_linger` to close. An app that
/// never acknowledges the engine's FIN is then reset, which frees the stack's socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_the_app_never_acknowledges_ends_in_a_reset() {
    let server = tcp_server(close_after_the_app);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            tcp_linger: Duration::from_secs(1),
            ..EngineConfig::default()
        },
    );
    let app = TcpApp::new(41_101, server);
    let syn_ack = h.handshake(&app).await;
    h.send(&app.fin(&syn_ack));
    let closed = std::time::Instant::now();
    let seen = h
        .tcp_until(app.from, Duration::from_secs(5), |s| s.rst)
        .await;
    assert!(
        seen.iter().any(|s| s.fin),
        "the engine closed its side: {seen:?}"
    );
    assert!(seen.last().is_some_and(|s| s.rst), "then reset: {seen:?}");
    assert!(
        closed.elapsed() >= Duration::from_millis(900),
        "not before the linger time"
    );
    h.ended(1).await;
    h.engine.abort();
}

/// Audit A-04: the stack's sockets count towards `max_flows`, those still closing after
/// their flow ended included. Beyond them a connection is reset and counted as refused;
/// once a socket is freed, a new one opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sockets_still_closing_count_towards_the_cap() {
    let server = tcp_server(close_after_the_app);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            max_flows: 1,
            tcp_linger: Duration::from_secs(1),
            ..EngineConfig::default()
        },
    );
    let first = TcpApp::new(41_102, server);
    let syn_ack = h.handshake(&first).await;
    h.send(&first.fin(&syn_ack));
    h.ended(1).await;
    assert_eq!(
        h.stats.flows_active(),
        0,
        "the flow ended; its socket still closes"
    );

    let second = TcpApp::new(41_103, server);
    h.send(&second.syn());
    let seen = h
        .tcp_until(second.from, Duration::from_secs(2), |s| s.rst)
        .await;
    assert!(seen.last().is_some_and(|s| s.rst), "reset: {seen:?}");
    assert!(!seen.iter().any(|s| s.syn), "never opened: {seen:?}");
    assert_eq!(h.stats.flows_refused(), 1);
    assert_eq!(h.stats.flows_total(), 1, "a refused connection is no flow");

    let freed = h
        .tcp_until(first.from, Duration::from_secs(5), |s| s.rst)
        .await;
    assert!(
        freed.last().is_some_and(|s| s.rst),
        "the first is reset: {freed:?}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    h.handshake(&TcpApp::new(41_104, server)).await;
    // The stack answers the handshake; the relay counts the flow when it starts.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while h.stats.flows_total() < 2 {
        assert!(std::time::Instant::now() < deadline, "no second flow");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.engine.abort();
}

/// Audit A-04: a SYN sent again, as an app does when the SYN-ACK is slow, reaches the
/// connection's socket. Before, it made a second socket that never opened, and a second
/// flow that waited on it for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_syn_sent_again_opens_one_flow() {
    let server = tcp_server(drop);
    let h = start(Recorder::default());
    let app = TcpApp::new(41_105, server);
    h.send(&app.syn());
    h.send(&app.syn());
    let seen = h
        .tcp_until(app.from, Duration::from_secs(2), |s| s.syn && s.ack)
        .await;
    assert!(seen.iter().any(|s| s.syn && s.ack), "opened: {seen:?}");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while h.stats.flows_total() < 1 {
        assert!(std::time::Instant::now() < deadline, "no flow");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // A second flow would have started by now.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.stats.flows_total(), 1);
    h.engine.abort();
}

/// Audit A-18: a connection with no byte either way for `tcp_idle_timeout` is reset.
/// On smoltcp nothing else ends a connection that both sides keep open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_is_reset() {
    let server = tcp_server(|stream| {
        std::thread::sleep(Duration::from_secs(10));
        drop(stream);
    });
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            tcp_idle_timeout: Duration::from_millis(400),
            ..EngineConfig::default()
        },
    );
    let app = TcpApp::new(41_106, server);
    h.handshake(&app).await;
    let opened = std::time::Instant::now();
    let seen = h
        .tcp_until(app.from, Duration::from_secs(3), |s| s.rst)
        .await;
    assert!(seen.last().is_some_and(|s| s.rst), "reset: {seen:?}");
    assert!(
        opened.elapsed() >= Duration::from_millis(350),
        "not before the idle time"
    );
    h.ended(1).await;
    assert_eq!(
        h.recorder.ended.lock().unwrap()[0].1.verdict,
        Verdict::Allow
    );
    h.engine.abort();
}

/// A DNS server on loopback that answers every A query with `address`.
fn dns_server(address: Ipv4Addr) -> SocketAddr {
    use simple_dns::rdata::{A, RData};
    use simple_dns::{CLASS, Packet, ResourceRecord};

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let Ok(query) = Packet::parse(&buf[..n]) else {
                continue;
            };
            let mut reply = Packet::new_reply(query.id());
            reply.questions = query.questions.clone();
            for question in &query.questions {
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    300,
                    RData::A(A::from(address)),
                ));
            }
            let _ = socket.send_to(&reply.build_bytes_vec().unwrap(), from);
        }
    });
    local
}

/// The name a flow to `to` started with, once it started.
async fn started_name(h: &Harness, to: SocketAddr) -> Option<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(flow) = h
            .recorder
            .started
            .lock()
            .unwrap()
            .iter()
            .find(|f| f.dst == to)
        {
            return flow.hostname.clone();
        }
        assert!(std::time::Instant::now() < deadline, "no flow to {to}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Audit A-05: the tunnel resolver's answers name later connections. That answers from
/// a server the app chose do not is checked in the relay's own tests, which need no
/// server on port 53.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tunnel_resolvers_answers_name_flows() {
    let tunnel_dns = SocketAddr::new(Ipv4Addr::new(10, 111, 0, 53).into(), 53);
    let forward = Arc::new(DnsForward::new(vec![tunnel_dns.ip()]));
    let address = Ipv4Addr::new(127, 0, 0, 3);
    forward.set_upstream(vec![dns_server(address)]);
    let h = start_with(
        Recorder::default(),
        EngineConfig {
            dns_forward: Some(Arc::clone(&forward)),
            ..EngineConfig::default()
        },
    );
    h.send(&udp_packet_from(
        SocketAddr::new(APP_V4.into(), 42_000),
        tunnel_dns,
        &dns_query(0x0a05, "real.example"),
    ));
    assert!(h.recv().await.is_some(), "the tunnel's resolver answers");
    let server = udp_echo(address.into());
    h.send(&udp_packet_from(
        SocketAddr::new(APP_V4.into(), 42_001),
        server,
        b"x",
    ));
    assert!(h.recv().await.is_some());
    assert_eq!(
        started_name(&h, server).await.as_deref(),
        Some("real.example")
    );
    h.engine.abort();
}

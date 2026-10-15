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
    ended: Mutex<Vec<(FlowInfo, FlowTotals)>>,
}

impl Observer for Recorder {
    fn flow_started(&self, flow: &FlowInfo) -> Verdict {
        if Some(flow.dst.port()) == self.block_port {
            Verdict::Block
        } else {
            Verdict::Allow
        }
    }

    fn dns_query(&self, _flow: &FlowInfo, qname: &str) -> Verdict {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_flow_gets_no_reply() {
    let server = udp_echo(Ipv4Addr::LOCALHOST.into());
    let h = start(Recorder {
        block_port: Some(server.port()),
        ..Recorder::default()
    });
    h.send(&udp_packet(APP_V4.into(), server, b"secret"));
    assert!(
        h.recv().await.is_none(),
        "a blocked flow must not be relayed"
    );
    assert_eq!(h.stats.flows_blocked(), 1);
    let ended = h.recorder.ended.lock().unwrap();
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].1.verdict, Verdict::Block);
    assert_eq!(ended[0].1.bytes_up, 0);
    drop(ended);
    h.engine.abort();
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

    // Resolvers use a new source port per query, so each query is a new flow.
    let app = SocketAddr::new(APP_V4.into(), 40_001);
    h.send(&udp_packet_from(app, tunnel_dns, b"q1"));
    let (src, dst, payload) = parse_udp(&h.recv().await.expect("no answer"));
    assert_eq!(
        src, tunnel_dns,
        "the answer must come from the address the app asked"
    );
    assert_eq!(dst, app);
    assert_eq!(payload, b"Aq1");

    forward.set_upstream(vec![udp_echo_tagged(Ipv4Addr::LOCALHOST.into(), b"B")]);
    let app = SocketAddr::new(APP_V4.into(), 40_002);
    h.send(&udp_packet_from(app, tunnel_dns, b"q2"));
    let (src, _, payload) = parse_udp(&h.recv().await.expect("no answer after the change"));
    assert_eq!(src, tunnel_dns);
    assert_eq!(payload, b"Bq2");
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

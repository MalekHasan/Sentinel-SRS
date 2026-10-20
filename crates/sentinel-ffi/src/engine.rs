// SPDX-License-Identifier: GPL-3.0-or-later
//! Starting and stopping the packet engine from the Android `VpnService`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sentinel_vpn::{DnsForward, EngineConfig, EngineStats, Protect, TunDevice};
use tokio::sync::oneshot;

use crate::enrich::{IpDatabase, TrackerDatabase};
use crate::feed::Feed;
use crate::flows::{FlowEvents, FlowObserver, LiveApp};
use crate::history::HistoryStore;

/// Implemented by the `VpnService`: calls `VpnService.protect(fd)` so the engine's own
/// sockets bypass the tunnel. Returns false if Android refused.
#[uniffi::export(with_foreign)]
pub trait SocketProtector: Send + Sync {
    fn protect(&self, fd: i32) -> bool;
}

/// Engine lifecycle events for the app.
#[uniffi::export(with_foreign)]
pub trait EngineListener: Send + Sync {
    /// The engine has stopped. `error` is `None` after [`Engine::stop`], and says why
    /// otherwise (for example, the user revoked the VPN). The app records a monitoring
    /// gap for any stop it did not ask for (SRS SP-03).
    fn engine_stopped(&self, error: Option<String>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct EngineSnapshot {
    pub running: bool,
    pub flows_total: u64,
    pub flows_active: u64,
    pub flows_blocked: u64,
    /// Flows refused because as many as the engine allows were already open
    /// (THREAT-MODEL-A D2).
    #[uniffi(default = 0)]
    pub flows_refused: u64,
    pub upstream_failures: u64,
    /// Flow batches that could not be written to the history.
    pub history_failures: u64,
    /// What [`Engine::set_away`] last said.
    pub away: bool,
    /// Milliseconds since the engine last reported that it runs (SP-03, ADR-0029). It
    /// reports every 10 s; longer means it stopped or hangs. Time asleep does not count.
    #[uniffi(default = 0)]
    pub heartbeat_age_ms: u64,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EngineError {
    #[error("the tunnel descriptor {fd} is not valid")]
    InvalidDescriptor { fd: i32 },
    #[error("{address} is not an IP address")]
    InvalidAddress { address: String },
    #[error("the engine could not start: {reason}")]
    StartFailed { reason: String },
}

/// The running packet engine. Lives on its own thread with its own async runtime.
#[derive(uniffi::Object)]
pub struct Engine {
    stats: Arc<EngineStats>,
    events: Arc<FlowEvents>,
    dns: Arc<DnsForward>,
    away: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// Worker threads for the engine's runtime. Two keep a slow flow from stalling others
/// without waking more cores than needed (battery, NF-03).
const WORKER_THREADS: usize = 2;
/// How long [`Engine::stop`] waits for in-flight relays before dropping them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[uniffi::export]
impl Engine {
    /// Start the engine on a tunnel descriptor.
    ///
    /// Takes ownership of `tun_fd`: pass the result of
    /// `ParcelFileDescriptor.detachFd()`, and do not close it in Kotlin. `tunnel_dns`
    /// lists the resolver addresses given to `VpnService.Builder.addDnsServer`; DNS sent
    /// there goes to the resolvers set with [`Engine::set_upstream_dns`]. `flows`
    /// receives every flow, with its owner (CM-01), and `history`, if given, stores it.
    #[uniffi::constructor]
    pub fn start(
        tun_fd: i32,
        tunnel_dns: Vec<String>,
        protector: Arc<dyn SocketProtector>,
        listener: Arc<dyn EngineListener>,
        flows: Arc<dyn FlowObserver>,
        history: Option<Arc<HistoryStore>>,
    ) -> Result<Arc<Self>, EngineError> {
        if tun_fd < 0 {
            return Err(EngineError::InvalidDescriptor { fd: tun_fd });
        }
        // SAFETY: the caller hands over an open descriptor it no longer owns
        // (`detachFd()`); from here on only this `OwnedFd` closes it, including on
        // every error below.
        #[allow(unsafe_code)]
        let fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
        let tunnel_dns = tunnel_dns
            .into_iter()
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .map_err(|_| EngineError::InvalidAddress { address })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .thread_name("sentinel-engine")
            .enable_all()
            .build()
            .map_err(start_failed)?;
        // The device must be registered inside the runtime that will poll it.
        let device = runtime
            .block_on(async { TunDevice::new(fd) })
            .map_err(start_failed)?;

        let stats = Arc::new(EngineStats::default());
        let dns = Arc::new(DnsForward::new(tunnel_dns.clone()));
        let away = Arc::new(AtomicBool::new(false));
        let config = EngineConfig {
            dns_forward: Some(Arc::clone(&dns)),
            away: Arc::clone(&away),
            // A rule or mode change decides open connections again (RA-01).
            firewall_changes: history.as_ref().map(|history| history.firewall_changes()),
            ..EngineConfig::default()
        };
        let running = Arc::new(AtomicBool::new(true));
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        // The start time names this run in the history; flow ids restart at 1 each run.
        let events =
            Arc::new(FlowEvents::new(flows, history, now_ms()).with_tunnel_dns(tunnel_dns));

        let thread = {
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
            let events = Arc::clone(&events);
            std::thread::Builder::new()
                .name("sentinel-engine-main".into())
                .spawn(move || {
                    let observer = Arc::clone(&events);
                    let outcome = runtime.block_on(async {
                        tokio::select! {
                            result = sentinel_vpn::run(
                                device,
                                Arc::new(ForeignProtect(protector)),
                                observer,
                                config,
                                stats,
                            ) => match result {
                                Ok(()) => Some("the engine stopped unexpectedly".to_owned()),
                                Err(e) => Some(e.to_string()),
                            },
                            () = events.deliver() => None,
                            _ = stop_rx => None,
                        }
                    });
                    // The relays are gone: report the flows they left open as ended now,
                    // so the app never keeps a flow open forever.
                    events.close_all(now_ms());
                    runtime.shutdown_timeout(SHUTDOWN_GRACE);
                    running.store(false, Ordering::SeqCst);
                    listener.engine_stopped(outcome);
                })
                .map_err(start_failed)?
        };

        Ok(Arc::new(Engine {
            stats,
            events,
            dns,
            away,
            running,
            stop: Mutex::new(Some(stop_tx)),
            thread: Mutex::new(Some(thread)),
        }))
    }

    /// Stop the engine and wait for it to finish. Safe to call more than once, and
    /// from inside [`EngineListener::engine_stopped`] (it then does not wait for itself).
    pub fn stop(&self) {
        if let Some(tx) = self.stop.lock().ok().and_then(|mut s| s.take()) {
            let _ = tx.send(());
        }
        let Some(thread) = self.thread.lock().ok().and_then(|mut t| t.take()) else {
            return;
        };
        if thread.thread().id() != std::thread::current().id() {
            let _ = thread.join();
        }
    }

    /// Set the current network's resolvers, in order of preference. Call it at start
    /// and whenever the network or its resolvers change. Entries that are not plain IP
    /// addresses (for example scoped link-local ones like `fe80::1%wlan0`) are skipped.
    pub fn set_upstream_dns(&self, servers: Vec<String>) {
        let servers = servers
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        self.dns.set_upstream(servers);
    }

    /// Use `database` for the network, owner and country of each new flow (DT-01), or
    /// none. It can be replaced while the engine runs, for example when the feed brings a
    /// newer one.
    pub fn set_ip_database(&self, database: Option<Arc<IpDatabase>>) {
        self.events.set_ip_database(database);
    }

    /// Use `database` for the company and category of each new flow's hostname (DT-06),
    /// or none. Like the IP database, it can be replaced while the engine runs.
    pub fn set_tracker_database(&self, database: Option<Arc<TrackerDatabase>>) {
        self.events.set_tracker_database(database);
    }

    /// Match every DNS lookup, TLS server name and connection from now on against the
    /// indicators `feed` has in force, or against none (ID-13). A match raises a Critical
    /// alert in the history within a batch. The feed's newer bundles are used as soon as
    /// they are installed, and a bundle removed at its re-check stops matching at once.
    pub fn set_feed(&self, feed: Option<Arc<Feed>>) {
        self.events.set_feed(feed);
    }

    /// Whether the user is away (on Android: the screen is off or locked). While it is
    /// set, every byte relayed is also counted as "while away" (CM-06). Starts unset.
    pub fn set_away(&self, away: bool) {
        self.away.store(away, Ordering::Relaxed);
    }

    /// Open connections grouped by app, busiest first (SRS CM-03). Cheap enough to call
    /// every second while the live view is on screen.
    pub fn live_apps(&self) -> Vec<LiveApp> {
        self.events.live_apps()
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            running: self.running.load(Ordering::SeqCst),
            flows_total: self.stats.flows_total(),
            flows_active: self.stats.flows_active(),
            flows_blocked: self.stats.flows_blocked(),
            flows_refused: self.stats.flows_refused(),
            upstream_failures: self.stats.upstream_failures(),
            history_failures: self.events.history_failures(),
            away: self.away.load(Ordering::Relaxed),
            heartbeat_age_ms: u64::try_from(self.stats.since_heartbeat().as_millis())
                .unwrap_or(u64::MAX),
        }
    }
}

impl Drop for Engine {
    /// An engine whose Kotlin object is closed or collected must not keep running.
    fn drop(&mut self) {
        self.stop();
    }
}

fn start_failed(e: io::Error) -> EngineError {
    EngineError::StartFailed {
        reason: e.to_string(),
    }
}

/// Bridges the Kotlin protector to the engine's `Protect` trait.
struct ForeignProtect(Arc<dyn SocketProtector>);

impl Protect for ForeignProtect {
    fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        if self.0.protect(socket.as_raw_fd()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect refused the socket",
            ))
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::os::fd::IntoRawFd;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    use socket2::{Domain, Socket, Type};

    use crate::flows::{FlowOwner, FlowProto, FlowRecord};
    use crate::history::HistoryAway;

    struct CountingProtector(AtomicUsize);
    impl SocketProtector for CountingProtector {
        fn protect(&self, _fd: i32) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    struct ChannelListener(Mutex<mpsc::Sender<Option<String>>>);
    impl EngineListener for ChannelListener {
        fn engine_stopped(&self, error: Option<String>) {
            let _ = self.0.lock().unwrap().send(error);
        }
    }

    /// One `owner_uid` question: protocol, local address and port, remote address and port.
    type OwnerQuestion = (FlowProto, String, u16, String, u16);

    /// Says every flow belongs to UID 10123 (`org.example.owner`), installed at
    /// `installed_ms`, and passes on each batch it receives.
    struct RecordingFlows {
        asked: Mutex<Vec<OwnerQuestion>>,
        batches: Mutex<mpsc::Sender<Vec<FlowRecord>>>,
        installed_ms: Option<i64>,
    }
    const OWNER: i32 = 10_123;
    const OWNER_APP: &str = "org.example.owner";
    impl FlowObserver for RecordingFlows {
        fn owner(
            &self,
            proto: FlowProto,
            local_ip: String,
            local_port: u16,
            remote_ip: String,
            remote_port: u16,
        ) -> FlowOwner {
            self.asked
                .lock()
                .unwrap()
                .push((proto, local_ip, local_port, remote_ip, remote_port));
            FlowOwner {
                uid: OWNER,
                app: Some(OWNER_APP.to_owned()),
                installed_ms: self.installed_ms,
                system: false,
            }
        }
        fn flows(&self, records: Vec<FlowRecord>) {
            let _ = self.batches.lock().unwrap().send(records);
        }
    }

    fn recording_flows() -> (Arc<RecordingFlows>, mpsc::Receiver<Vec<FlowRecord>>) {
        recording_flows_installed(None)
    }

    fn recording_flows_installed(
        installed_ms: Option<i64>,
    ) -> (Arc<RecordingFlows>, mpsc::Receiver<Vec<FlowRecord>>) {
        let (tx, rx) = mpsc::channel();
        let flows = RecordingFlows {
            asked: Mutex::new(Vec::new()),
            batches: Mutex::new(tx),
            installed_ms,
        };
        (Arc::new(flows), rx)
    }

    /// Keeps every alert it hears of.
    #[derive(Default)]
    struct HeardAlerts(Mutex<Vec<crate::alerts::HistoryAlert>>);
    impl crate::alerts::AlertListener for HeardAlerts {
        fn raised(&self, alert: crate::alerts::HistoryAlert) {
            self.0.lock().unwrap().push(alert);
        }
    }

    fn udp_packet(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        udp_packet_from(40_000, dst, dst_port)
    }

    fn udp_packet_from(src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let builder =
            etherparse::PacketBuilder::ipv4([10, 111, 0, 1], dst, 64).udp(src_port, dst_port);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"hi").unwrap();
        packet
    }

    struct Started {
        engine: Arc<Engine>,
        peer: Socket,
        protector: Arc<CountingProtector>,
        stopped: mpsc::Receiver<Option<String>>,
        flows: Arc<RecordingFlows>,
        batches: mpsc::Receiver<Vec<FlowRecord>>,
    }

    fn start_on_socketpair() -> Started {
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let protector = Arc::new(CountingProtector(AtomicUsize::new(0)));
        let (tx, stopped) = mpsc::channel();
        let (flows, batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            vec!["10.111.0.53".into()],
            Arc::clone(&protector) as Arc<dyn SocketProtector>,
            Arc::new(ChannelListener(Mutex::new(tx))),
            Arc::clone(&flows) as Arc<dyn FlowObserver>,
            None,
        )
        .unwrap();
        Started {
            engine,
            peer,
            protector,
            stopped,
            flows,
            batches,
        }
    }

    #[test]
    fn relays_through_a_protected_socket_and_stops_cleanly() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        let Started {
            engine,
            peer,
            protector,
            stopped,
            ..
        } = start_on_socketpair();
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        let mut reply = vec![0u8; 2048];
        let n = (&peer)
            .read(&mut reply)
            .expect("no reply through the engine");
        assert!(n > 28, "reply is a full IP packet");
        assert_eq!(&reply[n - 2..n], b"hi");

        let snap = engine.snapshot();
        assert!(snap.running);
        assert_eq!(snap.flows_total, 1);
        assert!(snap.heartbeat_age_ms < 10_000, "the engine reports (SP-03)");
        assert_eq!(
            protector.0.load(Ordering::SeqCst),
            1,
            "upstream socket protected"
        );

        engine.stop();
        engine.stop(); // idempotent
        assert_eq!(stopped.recv_timeout(Duration::from_secs(5)).unwrap(), None);
        assert!(!engine.snapshot().running);
    }

    #[test]
    fn reports_an_unexpected_stop_when_the_tunnel_closes() {
        let Started {
            engine,
            peer,
            stopped,
            ..
        } = start_on_socketpair();
        drop(peer);
        let reason = stopped
            .recv_timeout(Duration::from_secs(5))
            .expect("listener not called")
            .expect("an unexpected stop carries a reason");
        assert!(reason.contains("tunnel"), "reason: {reason}");
        engine.stop();
        assert!(!engine.snapshot().running);
    }

    /// Kotlin may call `stop()` from inside `engine_stopped`; that must not deadlock.
    #[test]
    fn stop_from_inside_the_listener_returns() {
        struct StopsEngine(Mutex<Option<Arc<Engine>>>, Mutex<mpsc::Sender<()>>);
        impl EngineListener for StopsEngine {
            fn engine_stopped(&self, _error: Option<String>) {
                if let Some(engine) = self.0.lock().unwrap().take() {
                    engine.stop();
                }
                let _ = self.1.lock().unwrap().send(());
            }
        }
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let listener = Arc::new(StopsEngine(Mutex::new(None), Mutex::new(done_tx)));
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::clone(&listener) as Arc<dyn EngineListener>,
            recording_flows().0,
            None,
        )
        .unwrap();
        *listener.0.lock().unwrap() = Some(Arc::clone(&engine));
        drop(peer); // the tunnel closes; the listener runs on the engine thread
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("listener deadlocked");
    }

    #[test]
    fn rejects_a_negative_descriptor() {
        let (tx, _rx) = mpsc::channel();
        let result = Engine::start(
            -1,
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            recording_flows().0,
            None,
        );
        assert!(matches!(
            result,
            Err(EngineError::InvalidDescriptor { fd: -1 })
        ));
    }

    #[test]
    fn rejects_a_tunnel_resolver_that_is_not_an_address() {
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (tx, _rx) = mpsc::channel();
        let result = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            vec!["dns.example".into()],
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            recording_flows().0,
            None,
        );
        assert!(matches!(
            result,
            Err(EngineError::InvalidAddress { address }) if address == "dns.example"
        ));
        // The engine owned the descriptor and closed it: the peer reads end-of-file.
        assert_eq!((&peer).read(&mut [0u8; 16]).unwrap(), 0);
    }

    #[test]
    fn keeps_only_plain_ip_resolvers() {
        let Started {
            engine,
            peer: _peer,
            ..
        } = start_on_socketpair();
        engine.set_upstream_dns(vec![
            "192.0.2.1".into(),
            "fe80::1%wlan0".into(),
            "not an address".into(),
            "2001:db8::1".into(),
        ]);
        let expected: Vec<SocketAddr> = vec![
            "192.0.2.1:53".parse().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        ];
        assert_eq!(engine.dns.upstream(), expected);
        engine.stop();
    }

    /// Every flow reaches the app with its owner within a second (CM-01), and every
    /// flow that starts also ends, even when the engine stops first.
    #[test]
    fn reports_each_flow_with_its_owner_within_a_second() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let Started {
            engine,
            peer,
            flows,
            batches,
            ..
        } = start_on_socketpair();

        let sent = std::time::Instant::now();
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        let first = batches
            .recv_timeout(Duration::from_secs(1))
            .expect("no flow event within 1 s");
        assert!(sent.elapsed() < Duration::from_secs(1));
        assert_eq!(first.len(), 1);
        let started = &first[0];
        assert_eq!(started.proto, FlowProto::Udp);
        assert_eq!(
            (started.local_ip.as_str(), started.local_port),
            ("10.111.0.1", 40_000)
        );
        assert_eq!(
            (started.remote_ip.as_str(), started.remote_port),
            ("127.0.0.1", port)
        );
        assert_eq!(started.uid, OWNER);
        assert_eq!(started.app.as_deref(), Some(OWNER_APP));
        assert_eq!(started.ended_ms, None);
        assert_eq!(
            flows.asked.lock().unwrap()[0],
            (
                FlowProto::Udp,
                "10.111.0.1".to_owned(),
                40_000,
                "127.0.0.1".to_owned(),
                port
            )
        );
        let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
        assert!(echoed > 0);

        // Refused at once (port 853 at the tunnel resolver): it starts and ends.
        peer.send(&udp_packet([10, 111, 0, 53], 853)).unwrap();
        let mut records = Vec::new();
        while !records
            .iter()
            .any(|r: &FlowRecord| r.remote_port == 853 && r.ended_ms.is_some())
        {
            records.extend(
                batches
                    .recv_timeout(Duration::from_secs(1))
                    .expect("refused flow not reported"),
            );
        }

        // Stopping ends the echo flow, which was still open, with its byte counts.
        engine.stop();
        let mut rest: Vec<FlowRecord> = batches.try_iter().flatten().collect();
        rest.retain(|r| r.id == started.id);
        assert_eq!(
            rest.len(),
            1,
            "the open flow must be reported as ended once"
        );
        let ended = &rest[0];
        assert!(ended.ended_ms.unwrap() >= ended.started_ms);
        assert_eq!((ended.bytes_up, ended.bytes_down), (2, 2));
        assert_eq!(ended.uid, OWNER);
        assert!(!ended.blocked);
    }

    /// With a history, every flow is stored, encrypted, with its app and final counts.
    /// The app was installed after the history began, so its first connection raises
    /// one alert (CM-04).
    #[test]
    fn writes_flows_to_the_history() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path.clone(), vec![3; 32]).unwrap();
        let heard = Arc::new(HeardAlerts::default());
        history.set_alert_listener(Some(heard.clone()));

        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, batches) = recording_flows_installed(Some(history.began_ms()));
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
        assert!(echoed > 0);
        // The start is in the history after the first batch.
        batches.recv_timeout(Duration::from_secs(1)).unwrap();
        let stored = history.recent_flows(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].app.as_deref(), Some(OWNER_APP));
        assert_eq!(stored[0].ended_ms, None);

        engine.stop();
        let stored = history.recent_flows(10).unwrap();
        assert_eq!(stored.len(), 1, "start and end are one row");
        let flow = &stored[0];
        assert_eq!(
            (flow.remote_ip.as_str(), flow.remote_port),
            ("127.0.0.1", port)
        );
        assert!(flow.ended_ms.is_some());
        assert_eq!((flow.bytes_up, flow.bytes_down), (2, 2));
        assert_eq!(engine.snapshot().history_failures, 0);

        // The app detail view reads the same flow back per destination.
        let app = history.app_summary(OWNER_APP.into(), 10).unwrap().unwrap();
        assert_eq!((app.flows, app.bytes_up, app.bytes_down), (1, 2, 2));
        assert_eq!(app.destinations.len(), 1);
        assert_eq!(app.destinations[0].destination, "127.0.0.1");
        assert_eq!(app.first_seen_ms, flow.started_ms);

        // CM-04: one alert for the new app's first connection, to an address here.
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};
        let heard = heard.0.lock().unwrap().clone();
        assert_eq!(heard.len(), 1, "{heard:?}");
        assert_eq!(heard[0].rule, AlertRule::FirstNetworkUse);
        assert_eq!(heard[0].severity, AlertSeverity::Info);
        assert_eq!(
            heard[0].evidence,
            [
                AlertEvidence::App {
                    app: OWNER_APP.into()
                },
                AlertEvidence::Destinations {
                    destinations: vec!["127.0.0.1".into()],
                    more: 0
                },
            ]
        );
        assert_eq!(history.alerts(true, 10).unwrap(), heard);
    }

    /// ID-13 through the real packet engine: a datagram to an address that the indicator
    /// list in force names raises a Critical alert about its app within 5 s, and is not
    /// blocked.
    #[test]
    fn a_known_address_raises_an_alert_within_five_seconds() {
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};
        use crate::feed::tests::{indicators, open, path, stage};

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(db, vec![3; 32]).unwrap();
        let heard = Arc::new(HeardAlerts::default());
        history.set_alert_listener(Some(heard.clone()));
        let feed = open(&dir.path().join("feed"));
        let staged = stage(
            dir.path(),
            1,
            &[(
                "indicators-lab.json",
                indicators("lab", &[("address", "198.51.100.7")]),
            )],
        );
        feed.install(path(&staged)).unwrap();

        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, _batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        engine.set_feed(Some(feed));
        let sent = std::time::Instant::now();
        peer.send(&udp_packet([198, 51, 100, 7], 9)).unwrap();
        while heard.0.lock().unwrap().is_empty() && sent.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let elapsed = sent.elapsed();
        engine.stop();

        let heard = heard.0.lock().unwrap();
        assert_eq!(heard.len(), 1, "after {elapsed:?}: {heard:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(heard[0].rule, AlertRule::KnownIndicator);
        assert_eq!(heard[0].severity, AlertSeverity::Critical);
        assert_eq!(
            heard[0].evidence[0],
            AlertEvidence::App {
                app: OWNER_APP.into()
            }
        );
        let stored = history.recent_flows(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].blocked, "nothing is blocked without the user");
    }

    /// CM-10 through the real packet engine: with a rule blocking the app, its datagram
    /// never reaches the server, and the flow is stored as blocked.
    #[test]
    fn a_blocking_rule_stops_an_apps_traffic() {
        use crate::firewall::{FirewallRule, RuleAction};

        let (_dir, history) = blocking_history();
        history
            .set_firewall_rule(
                FirewallRule {
                    app: Some(OWNER_APP.into()),
                    destination: None,
                    action: RuleAction::Block,
                },
                None,
            )
            .unwrap();
        assert_the_engine_blocks(&history, recording_flows());
    }

    /// CM-08 through the real packet engine: with Block-unknown on, an app installed
    /// since then has its datagram stopped, and the alert for its first connection says
    /// it was blocked.
    #[test]
    fn block_unknown_stops_a_new_apps_traffic() {
        use crate::alerts::{AlertAction, AlertEvidence};
        use crate::firewall::FirewallMode;

        let (_dir, history) = blocking_history();
        let heard = Arc::new(HeardAlerts::default());
        history.set_alert_listener(Some(heard.clone()));
        history
            .set_firewall_mode(FirewallMode::BlockUnknown)
            .unwrap();
        let installed = crate::history::now_ms() + 1;
        assert_the_engine_blocks(&history, recording_flows_installed(Some(installed)));
        let heard = heard.0.lock().unwrap();
        assert_eq!(heard.len(), 1, "{heard:?}");
        assert!(heard[0].evidence.contains(&AlertEvidence::NewAppBlocked));
        assert_eq!(
            heard[0].actions[0],
            AlertAction::AllowApp {
                app: OWNER_APP.into()
            }
        );
    }

    fn blocking_history() -> (tempfile::TempDir, Arc<HistoryStore>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![7; 32]).unwrap();
        (dir, history)
    }

    /// Sends one datagram through the engine and checks that the firewall stopped it:
    /// nothing reaches the server, and the flow is reported and stored as blocked.
    fn assert_the_engine_blocks(
        history: &Arc<HistoryStore>,
        (flows, batches): (Arc<RecordingFlows>, mpsc::Receiver<Vec<FlowRecord>>),
    ) {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        echo.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        let (tx, _stopped) = mpsc::channel();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(history)),
        )
        .unwrap();
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        let mut records = Vec::new();
        while !records.iter().any(|r: &FlowRecord| r.ended_ms.is_some()) {
            records.extend(
                batches
                    .recv_timeout(Duration::from_secs(1))
                    .expect("the blocked flow is reported"),
            );
        }
        assert!(
            echo.recv_from(&mut [0u8; 64]).is_err(),
            "nothing reached the server"
        );
        assert!(records.iter().all(|r| r.blocked));
        engine.stop();
        let stored = history.recent_flows(10).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].blocked);
        assert_eq!(engine.snapshot().history_failures, 0);
    }

    /// RA-01 through the real packet engine: blocking an app ends its open connection
    /// within a second, so nothing more reaches the server, and the connection is
    /// stored as blocked.
    #[test]
    fn blocking_an_app_ends_its_open_connections() {
        use crate::firewall::{FirewallRule, RuleAction};

        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (_dir, history) = blocking_history();
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        assert!((&peer).read(&mut [0u8; 2048]).expect("no echo") > 0);

        let blocked_at = std::time::Instant::now();
        history
            .set_firewall_rule(
                FirewallRule {
                    app: Some(OWNER_APP.into()),
                    destination: None,
                    action: RuleAction::Block,
                },
                None,
            )
            .unwrap();
        let ended = loop {
            let batch = batches
                .recv_timeout(Duration::from_secs(1))
                .expect("the open flow ends");
            if let Some(ended) = batch.into_iter().find(|r| r.ended_ms.is_some()) {
                break ended;
            }
        };
        let took = blocked_at.elapsed();
        assert!(ended.blocked, "{ended:?}");
        assert!(took < Duration::from_secs(1), "took {took:?}");
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        assert!(
            (&peer).read(&mut [0u8; 2048]).is_err(),
            "nothing comes back once blocked"
        );
        engine.stop();
        let stored = history.recent_flows(10).unwrap();
        assert!(
            !stored.is_empty() && stored.iter().all(|f| f.blocked),
            "{stored:?}"
        );
        assert_eq!(engine.snapshot().history_failures, 0);
    }

    /// RA-03 through the real packet engine: isolating the phone ends an app's open
    /// connection within a second, unless a rule allows the app as a whole; ending
    /// isolation lets it through again.
    #[test]
    fn isolation_ends_open_connections_of_apps_not_allowed() {
        use crate::firewall::{FirewallRule, RuleAction};

        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let (_dir, history) = blocking_history();
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        let echoed = |source_port: u16| {
            peer.send(&udp_packet_from(source_port, [127, 0, 0, 1], port))
                .unwrap();
            (&peer).read(&mut [0u8; 2048]).is_ok()
        };
        assert!(echoed(40_000));

        let isolated_at = std::time::Instant::now();
        history
            .isolate("io.github.malekhasan.sentinel".into())
            .unwrap();
        let ended = loop {
            let batch = batches
                .recv_timeout(Duration::from_secs(1))
                .expect("the open flow ends");
            if let Some(ended) = batch.into_iter().find(|r| r.ended_ms.is_some()) {
                break ended;
            }
        };
        let took = isolated_at.elapsed();
        assert!(ended.blocked, "{ended:?}");
        assert!(took < Duration::from_secs(1), "took {took:?}");
        assert!(!echoed(40_001), "isolated");

        history
            .set_firewall_rule(
                FirewallRule {
                    app: Some(OWNER_APP.into()),
                    destination: None,
                    action: RuleAction::Allow,
                },
                None,
            )
            .unwrap();
        assert!(echoed(40_002), "an app allowed as a whole");
        history.firewall_rules().unwrap().iter().for_each(|rule| {
            history.remove_firewall_rule(rule.key.clone()).unwrap();
        });
        assert!(!echoed(40_003), "isolated again without the rule");
        history.end_isolation().unwrap();
        assert!(echoed(40_004), "isolation ended");
        engine.stop();
    }

    /// Bytes relayed while the user is away are counted apart in the same flow, stored,
    /// and totalled per app (CM-06).
    #[test]
    fn counts_traffic_while_away_apart() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![5; 32]).unwrap();
        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, _batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        assert!(!engine.snapshot().away, "present until told otherwise");

        // One flow (same ports each time): present, away, present again. Each echo is
        // read back before the switch flips, so both of its directions are counted.
        for away in [false, true, false] {
            engine.set_away(away);
            assert_eq!(engine.snapshot().away, away);
            peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
            let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
            assert!(echoed > 0);
        }
        engine.stop();

        let stored = history.recent_flows(10).unwrap();
        assert_eq!(stored.len(), 1, "one flow");
        assert_eq!((stored[0].bytes_up, stored[0].bytes_down), (6, 6));
        let app = history.app_summary(OWNER_APP.into(), 10).unwrap().unwrap();
        assert_eq!((app.bytes_up_away, app.bytes_down_away), (2, 2));
        assert_eq!(
            history.away_totals(0, 10).unwrap(),
            vec![HistoryAway {
                app: Some(OWNER_APP.to_owned()),
                flows: 1,
                bytes_up_away: 2,
                bytes_down_away: 2,
            }]
        );
    }

    /// With an IP database set, every flow carries its network, owner and country
    /// (DT-01); without one, none. The database can be set while the engine runs.
    #[test]
    fn enriches_each_flow_from_the_ip_database() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let mut builder = sentinel_enrich::IpDbBuilder::new(sentinel_enrich::Sources {
            network: "IPtoASN test".into(),
            country: "DB-IP Lite test".into(),
        });
        let loopback = std::net::IpAddr::from(Ipv4Addr::LOCALHOST);
        builder.add_network(loopback, loopback, 64_500).unwrap();
        builder.name_network(64_500, "EXAMPLE-NET").unwrap();
        builder.add_country(loopback, loopback, "JO").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ip.db");
        std::fs::write(&path, builder.build().unwrap()).unwrap();
        let database = IpDatabase::open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(database.sources().network, "IPtoASN test");

        let Started {
            engine,
            peer,
            batches,
            ..
        } = start_on_socketpair();
        let first_record = |src_port: u16| {
            peer.send(&udp_packet_from(src_port, [127, 0, 0, 1], port))
                .unwrap();
            let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
            assert!(echoed > 0);
            loop {
                let batch = batches
                    .recv_timeout(Duration::from_secs(1))
                    .expect("no flow event");
                if let Some(record) = batch.into_iter().find(|r| r.local_port == src_port) {
                    return record;
                }
            }
        };

        let plain = first_record(40_101);
        assert_eq!((plain.asn, plain.country), (None, None), "no database yet");

        engine.set_ip_database(Some(database));
        let enriched = first_record(40_102);
        assert_eq!(enriched.asn, Some(64_500));
        assert_eq!(enriched.network_owner.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(enriched.country.as_deref(), Some("JO"));

        engine.set_ip_database(None);
        assert_eq!(first_record(40_103).asn, None);
        engine.stop();
    }

    /// The history keeps each destination's network and country with the sources they
    /// come from, for "why we believe this" (DT-02).
    #[test]
    fn stores_destination_facts_with_their_sources() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let mut builder = sentinel_enrich::IpDbBuilder::new(sentinel_enrich::Sources {
            network: "IPtoASN 2026-10-15".into(),
            country: "DB-IP Lite 2026-10".into(),
        });
        let loopback = std::net::IpAddr::from(Ipv4Addr::LOCALHOST);
        builder.add_network(loopback, loopback, 64_500).unwrap();
        builder.name_network(64_500, "EXAMPLE-NET").unwrap();
        builder.add_country(loopback, loopback, "JO").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ip.db");
        std::fs::write(&db_path, builder.build().unwrap()).unwrap();
        let history_path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(history_path, vec![6; 32]).unwrap();

        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (tx, _stopped) = mpsc::channel();
        let (flows, _batches) = recording_flows();
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            flows,
            Some(Arc::clone(&history)),
        )
        .unwrap();
        engine.set_ip_database(Some(
            IpDatabase::open(db_path.to_string_lossy().into_owned()).unwrap(),
        ));
        peer.send(&udp_packet([127, 0, 0, 1], port)).unwrap();
        let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
        assert!(echoed > 0);
        engine.stop();

        let app = history.app_summary(OWNER_APP.into(), 10).unwrap().unwrap();
        let destination = &app.destinations[0];
        assert_eq!(destination.destination, "127.0.0.1");
        assert_eq!(destination.name_source, None, "an address, no name");
        assert_eq!(destination.asn, Some(64_500));
        assert_eq!(destination.network_owner.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(
            destination.network_source.as_deref(),
            Some("IPtoASN 2026-10-15")
        );
        assert_eq!(destination.country.as_deref(), Some("JO"));
        assert_eq!(
            destination.country_source.as_deref(),
            Some("DB-IP Lite 2026-10")
        );
    }

    /// The live view (CM-03) shows open flows by app with their bytes so far, and
    /// forgets them once they end.
    #[test]
    fn live_view_groups_open_flows_by_app() {
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let Started { engine, peer, .. } = start_on_socketpair();
        assert!(engine.live_apps().is_empty());

        for src_port in [40_001, 40_002] {
            peer.send(&udp_packet_from(src_port, [127, 0, 0, 1], port))
                .unwrap();
            let echoed = (&peer).read(&mut [0u8; 2048]).expect("no echo");
            assert!(echoed > 0);
        }
        let apps = engine.live_apps();
        assert_eq!(apps.len(), 1, "both flows belong to one app: {apps:?}");
        let app = &apps[0];
        assert_eq!((app.uid, app.app.as_deref()), (OWNER, Some(OWNER_APP)));
        assert_eq!(app.open_flows, 2);
        assert_eq!((app.bytes_up, app.bytes_down), (4, 4));
        assert_eq!(app.top_destinations, vec!["127.0.0.1"]);

        engine.stop();
        assert!(
            engine.live_apps().is_empty(),
            "no flow is open after a stop"
        );
    }

    /// Notes when each flow is first reported, by the app's source port.
    #[derive(Default)]
    struct TimedFlows {
        first_seen: Mutex<std::collections::HashMap<u16, std::time::Instant>>,
        records: Mutex<Vec<FlowRecord>>,
    }
    impl FlowObserver for TimedFlows {
        fn owner(&self, _: FlowProto, _: String, _: u16, _: String, _: u16) -> FlowOwner {
            FlowOwner {
                uid: OWNER,
                app: Some(OWNER_APP.to_owned()),
                installed_ms: None,
                system: false,
            }
        }
        fn flows(&self, records: Vec<FlowRecord>) {
            let now = std::time::Instant::now();
            let mut seen = self.first_seen.lock().unwrap();
            for record in &records {
                seen.entry(record.local_port).or_insert(now);
            }
            self.records.lock().unwrap().extend(records);
        }
    }

    /// CM-01 acceptance: every flow in the run reaches the app with its owner within
    /// 1 s of its first packet, and every flow ends up in the history.
    #[test]
    fn every_flow_is_reported_within_a_second() {
        const FLOWS: u16 = 200;
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![4; 32]).unwrap();

        let (tun, peer) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).unwrap();
        // Read the echoes, so the tunnel never backs up.
        let reader = peer.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while (&reader).read(&mut buf).is_ok_and(|n| n > 0) {}
        });
        let (tx, _stopped) = mpsc::channel();
        let timed = Arc::new(TimedFlows::default());
        let engine = Engine::start(
            OwnedFd::from(tun).into_raw_fd(),
            Vec::new(),
            Arc::new(CountingProtector(AtomicUsize::new(0))),
            Arc::new(ChannelListener(Mutex::new(tx))),
            Arc::clone(&timed) as Arc<dyn FlowObserver>,
            Some(Arc::clone(&history)),
        )
        .unwrap();

        let mut sent = std::collections::HashMap::new();
        for i in 0..FLOWS {
            let port = 41_000 + i;
            sent.insert(port, std::time::Instant::now());
            peer.send(&udp_packet_from(port, [127, 0, 0, 1], echo_port))
                .unwrap();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while timed.first_seen.lock().unwrap().len() < usize::from(FLOWS)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let seen = timed.first_seen.lock().unwrap().clone();
        let mut late: Vec<_> = sent
            .iter()
            .filter(|(port, at)| {
                seen.get(port)
                    .is_none_or(|first| first.duration_since(**at) >= Duration::from_secs(1))
            })
            .map(|(port, _)| *port)
            .collect();
        late.sort_unstable();
        assert!(
            late.is_empty(),
            "{} of {FLOWS} flows missing or reported after 1 s: {late:?}",
            late.len()
        );
        assert!(
            timed
                .records
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.uid == OWNER && r.app.as_deref() == Some(OWNER_APP)),
            "every record carries its owner"
        );

        engine.stop();
        let stored = history.recent_flows(u32::from(FLOWS) * 2).unwrap();
        assert_eq!(stored.len(), usize::from(FLOWS), "one history row per flow");
        assert!(
            stored.iter().all(|f| f.ended_ms.is_some()),
            "every flow ended"
        );
        assert_eq!(engine.snapshot().history_failures, 0);
    }
}

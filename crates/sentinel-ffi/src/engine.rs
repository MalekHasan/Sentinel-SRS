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

use crate::flows::{FlowEvents, FlowObserver};

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
    pub upstream_failures: u64,
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
    dns: Arc<DnsForward>,
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
    /// receives every flow, with its owner (CM-01).
    #[uniffi::constructor]
    pub fn start(
        tun_fd: i32,
        tunnel_dns: Vec<String>,
        protector: Arc<dyn SocketProtector>,
        listener: Arc<dyn EngineListener>,
        flows: Arc<dyn FlowObserver>,
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
        let dns = Arc::new(DnsForward::new(tunnel_dns));
        let config = EngineConfig {
            dns_forward: Some(Arc::clone(&dns)),
            ..EngineConfig::default()
        };
        let running = Arc::new(AtomicBool::new(true));
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let events = Arc::new(FlowEvents::new(flows));

        let thread = {
            let stats = Arc::clone(&stats);
            let running = Arc::clone(&running);
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
            dns,
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

    pub fn snapshot(&self) -> EngineSnapshot {
        EngineSnapshot {
            running: self.running.load(Ordering::SeqCst),
            flows_total: self.stats.flows_total(),
            flows_active: self.stats.flows_active(),
            flows_blocked: self.stats.flows_blocked(),
            upstream_failures: self.stats.upstream_failures(),
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

    use crate::flows::{FlowProto, FlowRecord};

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

    /// Says every flow belongs to UID 10123, and passes on each batch it receives.
    struct RecordingFlows {
        asked: Mutex<Vec<OwnerQuestion>>,
        batches: Mutex<mpsc::Sender<Vec<FlowRecord>>>,
    }
    const OWNER: i32 = 10_123;
    impl FlowObserver for RecordingFlows {
        fn owner_uid(
            &self,
            proto: FlowProto,
            local_ip: String,
            local_port: u16,
            remote_ip: String,
            remote_port: u16,
        ) -> i32 {
            self.asked
                .lock()
                .unwrap()
                .push((proto, local_ip, local_port, remote_ip, remote_port));
            OWNER
        }
        fn flows(&self, records: Vec<FlowRecord>) {
            let _ = self.batches.lock().unwrap().send(records);
        }
    }

    fn recording_flows() -> (Arc<RecordingFlows>, mpsc::Receiver<Vec<FlowRecord>>) {
        let (tx, rx) = mpsc::channel();
        let flows = RecordingFlows {
            asked: Mutex::new(Vec::new()),
            batches: Mutex::new(tx),
        };
        (Arc::new(flows), rx)
    }

    fn udp_packet(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let builder =
            etherparse::PacketBuilder::ipv4([10, 111, 0, 1], dst, 64).udp(40_000, dst_port);
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
}

// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::DnsForward;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Must match `VpnService.Builder.setMtu`.
    pub mtu: u16,
    /// Idle time after which a TCP flow is reset: no byte either way for this long
    /// (audit A-18). Phones keep push-notification connections idle for many minutes, so
    /// this must be long (ipstack's default of 60 s would force constant reconnects and
    /// waste battery). Zero: no limit on smoltcp.
    pub tcp_idle_timeout: Duration,
    /// How long the app's side of a TCP flow may take to close once the flow ended,
    /// before it is reset (audit A-04): an app that never acknowledges the FIN would
    /// otherwise hold the stack's socket and its buffers for hours.
    pub tcp_linger: Duration,
    pub udp_idle_timeout: Duration,
    pub connect_timeout: Duration,
    /// How long to wait for the rest of a ClientHello split across TCP segments.
    pub sni_wait: Duration,
    pub dns_cache_capacity: usize,
    /// How often the engine reports that it still runs (SP-03, ADR-0029): see
    /// [`EngineStats::since_heartbeat`].
    pub heartbeat: Duration,
    /// The most flows open at once, TCP and UDP together (THREAT-MODEL-A D2, ADR-0028).
    /// A flow beyond it is refused before it reaches the observer: a TCP connection is
    /// reset, a datagram dropped. On smoltcp it also bounds the stack's TCP sockets,
    /// those still closing included. Each TCP flow holds about 176 KiB of buffers (128
    /// in the stack, 48 in the relay), so this bounds the engine's memory however many
    /// connections an app opens.
    pub max_flows: usize,
    /// Per-connection TCP buffer towards the app, in bytes, each direction. The window
    /// faces the app over a local tunnel with a tiny round-trip time, so small buffers
    /// keep throughput while bounding memory (ADR-0006). `None` keeps the stack default.
    pub tcp_buffer: Option<u32>,
    /// The tunnel's own resolver address and the real resolvers behind it. `None`
    /// relays DNS to whatever address the app asked, like any other flow.
    pub dns_forward: Option<Arc<DnsForward>>,
    /// Set while the user is away (on Android: the screen is off or locked). Bytes
    /// relayed meanwhile are also counted as "while away" in each flow (CM-06).
    pub away: Arc<AtomicBool>,
    /// Changes whenever the firewall may decide differently (its rules or mode). Every
    /// open flow then asks [`crate::Observer::recheck`] again, and ends if it is now
    /// blocked. `None`: verdicts never change while a flow is open.
    pub firewall_changes: Option<watch::Receiver<u64>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            mtu: 1500,
            tcp_idle_timeout: Duration::from_secs(2 * 60 * 60),
            tcp_linger: Duration::from_secs(60),
            udp_idle_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            sni_wait: Duration::from_millis(500),
            dns_cache_capacity: 20_000,
            heartbeat: Duration::from_secs(10),
            max_flows: 1024,
            tcp_buffer: Some(32 * 1024),
            dns_forward: None,
            away: Arc::new(AtomicBool::new(false)),
            firewall_changes: None,
        }
    }
}

/// Engine-wide counters, for health checks and the spike measurements.
#[derive(Debug)]
pub struct EngineStats {
    pub(crate) flows_total: AtomicU64,
    pub(crate) flows_active: AtomicU64,
    pub(crate) flows_blocked: AtomicU64,
    pub(crate) upstream_failures: AtomicU64,
    pub(crate) unsupported_packets: AtomicU64,
    /// Shared with the smoltcp stack, which refuses TCP connections beyond its sockets.
    pub(crate) flows_refused: Arc<AtomicU64>,
    /// When these counters were made: the origin of `last_beat_ms`.
    origin: Instant,
    /// The engine's last heartbeat, in milliseconds after `origin`.
    last_beat_ms: AtomicU64,
}

impl Default for EngineStats {
    fn default() -> Self {
        EngineStats {
            flows_total: AtomicU64::new(0),
            flows_active: AtomicU64::new(0),
            flows_blocked: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            unsupported_packets: AtomicU64::new(0),
            flows_refused: Arc::new(AtomicU64::new(0)),
            origin: Instant::now(),
            last_beat_ms: AtomicU64::new(0),
        }
    }
}

impl EngineStats {
    pub fn flows_total(&self) -> u64 {
        self.flows_total.load(Ordering::Relaxed)
    }
    pub fn flows_active(&self) -> u64 {
        self.flows_active.load(Ordering::Relaxed)
    }
    pub fn flows_blocked(&self) -> u64 {
        self.flows_blocked.load(Ordering::Relaxed)
    }
    pub fn upstream_failures(&self) -> u64 {
        self.upstream_failures.load(Ordering::Relaxed)
    }
    /// Flows refused because [`EngineConfig::max_flows`] were already open.
    pub fn flows_refused(&self) -> u64 {
        self.flows_refused.load(Ordering::Relaxed)
    }
    /// ICMP and other non-TCP/UDP packets, which this prototype does not forward.
    pub fn unsupported_packets(&self) -> u64 {
        self.unsupported_packets.load(Ordering::Relaxed)
    }
    /// How long ago the engine last reported that it runs (SP-03, ADR-0029): at most
    /// [`EngineConfig::heartbeat`] while it can run its tasks. It grows once the engine
    /// stops or hangs, for example with every worker thread stuck in a callback.
    ///
    /// Measured on the monotonic clock, which stands still while the device sleeps: a
    /// phone asleep is not an engine gone silent.
    pub fn since_heartbeat(&self) -> Duration {
        let last = Duration::from_millis(self.last_beat_ms.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last)
    }
    fn beat(&self) {
        let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_beat_ms.store(now, Ordering::Relaxed);
    }
}

/// SP-03: report every `period`, for as long as the engine's runtime runs its tasks.
/// Never returns; the engine drops it when it stops.
pub(crate) async fn heartbeat(stats: Arc<EngineStats>, period: Duration) {
    let mut every = tokio::time::interval(period);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        stats.beat();
    }
}

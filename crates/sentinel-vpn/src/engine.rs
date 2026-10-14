// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Must match `VpnService.Builder.setMtu`.
    pub mtu: u16,
    /// Idle time after which a TCP flow is dropped. Phones keep push-notification
    /// connections idle for many minutes, so this must be long (ipstack's default of
    /// 60 s would force constant reconnects and waste battery).
    pub tcp_idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub connect_timeout: Duration,
    /// How long to wait for the rest of a ClientHello split across TCP segments.
    pub sni_wait: Duration,
    pub dns_cache_capacity: usize,
    /// Per-connection TCP buffer towards the app, in bytes, each direction. The window
    /// faces the app over a local tunnel with a tiny round-trip time, so small buffers
    /// keep throughput while bounding memory (ADR-0006). `None` keeps the stack default.
    pub tcp_buffer: Option<u32>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            mtu: 1500,
            tcp_idle_timeout: Duration::from_secs(2 * 60 * 60),
            udp_idle_timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(10),
            sni_wait: Duration::from_millis(500),
            dns_cache_capacity: 20_000,
            tcp_buffer: Some(32 * 1024),
        }
    }
}

/// Engine-wide counters, for health checks and the spike measurements.
#[derive(Debug, Default)]
pub struct EngineStats {
    pub(crate) flows_total: AtomicU64,
    pub(crate) flows_active: AtomicU64,
    pub(crate) flows_blocked: AtomicU64,
    pub(crate) upstream_failures: AtomicU64,
    pub(crate) unsupported_packets: AtomicU64,
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
    /// ICMP and other non-TCP/UDP packets, which this prototype does not forward.
    pub fn unsupported_packets(&self) -> u64 {
        self.unsupported_packets.load(Ordering::Relaxed)
    }
}

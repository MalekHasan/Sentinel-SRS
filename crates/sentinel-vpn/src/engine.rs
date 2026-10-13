// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig};

use crate::dns::DnsCache;
use crate::relay::{self, Ctx};
use crate::{Observer, Protect, TunDevice};

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
    /// Per-connection TCP buffer towards the app, in bytes. `None` keeps the stack's
    /// default (ipstack: 16 KiB; smoltcp: about 320 KiB, allocated up front).
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
            tcp_buffer: None,
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

/// Run the engine until the tunnel closes or the future is dropped.
///
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
    let mut stack_config = IpStackConfig::default();
    stack_config.mtu(config.mtu)?;
    stack_config.udp_timeout(config.udp_idle_timeout);
    let mut tcp = TcpConfig::default();
    tcp.timeout = config.tcp_idle_timeout;
    if let Some(size) = config.tcp_buffer {
        tcp.max_unacked_bytes = size;
        tcp.read_buffer_size = size as usize;
    }
    stack_config.with_tcp_config(tcp);
    let mut stack = IpStack::new(stack_config, device);

    let ctx = Arc::new(Ctx {
        protect,
        observer,
        dns: DnsCache::new(config.dns_cache_capacity),
        config,
        stats,
        next_id: AtomicU64::new(1),
    });

    loop {
        match stack.accept().await.map_err(io::Error::from)? {
            IpStackStream::Tcp(stream) => {
                let (src, dst) = (stream.local_addr(), stream.peer_addr());
                tokio::spawn(relay::tcp(Arc::clone(&ctx), stream, src, dst));
            }
            IpStackStream::Udp(stream) => {
                let (src, dst) = (stream.local_addr(), stream.peer_addr());
                tokio::spawn(relay::udp(Arc::clone(&ctx), stream, src, dst));
            }
            IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {
                ctx.stats
                    .unsupported_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

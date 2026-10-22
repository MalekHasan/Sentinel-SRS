// SPDX-License-Identifier: GPL-3.0-or-later
//! Engine on ipstack, kept behind the `ipstack` feature to re-run the stack comparison
//! (ADR-0006). Not used by the app: ipstack has no receive flow control, so an app
//! uploading faster than the network makes the engine buffer the difference in memory.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig};
use tokio::task::JoinSet;

use crate::dns::DnsCache;
use crate::engine::heartbeat;
use crate::relay::{self, BlockedUdp, Ctx, Reset};
use crate::{EngineConfig, EngineStats, Observer, Protect, TunDevice};

/// Run the engine until the tunnel closes or the future is dropped.
///
/// Returns an error of kind `BrokenPipe` when the tunnel closes or fails (for example
/// when the user revokes the VPN), so the app can record a monitoring gap (SP-03).
/// Dropping the future (or aborting its task) stops all flows. If this process dies,
/// Android tears down the tunnel and traffic flows outside it: the engine fails open
/// (SRS NF-07), and the app records a monitoring gap.
pub async fn run_ipstack(
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
    let closed = device.closed();
    let mut stack = IpStack::new(stack_config, device);

    let ctx = Arc::new(Ctx {
        protect,
        observer,
        dns: DnsCache::new(config.dns_cache_capacity),
        config,
        stats,
        next_id: AtomicU64::new(1),
    });

    // Relays belong to this future, so dropping it aborts them (`IpStack` aborts its
    // own task on drop). So does the heartbeat (SP-03).
    let mut relays = JoinSet::new();
    let mut beats = JoinSet::new();
    let stats = Arc::clone(&ctx.stats);
    beats.spawn(heartbeat(ctx.config.heartbeat, move || stats.beat()));
    let closed = closed.wait();
    tokio::pin!(closed);
    loop {
        tokio::select! {
            biased;
            reason = &mut closed => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, reason));
            }
            accepted = stack.accept() => match accepted.map_err(io::Error::from)? {
                IpStackStream::Tcp(stream) => {
                    let (src, dst) = (stream.local_addr(), stream.peer_addr());
                    relays.spawn(relay::tcp(Arc::clone(&ctx), stream, src, dst));
                }
                IpStackStream::Udp(stream) => {
                    let (src, dst) = (stream.local_addr(), stream.peer_addr());
                    relays.spawn(relay::udp(Arc::clone(&ctx), stream, src, dst));
                }
                IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {
                    ctx.stats
                        .unsupported_packets
                        .fetch_add(1, Ordering::Relaxed);
                }
            },
            Some(_) = relays.join_next(), if !relays.is_empty() => {}
        }
    }
}

/// The comparison stack keeps its own UDP sessions: a blocked one is ended, and the
/// next datagram decided again.
impl BlockedUdp for ipstack::IpStackUdpStream {
    fn remember_blocked(&self, _idle: std::time::Duration) {}
}

impl Reset for ipstack::IpStackTcpStream {
    /// ipstack offers no reset: the stream is dropped, and ipstack ends the connection.
    fn reset(self) {}
}

// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Where a flow's hostname came from (SRS §13 `flow.hostname_src`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSource {
    Dns,
    Sni,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
}

/// Live byte counters, readable while the flow is running (for the live view, CM-03).
/// Bytes carried while the user is away are also counted separately (CM-06).
#[derive(Debug, Default)]
pub struct FlowCounters {
    up: AtomicU64,
    down: AtomicU64,
    up_away: AtomicU64,
    down_away: AtomicU64,
    /// The engine's "user is away" switch ([`crate::EngineConfig::away`]).
    away: Arc<AtomicBool>,
}

impl FlowCounters {
    /// Counters that follow the engine's `away` switch.
    pub fn new(away: Arc<AtomicBool>) -> Self {
        FlowCounters {
            away,
            ..FlowCounters::default()
        }
    }

    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    /// Of [`Self::bytes_up`], the bytes sent while the user was away.
    pub fn bytes_up_away(&self) -> u64 {
        self.up_away.load(Ordering::Relaxed)
    }

    /// Of [`Self::bytes_down`], the bytes received while the user was away.
    pub fn bytes_down_away(&self) -> u64 {
        self.down_away.load(Ordering::Relaxed)
    }

    /// Counts bytes the app sent. Public so that other stacks, and tests, can feed the
    /// same live view.
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
        if self.away.load(Ordering::Relaxed) {
            self.up_away.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    /// Counts bytes the app received.
    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
        if self.away.load(Ordering::Relaxed) {
            self.down_away.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

/// One network conversation from an app (SRS §1.4 "Flow").
#[derive(Debug, Clone)]
pub struct FlowInfo {
    pub id: u64,
    pub proto: Proto,
    /// The app's side, inside the tunnel. On Android, used to look up the owner UID.
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub hostname: Option<String>,
    pub hostname_source: Option<HostnameSource>,
    /// Unix milliseconds.
    pub started_ms: u64,
    pub counters: Arc<FlowCounters>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTotals {
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Of the above, the bytes carried while the user was away (CM-06).
    pub bytes_up_away: u64,
    pub bytes_down_away: u64,
    pub ended_ms: u64,
    pub verdict: Verdict,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Receives flow events. Called from engine tasks, so implementations must be quick and
/// must not block; heavy work (database writes, detection) belongs on another thread.
pub trait Observer: Send + Sync + 'static {
    /// A new flow, before any upstream connection. On Android this is where the owner
    /// UID is looked up and per-app rules are applied.
    fn flow_started(&self, _flow: &FlowInfo) -> Verdict {
        Verdict::Allow
    }

    /// The TLS server name of a TCP flow is known. Returning [`Verdict::Block`] closes
    /// the flow before the ClientHello is forwarded.
    fn hostname_seen(&self, _flow: &FlowInfo, _hostname: &str) -> Verdict {
        Verdict::Allow
    }

    /// A TCP flow began a TLS handshake whose server name cannot be read: its ClientHello
    /// came too slowly ([`crate::EngineConfig::sni_wait`]), or broken, or longer than the
    /// engine reads. The server may still see a name. Returning [`Verdict::Block`] closes
    /// the flow before anything is forwarded (audit finding A-03).
    fn hostname_unreadable(&self, _flow: &FlowInfo) -> Verdict {
        Verdict::Allow
    }

    /// A DNS query for `qname` is about to be sent, asking for records of type `qtype`
    /// (see [`crate::DnsQuery`]). Returning [`Verdict::Block`] answers it at once with
    /// "no such name" instead, and nothing is sent.
    fn dns_query(&self, _flow: &FlowInfo, _qname: &str, _qtype: u16) -> Verdict {
        Verdict::Allow
    }

    /// A DNS response passed through the tunnel.
    fn dns_answer(&self, _flow: &FlowInfo, _qname: &str, _ips: &[IpAddr]) {}

    /// The firewall changed ([`crate::EngineConfig::firewall_changes`]) while `flow` was
    /// open: may it go on? Returning [`Verdict::Block`] ends it at once, in both
    /// directions. Called for every open flow on each change.
    fn recheck(&self, _flow: &FlowInfo) -> Verdict {
        Verdict::Allow
    }

    fn flow_ended(&self, _flow: &FlowInfo, _totals: FlowTotals) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_carried_while_away_are_counted_apart() {
        let away = Arc::new(AtomicBool::new(false));
        let counters = FlowCounters::new(Arc::clone(&away));
        counters.add_up(10);
        counters.add_down(100);
        away.store(true, Ordering::Relaxed);
        counters.add_up(1);
        counters.add_down(2);
        away.store(false, Ordering::Relaxed);
        counters.add_up(1_000);
        assert_eq!((counters.bytes_up(), counters.bytes_down()), (1_011, 102));
        assert_eq!(
            (counters.bytes_up_away(), counters.bytes_down_away()),
            (1, 2)
        );
    }
}

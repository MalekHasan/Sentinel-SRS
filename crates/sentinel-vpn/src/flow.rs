// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
#[derive(Debug, Default)]
pub struct FlowCounters {
    up: AtomicU64,
    down: AtomicU64,
}

impl FlowCounters {
    pub fn bytes_up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }

    pub(crate) fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
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

    /// A DNS response passed through the tunnel.
    fn dns_answer(&self, _flow: &FlowInfo, _qname: &str, _ips: &[IpAddr]) {}

    fn flow_ended(&self, _flow: &FlowInfo, _totals: FlowTotals) {}
}

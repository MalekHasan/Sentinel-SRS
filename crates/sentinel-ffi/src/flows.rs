// SPDX-License-Identifier: GPL-3.0-or-later
//! Flow events for the app (SRS CM-01, CM-02): which app opened each connection, where
//! to, under which name, and how much it carried.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sentinel_vpn::{FlowInfo, FlowTotals, HostnameSource, Observer, Proto, Verdict};
use tokio::sync::Notify;

/// How long events wait so that several can cross into Kotlin together. Short enough
/// that every flow appears within a second (CM-01).
const BATCH_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FlowProto {
    Tcp,
    Udp,
}

/// Where a flow's hostname came from (SRS §13 `flow.hostname_src`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NameSource {
    Dns,
    Sni,
}

/// One flow, as first seen or as finished. The same `id` arrives twice: once when the
/// flow starts (`ended_ms` is `None`) and once when it ends.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FlowRecord {
    pub id: u64,
    pub proto: FlowProto,
    /// The app's side, inside the tunnel.
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    /// Linux UID of the app that owns the connection, or -1 if Android could not say.
    pub uid: i32,
    pub hostname: Option<String>,
    pub hostname_source: Option<NameSource>,
    /// Unix milliseconds.
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked: bool,
}

/// Implemented by the app.
#[uniffi::export(with_foreign)]
pub trait FlowObserver: Send + Sync {
    /// The app that owns a new connection: on Android,
    /// `ConnectivityManager.getConnectionOwnerUid`, or -1. Called once per flow on an
    /// engine thread, before the upstream connection exists, so it must be quick.
    fn owner_uid(
        &self,
        proto: FlowProto,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
    ) -> i32;

    /// New and finished flows, oldest first, in batches.
    fn flows(&self, records: Vec<FlowRecord>);
}

/// Bridges the engine's [`Observer`] to a [`FlowObserver`], batching events.
pub(crate) struct FlowEvents {
    foreign: Arc<dyn FlowObserver>,
    /// Flows that have started and not ended, with their owner.
    open: Mutex<HashMap<u64, (FlowInfo, i32)>>,
    pending: Mutex<Vec<FlowRecord>>,
    ready: Notify,
}

impl FlowEvents {
    pub(crate) fn new(foreign: Arc<dyn FlowObserver>) -> Self {
        FlowEvents {
            foreign,
            open: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            ready: Notify::new(),
        }
    }

    /// Delivers batches for as long as it is polled. Sleeps without a timer while there
    /// is nothing to send, so an idle engine does not wake up for it.
    pub(crate) async fn deliver(&self) {
        loop {
            self.ready.notified().await;
            tokio::time::sleep(BATCH_DELAY).await;
            self.flush();
        }
    }

    /// Ends every flow still open (the engine is stopping), then sends what is left.
    pub(crate) fn close_all(&self, ended_ms: u64) {
        let open: Vec<_> = lock(&self.open).drain().map(|(_, entry)| entry).collect();
        let mut pending = lock(&self.pending);
        for (flow, uid) in open {
            pending.push(record(&flow, uid, Some(ended_ms), false));
        }
        drop(pending);
        self.flush();
    }

    fn flush(&self) {
        let batch = std::mem::take(&mut *lock(&self.pending));
        if !batch.is_empty() {
            self.foreign.flows(batch);
        }
    }

    fn push(&self, record: FlowRecord) {
        lock(&self.pending).push(record);
        self.ready.notify_one();
    }
}

impl Observer for FlowEvents {
    fn flow_started(&self, flow: &FlowInfo) -> Verdict {
        let uid = self.foreign.owner_uid(
            proto(flow.proto),
            flow.src.ip().to_string(),
            flow.src.port(),
            flow.dst.ip().to_string(),
            flow.dst.port(),
        );
        lock(&self.open).insert(flow.id, (flow.clone(), uid));
        self.push(record(flow, uid, None, false));
        Verdict::Allow
    }

    fn hostname_seen(&self, flow: &FlowInfo, hostname: &str) -> Verdict {
        if let Some((open, _)) = lock(&self.open).get_mut(&flow.id) {
            open.hostname = Some(hostname.to_owned());
            open.hostname_source = Some(HostnameSource::Sni);
        }
        Verdict::Allow
    }

    fn flow_ended(&self, flow: &FlowInfo, totals: FlowTotals) {
        let uid = lock(&self.open).remove(&flow.id).map_or(-1, |(_, uid)| uid);
        let mut ended = record(
            flow,
            uid,
            Some(totals.ended_ms),
            totals.verdict == Verdict::Block,
        );
        ended.bytes_up = totals.bytes_up;
        ended.bytes_down = totals.bytes_down;
        self.push(ended);
    }
}

fn record(flow: &FlowInfo, uid: i32, ended_ms: Option<u64>, blocked: bool) -> FlowRecord {
    FlowRecord {
        id: flow.id,
        proto: proto(flow.proto),
        local_ip: flow.src.ip().to_string(),
        local_port: flow.src.port(),
        remote_ip: flow.dst.ip().to_string(),
        remote_port: flow.dst.port(),
        uid,
        hostname: flow.hostname.clone(),
        hostname_source: flow.hostname_source.map(|source| match source {
            HostnameSource::Dns => NameSource::Dns,
            HostnameSource::Sni => NameSource::Sni,
        }),
        started_ms: flow.started_ms,
        ended_ms,
        bytes_up: flow.counters.bytes_up(),
        bytes_down: flow.counters.bytes_down(),
        blocked,
    }
}

fn proto(proto: Proto) -> FlowProto {
    match proto {
        Proto::Tcp => FlowProto::Tcp,
        Proto::Udp => FlowProto::Udp,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

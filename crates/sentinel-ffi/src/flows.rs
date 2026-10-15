// SPDX-License-Identifier: GPL-3.0-or-later
//! Flow events for the app (SRS CM-01, CM-02): which app opened each connection, where
//! to, under which name, and how much it carried.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use sentinel_vpn::{FlowInfo, FlowTotals, HostnameSource, Observer, Proto, Verdict};
use tokio::sync::Notify;

use crate::enrich::IpDatabase;
use crate::history::HistoryStore;

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
    /// Package name of that app, if known.
    pub app: Option<String>,
    pub hostname: Option<String>,
    pub hostname_source: Option<NameSource>,
    /// Unix milliseconds.
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Of the above, the bytes carried while the user was away (CM-06).
    pub bytes_up_away: u64,
    pub bytes_down_away: u64,
    pub blocked: bool,
    /// The network the remote address belongs to (autonomous system number), from the
    /// IP database if one is set (DT-01).
    pub asn: Option<u32>,
    /// That network's registered name.
    pub network_owner: Option<String>,
    /// Approximate country of the remote address, ISO 3166 two letters.
    pub country: Option<String>,
}

/// Who owns a connection.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FlowOwner {
    /// Linux UID, or -1 if unknown.
    pub uid: i32,
    /// Package name (or Android's name for a shared UID), if known.
    pub app: Option<String>,
}

/// One app's open connections right now, for the live view (SRS CM-03).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LiveApp {
    pub uid: i32,
    pub app: Option<String>,
    pub open_flows: u32,
    /// Bytes carried so far by the open flows.
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// The destinations with the most traffic, hostname if known, at most
    /// [`LIVE_DESTINATIONS`].
    pub top_destinations: Vec<String>,
}

/// Destinations listed per app in the live view.
pub const LIVE_DESTINATIONS: usize = 5;

/// Implemented by the app.
#[uniffi::export(with_foreign)]
pub trait FlowObserver: Send + Sync {
    /// The app that owns a new connection: on Android,
    /// `ConnectivityManager.getConnectionOwnerUid` and the package for that UID. Called
    /// once per flow on an engine thread, before the upstream connection exists, so it
    /// must be quick.
    fn owner(
        &self,
        proto: FlowProto,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
    ) -> FlowOwner;

    /// New and finished flows, oldest first, in batches.
    fn flows(&self, records: Vec<FlowRecord>);
}

/// Bridges the engine's [`Observer`] to a [`FlowObserver`] and the history, batching
/// events.
pub(crate) struct FlowEvents {
    foreign: Arc<dyn FlowObserver>,
    history: Option<Arc<HistoryStore>>,
    /// This engine run, to tell its flow ids from earlier runs' in the history.
    session: u64,
    /// Flows that have started and not ended, with their owner.
    open: Mutex<HashMap<u64, (FlowInfo, FlowOwner)>>,
    pending: Mutex<Vec<FlowRecord>>,
    ip_database: RwLock<Option<Arc<IpDatabase>>>,
    ready: Notify,
    history_failures: AtomicU64,
}

impl FlowEvents {
    pub(crate) fn new(
        foreign: Arc<dyn FlowObserver>,
        history: Option<Arc<HistoryStore>>,
        session: u64,
    ) -> Self {
        FlowEvents {
            foreign,
            history,
            session,
            open: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            ip_database: RwLock::new(None),
            ready: Notify::new(),
            history_failures: AtomicU64::new(0),
        }
    }

    /// Replace the IP database used for flows from now on (DT-01).
    pub(crate) fn set_ip_database(&self, database: Option<Arc<IpDatabase>>) {
        *self
            .ip_database
            .write()
            .unwrap_or_else(PoisonError::into_inner) = database;
    }

    fn ip_database(&self) -> Option<Arc<IpDatabase>> {
        self.ip_database
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Batches that could not be written to the history.
    pub(crate) fn history_failures(&self) -> u64 {
        self.history_failures.load(Ordering::Relaxed)
    }

    /// Delivers batches for as long as it is polled. Sleeps without a timer while there
    /// is nothing to send, so an idle engine does not wake up for it.
    pub(crate) async fn deliver(&self) {
        loop {
            self.ready.notified().await;
            tokio::time::sleep(BATCH_DELAY).await;
            // The history write waits on the disk: let other tasks move to another worker.
            tokio::task::block_in_place(|| self.flush());
        }
    }

    /// Ends every flow still open (the engine is stopping), then sends what is left.
    pub(crate) fn close_all(&self, ended_ms: u64) {
        let open: Vec<_> = lock(&self.open).drain().map(|(_, entry)| entry).collect();
        let database = self.ip_database();
        let mut pending = lock(&self.pending);
        for (flow, owner) in open {
            pending.push(record(
                &flow,
                &owner,
                Some(ended_ms),
                false,
                database.as_deref(),
            ));
        }
        drop(pending);
        self.flush();
    }

    fn flush(&self) {
        let batch = std::mem::take(&mut *lock(&self.pending));
        if batch.is_empty() {
            return;
        }
        if let Some(history) = &self.history {
            let events: Vec<_> = batch.iter().map(history_event).collect();
            if let Err(e) = history.store.record_flows(self.session, &events) {
                log::warn!("could not write {} flows to the history: {e}", events.len());
                self.history_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.foreign.flows(batch);
    }

    /// Open flows grouped by app, busiest first: the live view (CM-03). Byte counts
    /// are read from the relays' live counters, so they grow while flows run.
    pub(crate) fn live_apps(&self) -> Vec<LiveApp> {
        let open = lock(&self.open);
        group_live(open.values().map(|(flow, owner)| (flow, owner)))
    }

    fn push(&self, record: FlowRecord) {
        lock(&self.pending).push(record);
        self.ready.notify_one();
    }
}

impl Observer for FlowEvents {
    fn flow_started(&self, flow: &FlowInfo) -> Verdict {
        let owner = self.foreign.owner(
            proto(flow.proto),
            flow.src.ip().to_string(),
            flow.src.port(),
            flow.dst.ip().to_string(),
            flow.dst.port(),
        );
        self.push(record(
            flow,
            &owner,
            None,
            false,
            self.ip_database().as_deref(),
        ));
        lock(&self.open).insert(flow.id, (flow.clone(), owner));
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
        let owner = lock(&self.open)
            .remove(&flow.id)
            .map_or(FlowOwner { uid: -1, app: None }, |(_, owner)| owner);
        let mut ended = record(
            flow,
            &owner,
            Some(totals.ended_ms),
            totals.verdict == Verdict::Block,
            self.ip_database().as_deref(),
        );
        ended.bytes_up = totals.bytes_up;
        ended.bytes_down = totals.bytes_down;
        ended.bytes_up_away = totals.bytes_up_away;
        ended.bytes_down_away = totals.bytes_down_away;
        self.push(ended);
    }
}

fn record(
    flow: &FlowInfo,
    owner: &FlowOwner,
    ended_ms: Option<u64>,
    blocked: bool,
    database: Option<&IpDatabase>,
) -> FlowRecord {
    let ip = database.map(|database| database.db.lookup(flow.dst.ip()));
    FlowRecord {
        id: flow.id,
        proto: proto(flow.proto),
        local_ip: flow.src.ip().to_string(),
        local_port: flow.src.port(),
        remote_ip: flow.dst.ip().to_string(),
        remote_port: flow.dst.port(),
        uid: owner.uid,
        app: owner.app.clone(),
        hostname: flow.hostname.clone(),
        hostname_source: flow.hostname_source.map(|source| match source {
            HostnameSource::Dns => NameSource::Dns,
            HostnameSource::Sni => NameSource::Sni,
        }),
        started_ms: flow.started_ms,
        ended_ms,
        bytes_up: flow.counters.bytes_up(),
        bytes_down: flow.counters.bytes_down(),
        bytes_up_away: flow.counters.bytes_up_away(),
        bytes_down_away: flow.counters.bytes_down_away(),
        blocked,
        asn: ip.and_then(|ip| ip.asn),
        network_owner: ip.and_then(|ip| ip.network_owner).map(str::to_owned),
        country: ip.and_then(|ip| ip.country).map(str::to_owned),
    }
}

/// The history's form of a flow record.
fn history_event(record: &FlowRecord) -> sentinel_store::FlowEvent {
    let signed = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    sentinel_store::FlowEvent {
        engine_id: record.id,
        flow: sentinel_store::FlowRow {
            app: record.app.clone(),
            proto: match record.proto {
                FlowProto::Tcp => sentinel_store::Proto::Tcp,
                FlowProto::Udp => sentinel_store::Proto::Udp,
            },
            local_ip: record.local_ip.clone(),
            local_port: record.local_port,
            remote_ip: record.remote_ip.clone(),
            remote_port: record.remote_port,
            hostname: record.hostname.clone(),
            hostname_src: record.hostname_source.map(|source| match source {
                NameSource::Dns => sentinel_store::HostnameSource::Dns,
                NameSource::Sni => sentinel_store::HostnameSource::Sni,
            }),
            started: signed(record.started_ms),
            ended: record.ended_ms.map(signed),
            bytes_up: signed(record.bytes_up),
            bytes_down: signed(record.bytes_down),
            bytes_up_away: signed(record.bytes_up_away),
            bytes_down_away: signed(record.bytes_down_away),
            blocked: record.blocked,
        },
    }
}

fn proto(proto: Proto) -> FlowProto {
    match proto {
        Proto::Tcp => FlowProto::Tcp,
        Proto::Udp => FlowProto::Udp,
    }
}

/// Group open flows by owner. Apps are ordered by bytes carried, then by open flows,
/// then by name, so the order is stable between refreshes when nothing changes.
fn group_live<'a>(flows: impl Iterator<Item = (&'a FlowInfo, &'a FlowOwner)>) -> Vec<LiveApp> {
    struct Group {
        live: LiveApp,
        destinations: HashMap<String, u64>,
    }
    let mut groups: HashMap<(i32, Option<String>), Group> = HashMap::new();
    for (flow, owner) in flows {
        let up = flow.counters.bytes_up();
        let down = flow.counters.bytes_down();
        let group = groups
            .entry((owner.uid, owner.app.clone()))
            .or_insert_with(|| Group {
                live: LiveApp {
                    uid: owner.uid,
                    app: owner.app.clone(),
                    open_flows: 0,
                    bytes_up: 0,
                    bytes_down: 0,
                    top_destinations: Vec::new(),
                },
                destinations: HashMap::new(),
            });
        group.live.open_flows += 1;
        group.live.bytes_up += up;
        group.live.bytes_down += down;
        let destination = flow
            .hostname
            .clone()
            .unwrap_or_else(|| flow.dst.ip().to_string());
        *group.destinations.entry(destination).or_default() += up + down;
    }
    let mut apps: Vec<LiveApp> = groups
        .into_values()
        .map(|mut group| {
            let mut destinations: Vec<_> = group.destinations.into_iter().collect();
            destinations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            group.live.top_destinations = destinations
                .into_iter()
                .take(LIVE_DESTINATIONS)
                .map(|(name, _)| name)
                .collect();
            group.live
        })
        .collect();
    apps.sort_by(|a, b| {
        (b.bytes_up + b.bytes_down)
            .cmp(&(a.bytes_up + a.bytes_down))
            .then_with(|| b.open_flows.cmp(&a.open_flows))
            .then_with(|| a.app.cmp(&b.app))
            .then_with(|| a.uid.cmp(&b.uid))
    });
    apps
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_vpn::FlowCounters;

    fn flow(id: u64, dst: &str, hostname: Option<&str>) -> FlowInfo {
        FlowInfo {
            id,
            proto: Proto::Tcp,
            src: "10.215.173.1:40000".parse().unwrap(),
            dst: dst.parse().unwrap(),
            hostname: hostname.map(str::to_owned),
            hostname_source: hostname.map(|_| HostnameSource::Dns),
            started_ms: 0,
            counters: Arc::new(FlowCounters::default()),
        }
    }

    fn owner(uid: i32, app: &str) -> FlowOwner {
        FlowOwner {
            uid,
            app: Some(app.to_owned()),
        }
    }

    #[test]
    fn groups_open_flows_by_app_busiest_first() {
        let video = owner(10_001, "org.example.video");
        let chat = owner(10_002, "org.example.chat");
        let flows = [
            (
                flow(1, "203.0.113.5:443", Some("cdn.example")),
                video.clone(),
                900,
                9_000,
            ),
            (
                flow(2, "203.0.113.6:443", Some("api.example")),
                video.clone(),
                100,
                100,
            ),
            (
                flow(3, "203.0.113.5:443", Some("cdn.example")),
                video.clone(),
                0,
                1_000,
            ),
            (flow(4, "198.51.100.7:5222", None), chat.clone(), 10, 20),
        ];
        for (f, _, up, down) in &flows {
            f.counters.add_up(*up);
            f.counters.add_down(*down);
        }
        let apps = group_live(flows.iter().map(|(f, o, _, _)| (f, o)));
        assert_eq!(apps.len(), 2);
        let first = &apps[0];
        assert_eq!(first.app.as_deref(), Some("org.example.video"));
        assert_eq!(first.open_flows, 3);
        assert_eq!((first.bytes_up, first.bytes_down), (1_000, 10_100));
        assert_eq!(first.top_destinations, vec!["cdn.example", "api.example"]);
        let second = &apps[1];
        assert_eq!((second.uid, second.open_flows), (10_002, 1));
        assert_eq!(
            second.top_destinations,
            vec!["198.51.100.7"],
            "address when no name"
        );
    }

    #[test]
    fn lists_at_most_five_destinations() {
        let app = owner(10_003, "org.example.browser");
        let flows: Vec<_> = (0..8u64)
            .map(|i| {
                let f = flow(i, &format!("192.0.2.{}:443", i + 1), None);
                f.counters.add_down(usize::try_from(i).unwrap() * 10);
                f
            })
            .collect();
        let apps = group_live(flows.iter().map(|f| (f, &app)));
        assert_eq!(apps[0].open_flows, 8);
        assert_eq!(
            apps[0].top_destinations,
            vec![
                "192.0.2.8",
                "192.0.2.7",
                "192.0.2.6",
                "192.0.2.5",
                "192.0.2.4"
            ]
        );
    }
}

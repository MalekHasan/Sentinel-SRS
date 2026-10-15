// SPDX-License-Identifier: GPL-3.0-or-later
//! Flow events for the app (SRS CM-01, CM-02): which app opened each connection, where
//! to, under which name, and how much it carried.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use sentinel_vpn::{FlowInfo, FlowTotals, HostnameSource, Observer, Proto, Verdict};
use tokio::sync::Notify;

use sentinel_store::FirstSeen;

use crate::enrich::{CategoryFact, CompanyFact, IpDatabase, TrackerDatabase};
use crate::history::{HistoryStore, now_ms};

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
    /// The company the hostname belongs to, from the tracker list if one is set (DT-06).
    pub company: Option<CompanyFact>,
    /// What kind of service the hostname is, from the tracker list.
    pub categories: Option<CategoryFact>,
}

/// Who owns a connection.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FlowOwner {
    /// Linux UID, or -1 if unknown.
    pub uid: i32,
    /// Package name (or Android's name for a shared UID), if known.
    pub app: Option<String>,
    /// When the app was first installed, Unix milliseconds, if known: on Android,
    /// `PackageInfo.firstInstallTime`. An app installed since the history began is new
    /// to the network when the history first sees it (CM-04).
    #[uniffi(default = None)]
    pub installed_ms: Option<i64>,
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
    /// When each app seen in this run was installed, where known (CM-04).
    installed: Mutex<HashMap<String, i64>>,
    pending: Mutex<Vec<FlowRecord>>,
    databases: RwLock<Databases>,
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
            installed: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            databases: RwLock::new(Databases::default()),
            ready: Notify::new(),
            history_failures: AtomicU64::new(0),
        }
    }

    /// Replace the IP database used for flows from now on (DT-01).
    pub(crate) fn set_ip_database(&self, database: Option<Arc<IpDatabase>>) {
        self.databases
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .ip = database;
    }

    /// Replace the tracker list used for flows from now on (DT-06).
    pub(crate) fn set_tracker_database(&self, database: Option<Arc<TrackerDatabase>>) {
        self.databases
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .trackers = database;
    }

    fn databases(&self) -> Databases {
        self.databases
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
        let databases = self.databases();
        let mut pending = lock(&self.pending);
        for (flow, owner) in open {
            pending.push(record(&flow, &owner, Some(ended_ms), false, &databases));
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
            let sources = self
                .databases()
                .ip
                .map(|database| database.db.sources().clone());
            let events: Vec<_> = batch
                .iter()
                .map(|record| history_event(record, sources.as_ref()))
                .collect();
            match history.store.record_flows(self.session, &events) {
                Ok(first_seen) => self.raise_first_seen(history, &first_seen),
                Err(e) => {
                    log::warn!("could not write {} flows to the history: {e}", events.len());
                    self.history_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.foreign.flows(batch);
    }

    /// Alerts for what the flows showed for the first time (CM-04): an app new to the
    /// network, and the names each app connected to for the first time, together.
    fn raise_first_seen(&self, history: &HistoryStore, first_seen: &[FirstSeen]) {
        let now = now_ms();
        let mut alerts = Vec::new();
        let mut destinations: Vec<(&str, i64, Vec<String>)> = Vec::new();
        for seen in first_seen {
            match seen {
                FirstSeen::App { app, destination } => {
                    let installed = lock(&self.installed).get(app).copied();
                    alerts.extend(sentinel_detect::first_network_use(
                        now,
                        app,
                        installed,
                        history.store.began(),
                        destination,
                    ));
                }
                FirstSeen::Destination {
                    app,
                    app_first_seen,
                    destination,
                } => match destinations.iter_mut().find(|(a, ..)| a == app) {
                    Some((.., names)) => names.push(destination.clone()),
                    None => destinations.push((app, *app_first_seen, vec![destination.clone()])),
                },
            }
        }
        let join_since = now.saturating_sub(sentinel_detect::GROUP_WINDOW_MS);
        let new_places = destinations.iter().filter_map(|(app, first_seen, names)| {
            sentinel_detect::new_destinations(now, app, *first_seen, names)
        });
        let results = alerts
            .iter()
            .map(|alert| history.raise(alert))
            .chain(new_places.map(|alert| history.raise_or_join(&alert, Some(join_since))));
        for result in results {
            if let Err(e) = result {
                log::warn!("could not raise an alert: {e}");
            }
        }
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
        if let (Some(app), Some(installed)) = (&owner.app, owner.installed_ms) {
            lock(&self.installed).insert(app.clone(), installed);
        }
        self.push(record(flow, &owner, None, false, &self.databases()));
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
        let owner = lock(&self.open).remove(&flow.id).map_or(
            FlowOwner {
                uid: -1,
                app: None,
                installed_ms: None,
            },
            |(_, owner)| owner,
        );
        let mut ended = record(
            flow,
            &owner,
            Some(totals.ended_ms),
            totals.verdict == Verdict::Block,
            &self.databases(),
        );
        ended.bytes_up = totals.bytes_up;
        ended.bytes_down = totals.bytes_down;
        ended.bytes_up_away = totals.bytes_up_away;
        ended.bytes_down_away = totals.bytes_down_away;
        self.push(ended);
    }
}

/// The offline data the flows are enriched from.
#[derive(Clone, Default)]
struct Databases {
    ip: Option<Arc<IpDatabase>>,
    trackers: Option<Arc<TrackerDatabase>>,
}

fn record(
    flow: &FlowInfo,
    owner: &FlowOwner,
    ended_ms: Option<u64>,
    blocked: bool,
    databases: &Databases,
) -> FlowRecord {
    let ip = databases.ip.as_ref().map(|db| db.db.lookup(flow.dst.ip()));
    let (company, categories) = match (&databases.trackers, &flow.hostname) {
        (Some(trackers), Some(hostname)) => trackers.lookup(hostname),
        _ => (None, None),
    };
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
        company,
        categories,
    }
}

/// The history's form of a flow record.
fn history_event(
    record: &FlowRecord,
    sources: Option<&sentinel_enrich::Sources>,
) -> sentinel_store::FlowEvent {
    let signed = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
    // What the IP database and the tracker list said about the destination, with where
    // each answer comes from (DT-02).
    let mut facts = sentinel_store::DestinationFacts {
        company: record.company.as_ref().map(Into::into),
        categories: record.categories.as_ref().map(Into::into),
        ..Default::default()
    };
    if let Some(sources) = sources {
        facts.asn = record.asn;
        facts.network_owner = record.network_owner.clone();
        facts.network_source = record.asn.map(|_| sources.network.clone());
        facts.country = record.country.clone();
        facts.country_source = record.country.as_ref().map(|_| sources.country.clone());
    }
    let destination = (facts != sentinel_store::DestinationFacts::default()).then_some(facts);
    sentinel_store::FlowEvent {
        engine_id: record.id,
        destination,
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
    use crate::history::HistoryCompany;
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
            installed_ms: None,
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

    /// Records what the app would be told.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<FlowRecord>>);

    impl FlowObserver for Recorder {
        fn owner(&self, _: FlowProto, _: String, _: u16, _: String, _: u16) -> FlowOwner {
            owner(10_001, "org.example.chat")
        }

        fn flows(&self, records: Vec<FlowRecord>) {
            self.0.lock().unwrap().extend(records);
        }
    }

    /// With a tracker list set, a flow with a hostname carries its company and
    /// categories, each with where it comes from, and the history keeps them (DT-02,
    /// DT-06). A flow without a name, or with a name no list covers, carries none.
    #[test]
    fn enriches_named_flows_from_the_tracker_list() {
        let mut builder = sentinel_enrich::TrackerDbBuilder::new();
        let radar = builder.add_source("Tracker Radar test").unwrap();
        let apps = builder.add_source("App list test").unwrap();
        builder
            .add_domain(radar, "ads.example", Some("Example Ads"), &["Advertising"])
            .unwrap();
        builder
            .add_domain(apps, "g.ads.example", Some("Example Ads"), &[])
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trackers.db");
        std::fs::write(&path, builder.build().unwrap()).unwrap();
        let trackers = TrackerDatabase::open(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(trackers.sources(), ["Tracker Radar test", "App list test"]);
        let history_path = dir.path().join("history.db");
        let history =
            HistoryStore::open(history_path.to_string_lossy().into_owned(), vec![5; 32]).unwrap();

        let recorder = Arc::new(Recorder::default());
        let events = FlowEvents::new(recorder.clone(), Some(Arc::clone(&history)), 1);
        let early = flow(1, "203.0.113.5:443", Some("x.g.ads.example"));
        events.flow_started(&early);
        events.set_tracker_database(Some(trackers));
        let named = flow(2, "203.0.113.5:443", Some("x.g.ads.example"));
        let bare = flow(3, "203.0.113.6:443", None);
        let unlisted = flow(4, "203.0.113.7:443", Some("plain.example"));
        for flow in [&named, &bare, &unlisted] {
            events.flow_started(flow);
        }
        events.close_all(1_000);

        let company = CompanyFact {
            company: "Example Ads".into(),
            listed_domain: "g.ads.example".into(),
            sources: vec!["App list test".into()],
        };
        let categories = CategoryFact {
            categories: vec!["Advertising".into()],
            listed_domain: "ads.example".into(),
            sources: vec!["Tracker Radar test".into()],
        };
        let records = recorder.0.lock().unwrap().clone();
        let started = |id: u64| {
            records
                .iter()
                .find(|r| r.id == id && r.ended_ms.is_none())
                .unwrap()
                .clone()
        };
        assert_eq!(started(1).company, None, "no tracker list yet");
        assert_eq!(started(2).company.as_ref(), Some(&company));
        assert_eq!(started(2).categories.as_ref(), Some(&categories));
        for id in [3, 4] {
            assert_eq!((started(id).company, started(id).categories), (None, None));
        }
        // A flow that ends after the list was set carries it, even if it started before.
        let early_end = records
            .iter()
            .find(|r| r.id == 1 && r.ended_ms.is_some())
            .unwrap();
        assert_eq!(early_end.company.as_ref(), Some(&company));

        let app = history
            .app_summary("org.example.chat".into(), 10)
            .unwrap()
            .unwrap();
        let stored = app
            .destinations
            .iter()
            .find(|d| d.destination == "x.g.ads.example")
            .unwrap();
        assert_eq!(stored.company.as_ref(), Some(&company));
        assert_eq!(stored.categories.as_ref(), Some(&categories));
        assert_eq!(stored.asn, None, "no IP database");
        assert_eq!(
            app.companies,
            [HistoryCompany {
                company: "Example Ads".into(),
                categories: vec!["Advertising".into()],
                destinations: 1,
                bytes_up: 0,
                bytes_down: 0,
            }]
        );
    }

    /// Owns each flow by its remote port, as the app would say.
    struct PortOwners {
        owners: HashMap<u16, FlowOwner>,
        heard: Mutex<Vec<crate::alerts::HistoryAlert>>,
    }

    impl FlowObserver for PortOwners {
        fn owner(&self, _: FlowProto, _: String, _: u16, _: String, port: u16) -> FlowOwner {
            self.owners[&port].clone()
        }

        fn flows(&self, _: Vec<FlowRecord>) {}
    }

    impl crate::alerts::AlertListener for PortOwners {
        fn raised(&self, alert: crate::alerts::HistoryAlert) {
            self.heard.lock().unwrap().push(alert);
        }
    }

    fn history() -> (tempfile::TempDir, Arc<HistoryStore>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![7; 32]).unwrap();
        (dir, history)
    }

    fn installed(app: &str, installed_ms: Option<i64>) -> FlowOwner {
        FlowOwner {
            uid: 10_100,
            app: Some(app.to_owned()),
            installed_ms,
        }
    }

    fn listen(history: &Arc<HistoryStore>, owners: Vec<(u16, FlowOwner)>) -> Arc<PortOwners> {
        let observer = Arc::new(PortOwners {
            owners: owners.into_iter().collect(),
            heard: Mutex::new(Vec::new()),
        });
        history.set_alert_listener(Some(observer.clone()));
        observer
    }

    /// CM-04: an app installed since the history began raises one alert on its first
    /// connection, naming where it went. Apps installed before, or at an unknown time
    /// (Android's shared system identities), raise none.
    #[test]
    fn only_apps_installed_since_the_history_began_are_new() {
        use crate::alerts::{AlertAction, AlertEvidence, AlertRule, AlertSeverity};

        let (_dir, history) = history();
        let began = history.began_ms();
        let observer = listen(
            &history,
            vec![
                (1, installed("org.example.new", Some(began + 5))),
                (2, installed("org.example.old", Some(began - 1))),
                (3, installed("android.uid.system:1000", None)),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let now = u64::try_from(now_ms()).unwrap();
        let started = |id: u64, port: u16, name: Option<&str>| {
            let mut flow = flow(id, &format!("203.0.113.5:{port}"), name);
            flow.started_ms = now;
            events.flow_started(&flow);
        };
        started(1, 1, Some("api.new.example"));
        started(2, 1, Some("cdn.new.example"));
        started(3, 2, Some("api.old.example"));
        started(4, 3, None);
        events.close_all(now + 10);

        let heard = observer.heard.lock().unwrap().clone();
        assert_eq!(heard.len(), 1, "{heard:?}");
        let alert = &heard[0];
        assert_eq!(alert.rule, AlertRule::FirstNetworkUse);
        assert_eq!(alert.severity, AlertSeverity::Info);
        assert_eq!(
            alert.evidence,
            [
                AlertEvidence::App {
                    app: "org.example.new".into()
                },
                AlertEvidence::Destinations {
                    destinations: vec!["api.new.example".into()],
                    more: 0
                },
            ]
        );
        assert_eq!(
            alert.actions,
            [AlertAction::OpenApp {
                app: "org.example.new".into()
            }]
        );
        // The history knows the apps now: their next connections are not new.
        started(5, 1, Some("api.new.example"));
        events.close_all(now + 20);
        assert_eq!(observer.heard.lock().unwrap().len(), 1);
    }

    /// CM-04: once the history has learned an app for a week, the names it connects to
    /// for the first time raise one alert, which later new names of the same day join.
    /// Names already used, and new apps' names, raise nothing; after the alert is
    /// dismissed the next new name raises another, and allowing the rule for the app
    /// stops them.
    #[test]
    fn new_names_after_the_learning_period_share_an_alert() {
        use crate::alerts::{AlertEvidence, AlertFeedback, AlertRule};

        let (_dir, history) = history();
        let observer = listen(
            &history,
            vec![
                (1, installed("org.example.chat", None)),
                (2, installed("org.example.fresh", None)),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let now = u64::try_from(now_ms()).unwrap();
        let week = u64::try_from(sentinel_detect::LEARNING_MS).unwrap();
        let mut next_id = 0;
        let mut connect = |port: u16, name: Option<&str>, at: u64| {
            next_id += 1;
            let mut flow = flow(next_id, &format!("203.0.113.5:{port}"), name);
            flow.started_ms = at;
            events.flow_started(&flow);
            events.close_all(at + 1);
        };
        // First seen more than a week ago, by address only.
        connect(1, None, now - week - 60_000);
        connect(1, Some("a.example"), now);
        connect(1, Some("b.example"), now);
        connect(1, Some("a.example"), now);
        // A new app's names are all new: still learning.
        connect(2, Some("x.example"), now);

        let heard = observer.heard.lock().unwrap().clone();
        assert_eq!(heard.len(), 1, "told once: {heard:?}");
        assert_eq!(heard[0].rule, AlertRule::NewDestination);
        let open = history.alerts(true, 10).unwrap();
        assert_eq!(open.len(), 1, "{open:?}");
        assert_eq!(
            open[0].evidence[1],
            AlertEvidence::Destinations {
                destinations: vec!["a.example".into(), "b.example".into()],
                more: 0
            }
        );

        history.dismiss_alert(open[0].id).unwrap();
        connect(1, Some("c.example"), now);
        let open = history.alerts(true, 10).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(
            open[0].evidence[1],
            AlertEvidence::Destinations {
                destinations: vec!["c.example".into()],
                more: 0
            }
        );
        history
            .set_feedback(open[0].id, Some(AlertFeedback::Allowed))
            .unwrap();
        connect(1, Some("d.example"), now);
        assert!(history.alerts(true, 10).unwrap().is_empty(), "allowed");
        assert_eq!(observer.heard.lock().unwrap().len(), 2);
    }
}

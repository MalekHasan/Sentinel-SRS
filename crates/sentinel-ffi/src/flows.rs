// SPDX-License-Identifier: GPL-3.0-or-later
//! Flow events for the app (SRS CM-01, CM-02): which app opened each connection, where
//! to, under which name, and how much it carried.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use std::net::IpAddr;

use sentinel_vpn::{FlowInfo, FlowTotals, HostnameSource, Observer, Proto, Verdict};
use tokio::sync::Notify;

use sentinel_detect::{Place, Sighting};
use sentinel_ioc::Hit;
use sentinel_store::FirstSeen;

use crate::enrich::{CategoryFact, CompanyFact, IpDatabase, TrackerDatabase};
use crate::feed::Feed;
use crate::history::{HistoryStore, now_ms};
use crate::hunt::indicator_match;

/// How long events wait so that several can cross into Kotlin together. Short enough
/// that every flow appears within a second (CM-01).
const BATCH_DELAY: Duration = Duration::from_millis(250);

/// How often the history is asked which apps sent far more than usual (DL-02).
const UPLOAD_CHECK: Duration = Duration::from_secs(15 * 60);

/// The most flows one app may have open at once (THREAT-MODEL-A D2, ADR-0028): half the
/// engine's own limit, so that one app cannot take every connection it allows, and above
/// the 500 one app opens in the CM-03 acceptance test.
pub(crate) const MAX_FLOWS_PER_APP: u32 = 512;

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
    /// Whether the app is part of the system: on Android, `ApplicationInfo.FLAG_SYSTEM`
    /// or a system UID. Its check-ins are not flagged (DL-04).
    #[uniffi(default = false)]
    pub system: bool,
}

impl FlowOwner {
    /// A connection Android could not name an owner for.
    fn unknown() -> FlowOwner {
        FlowOwner {
            uid: -1,
            app: None,
            installed_ms: None,
            system: false,
        }
    }
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
    /// The feed whose indicators the traffic is matched against (ID-13).
    feed: RwLock<Option<Arc<Feed>>>,
    /// Known-indicator alerts waiting for the next batch.
    sightings: Mutex<Vec<sentinel_detect::Alert>>,
    /// Each app and indicator already sighted in this run, `None` for an app not known:
    /// an app that keeps using a known server raises one alert, not one per lookup.
    sighted: Mutex<HashSet<(Option<String>, String)>>,
    /// How many flows each app has open (THREAT-MODEL-A D2).
    open_per_app: Mutex<HashMap<String, u32>>,
    /// Flows refused because their app had [`MAX_FLOWS_PER_APP`] open: neither their
    /// start nor their end is recorded.
    refused: Mutex<HashSet<u64>>,
    /// The apps that reached [`MAX_FLOWS_PER_APP`] in this run, alerted once each.
    limited: Mutex<HashSet<String>>,
    /// Each app's connections to each place, for check-ins at a fixed interval (DL-04).
    beacons: Mutex<sentinel_detect::Beacons>,
    /// Each app's lookups, for data hidden in DNS (DL-05).
    dns_watch: Mutex<sentinel_detect::DnsWatch>,
    /// The apps seen reaching an encrypted DNS service themselves in this run (DL-05).
    own_dns: Mutex<HashSet<String>>,
    /// When the history was last asked about upload surges, Unix ms (DL-02).
    uploads_checked: Mutex<i64>,
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
            feed: RwLock::new(None),
            sightings: Mutex::new(Vec::new()),
            sighted: Mutex::new(HashSet::new()),
            open_per_app: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashSet::new()),
            limited: Mutex::new(HashSet::new()),
            beacons: Mutex::new(sentinel_detect::Beacons::new()),
            dns_watch: Mutex::new(sentinel_detect::DnsWatch::new()),
            own_dns: Mutex::new(HashSet::new()),
            uploads_checked: Mutex::new(i64::MIN),
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

    /// Match lookups and connections from now on against the indicators `feed` has in
    /// force, whichever bundle that is at the time (ID-13); or against none.
    pub(crate) fn set_feed(&self, feed: Option<Arc<Feed>>) {
        *self.feed.write().unwrap_or_else(PoisonError::into_inner) = feed;
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
        let sightings = std::mem::take(&mut *lock(&self.sightings));
        if !batch.is_empty() {
            self.record_flows(&batch);
        }
        if let Some(history) = &self.history {
            for alert in &sightings {
                // One open alert per app and indicator, or per app at its flow limit.
                let same =
                    |new: &sentinel_detect::Alert, open: &sentinel_detect::Alert| match new.rule {
                        sentinel_detect::Rule::KnownIndicator => {
                            sentinel_detect::same_sighting(new, open)
                        }
                        _ => new.rule == open.rule && new.app() == open.app(),
                    };
                if let Err(e) = history.raise_unless_open(alert, same) {
                    log::warn!("could not raise an alert: {e}");
                }
            }
            self.check_uploads(history);
        }
        if !batch.is_empty() {
            self.foreign.flows(batch);
        }
    }

    /// DL-02: asks the history which apps sent far more than usual, at most every
    /// [`UPLOAD_CHECK`]. The first batch of a run asks at once.
    fn check_uploads(&self, history: &HistoryStore) {
        let now = now_ms();
        let interval = i64::try_from(UPLOAD_CHECK.as_millis()).unwrap_or(i64::MAX);
        {
            let mut checked = lock(&self.uploads_checked);
            if now.saturating_sub(*checked) < interval {
                return;
            }
            *checked = now;
        }
        if let Err(e) = history.raise_upload_surges(now) {
            log::warn!("could not check uploads: {e}");
        }
    }

    /// Keep `batch` in the history, and raise alerts for what it showed for the first
    /// time.
    fn record_flows(&self, batch: &[FlowRecord]) {
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
    }

    /// Alerts for what the flows showed for the first time (CM-04): an app new to the
    /// network, and the names each app connected to for the first time, together.
    fn raise_first_seen(&self, history: &HistoryStore, first_seen: &[FirstSeen]) {
        let now = now_ms();
        let mut alerts = Vec::new();
        let mut destinations: Vec<(&str, i64, Vec<String>)> = Vec::new();
        for seen in first_seen {
            match seen {
                FirstSeen::App {
                    app,
                    destination,
                    blocked,
                } => {
                    let installed = lock(&self.installed).get(app).copied();
                    // Said only when the app was blocked for being new, which allowing
                    // it undoes, not when a rule about a destination stopped it.
                    let blocked_as_new = *blocked
                        && history.rule_set().blocks_new_app(
                            history.mode_in_force(),
                            app,
                            installed,
                        );
                    alerts.extend(sentinel_detect::first_network_use(
                        now,
                        app,
                        installed,
                        history.store.began(),
                        destination,
                        blocked_as_new,
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

    /// Whether `name`, looked up or named as a TLS server, is a known indicator or
    /// below one (ID-13).
    fn match_name(&self, owner: &FlowOwner, name: &str, sighting: Sighting) {
        if let Some(matcher) = self.matcher()
            && let Some(hit) = matcher.name(name)
        {
            self.sighted(owner, hit, name, sighting);
        }
    }

    /// Whether `address`, connected to, is a known indicator (ID-13).
    fn match_address(&self, owner: &FlowOwner, address: IpAddr) {
        if let Some(matcher) = self.matcher()
            && let Some(hit) = matcher.address(address)
        {
            self.sighted(owner, hit, &address.to_string(), Sighting::Address);
        }
    }

    /// Whether `flow` may open: its app has fewer than [`MAX_FLOWS_PER_APP`] open
    /// (THREAT-MODEL-A D2, ADR-0028). A refused flow is not recorded, so that an app
    /// flooding the network cannot flood the history too; the first refusal in a run
    /// raises a Warning about the app. Flows of no known app count only towards the
    /// engine's own limit.
    fn admit(&self, flow: &FlowInfo, owner: &FlowOwner) -> bool {
        let Some(app) = &owner.app else {
            return true;
        };
        let mut open = lock(&self.open_per_app);
        let count = open.entry(app.clone()).or_default();
        if *count < MAX_FLOWS_PER_APP {
            *count += 1;
            return true;
        }
        drop(open);
        lock(&self.refused).insert(flow.id);
        if self.history.is_some() && lock(&self.limited).insert(app.clone()) {
            let alert = sentinel_detect::flow_limit(now_ms(), app, MAX_FLOWS_PER_APP);
            lock(&self.sightings).push(alert);
            self.ready.notify_one();
        }
        false
    }

    /// DL-04: an app's check-ins with one place at a fixed interval, with little data
    /// each time, raise an Info alert, once per app and place in a run. Not for system
    /// apps, nor for DNS (DL-05), nor for blocked connections, which carried nothing.
    fn watch_check_ins(&self, flow: &FlowInfo, owner: &FlowOwner, totals: &FlowTotals) {
        let Some(app) = self.watched(owner) else {
            return;
        };
        if totals.verdict == Verdict::Block || flow.dst.port() == 53 {
            return;
        }
        let destination = flow
            .hostname
            .clone()
            .unwrap_or_else(|| flow.dst.ip().to_string());
        let started = i64::try_from(flow.started_ms).unwrap_or(i64::MAX);
        let bytes = totals.bytes_up.saturating_add(totals.bytes_down);
        let found = lock(&self.beacons).connection(app, &destination, started, bytes);
        if let Some(beacon) = found {
            lock(&self.sightings).push(sentinel_detect::beacon_like(now_ms(), app, beacon));
            self.ready.notify_one();
        }
    }

    /// The app the unusual-DNS and beacon rules watch: one known, not part of the
    /// system, while alerts can be raised.
    fn watched<'a>(&self, owner: &'a FlowOwner) -> Option<&'a str> {
        let app = owner.app.as_deref()?;
        (!owner.system && self.history.is_some()).then_some(app)
    }

    /// DL-05: lookups that look like data hidden in DNS raise a Warning, once per app
    /// and domain (or app, for TXT lookups) in a run.
    fn watch_lookup(&self, owner: &FlowOwner, qname: &str, qtype: u16) {
        let Some(app) = self.watched(owner) else {
            return;
        };
        let now = now_ms();
        let found = lock(&self.dns_watch).lookup(now, app, qname, qtype);
        if let Some(tunnel) = found {
            lock(&self.sightings).push(sentinel_detect::dns_tunnel(now, app, tunnel));
            self.ready.notify_one();
        }
    }

    /// DL-05: an app that reaches an encrypted DNS service itself raises an Info alert,
    /// once per app in a run. `server_name` is the name it used, if known.
    fn watch_encrypted_dns(&self, owner: &FlowOwner, flow: &FlowInfo, server_name: Option<&str>) {
        let Some(app) = self.watched(owner) else {
            return;
        };
        let Some(server) =
            sentinel_detect::encrypted_dns(flow.dst.ip(), flow.dst.port(), server_name)
        else {
            return;
        };
        if lock(&self.own_dns).insert(app.to_owned()) {
            let alert = sentinel_detect::own_encrypted_dns(now_ms(), app, &server);
            lock(&self.sightings).push(alert);
            self.ready.notify_one();
        }
    }

    /// The indicators in force, if alerts can be raised at all.
    fn matcher(&self) -> Option<Arc<sentinel_ioc::Matcher>> {
        self.history.as_ref()?;
        self.feed
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()?
            .matcher()
    }

    /// The owner's traffic showed `hit`: the first time in this run for this app and
    /// indicator, an alert goes out with the next batch. Nothing is blocked (SRS §9).
    fn sighted(&self, owner: &FlowOwner, hit: &Hit, seen: &str, sighting: Sighting) {
        if !lock(&self.sighted).insert((owner.app.clone(), hit.indicator.value.clone())) {
            return;
        }
        let matched = indicator_match(hit, seen, sighting);
        let alert = sentinel_detect::known_indicator(now_ms(), owner.app.as_deref(), matched);
        lock(&self.sightings).push(alert);
        self.ready.notify_one();
    }

    /// What the firewall says about a connection or lookup on `port`: isolation first,
    /// then its rules, then its mode (RA-03, CM-10, CM-08; ADR-0017, ADR-0015,
    /// ADR-0016). A name's company comes from the tracker list, if one is set. Without a
    /// history there are no rules, no mode and no isolation, and everything is allowed.
    fn verdict(
        &self,
        owner: &FlowOwner,
        address: Option<IpAddr>,
        port: u16,
        name: Option<&str>,
    ) -> Verdict {
        let Some(history) = &self.history else {
            return Verdict::Allow;
        };
        if let Some(isolation) = history.isolation_in_force()
            && !history
                .rule_set()
                .isolation_lets_through(&isolation, owner.app.as_deref(), port)
        {
            return Verdict::Block;
        }
        let company = match (name, &self.databases().trackers) {
            (Some(name), Some(trackers)) => trackers.company(name),
            _ => None,
        };
        let place = Place {
            address,
            name,
            company: company.as_deref(),
        };
        let decision = history.rule_set().verdict(
            history.mode_in_force(),
            owner.app.as_deref(),
            owner.installed_ms,
            place,
        );
        match decision {
            sentinel_detect::RuleAction::Block => Verdict::Block,
            sentinel_detect::RuleAction::Allow => Verdict::Allow,
        }
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
        // The app and the address are known for sure; a name from an earlier DNS answer
        // is not, so it is not matched (ADR-0015).
        self.match_address(&owner, flow.dst.ip());
        if !self.admit(flow, &owner) {
            return Verdict::Block;
        }
        let verdict = self.verdict(&owner, Some(flow.dst.ip()), flow.dst.port(), None);
        let blocked = verdict == Verdict::Block;
        if !blocked {
            self.watch_encrypted_dns(&owner, flow, flow.hostname.as_deref());
        }
        self.push(record(flow, &owner, None, blocked, &self.databases()));
        lock(&self.open).insert(flow.id, (flow.clone(), owner));
        verdict
    }

    fn hostname_seen(&self, flow: &FlowInfo, hostname: &str) -> Verdict {
        let owner = match lock(&self.open).get_mut(&flow.id) {
            Some((open, owner)) => {
                open.hostname = Some(hostname.to_owned());
                open.hostname_source = Some(HostnameSource::Sni);
                owner.clone()
            }
            None => FlowOwner::unknown(),
        };
        self.match_name(&owner, hostname, Sighting::ServerName);
        let verdict = self.verdict(&owner, Some(flow.dst.ip()), flow.dst.port(), Some(hostname));
        if verdict == Verdict::Allow {
            self.watch_encrypted_dns(&owner, flow, Some(hostname));
        }
        verdict
    }

    fn dns_query(&self, flow: &FlowInfo, qname: &str, qtype: u16) -> Verdict {
        let owner = lock(&self.open)
            .get(&flow.id)
            .map_or_else(FlowOwner::unknown, |(_, owner)| owner.clone());
        // The address is the resolver's, not the destination's: only names count here.
        self.match_name(&owner, qname, Sighting::DnsQuery);
        let verdict = self.verdict(&owner, None, flow.dst.port(), Some(qname));
        if verdict == Verdict::Allow {
            self.watch_lookup(&owner, qname, qtype);
        }
        verdict
    }

    fn recheck(&self, flow: &FlowInfo) -> Verdict {
        let Some((open, owner)) = lock(&self.open).get(&flow.id).cloned() else {
            return Verdict::Allow;
        };
        // As when it was first decided: its app, its address, and a TLS server name if
        // one was seen. A name from an earlier DNS answer is still not matched.
        let name = match open.hostname_source {
            Some(HostnameSource::Sni) => open.hostname,
            _ => None,
        };
        self.verdict(
            &owner,
            Some(flow.dst.ip()),
            flow.dst.port(),
            name.as_deref(),
        )
    }

    fn flow_ended(&self, flow: &FlowInfo, totals: FlowTotals) {
        if lock(&self.refused).remove(&flow.id) {
            return;
        }
        let owner = lock(&self.open)
            .remove(&flow.id)
            .map_or_else(FlowOwner::unknown, |(_, owner)| owner);
        if let Some(app) = &owner.app
            && let Some(open) = lock(&self.open_per_app).get_mut(app)
        {
            *open = open.saturating_sub(1);
        }
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
        self.watch_check_ins(flow, &owner, &totals);
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
            system: false,
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
            system: false,
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

    /// DL-04, the beacon simulation: an app that checks in with one server every minute,
    /// a little data each time, raises one Info alert naming it, the server and the
    /// interval. The same pattern from a system app, or over DNS, raises nothing.
    #[test]
    fn an_app_checking_in_every_minute_raises_one_info_alert() {
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};

        let (_dir, history) = history();
        let system = FlowOwner {
            system: true,
            ..installed("com.android.example", None)
        };
        let observer = listen(
            &history,
            vec![
                (443, installed("org.example.beacon", None)),
                (8443, system),
                (53, installed("org.example.lookups", None)),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let mut id = 0;
        for minute in 0..10u64 {
            for (dst, hostname) in [
                ("203.0.113.9:443", Some("c2.example.net")),
                ("203.0.113.10:8443", Some("time.example.com")),
                ("10.215.173.53:53", None),
            ] {
                id += 1;
                let check_in = FlowInfo {
                    // A second or so late, now and then.
                    started_ms: 1_000_000 + minute * 60_000 + (minute % 3) * 700,
                    ..flow(id, dst, hostname)
                };
                assert_eq!(events.flow_started(&check_in), Verdict::Allow);
                events.flow_ended(
                    &check_in,
                    FlowTotals {
                        bytes_up: 300,
                        bytes_down: 900,
                        bytes_up_away: 0,
                        bytes_down_away: 0,
                        ended_ms: check_in.started_ms + 400,
                        verdict: Verdict::Allow,
                    },
                );
            }
        }
        events.flush();

        // Each app's first destinations raise their own alerts (CM-04).
        let alerts: Vec<_> = history
            .alerts(true, 10)
            .unwrap()
            .into_iter()
            .filter(|alert| alert.rule == AlertRule::BeaconLike)
            .collect();
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].severity, AlertSeverity::Info);
        assert_eq!(
            alerts[0].evidence,
            [
                AlertEvidence::App {
                    app: "org.example.beacon".to_owned()
                },
                AlertEvidence::Beacon {
                    destination: "c2.example.net".to_owned(),
                    // The median of its seven intervals.
                    interval_ms: 60_700,
                    check_ins: 8,
                    max_bytes: 1_200,
                }
            ]
        );
    }

    /// DL-05, the DNS-tunnel simulation: an app looking up a different encoded name
    /// every second under one domain raises one Warning naming the domain. The same
    /// lookups by a system app raise nothing. Apps that reach an encrypted DNS service
    /// themselves, by address, by name or on its own port, raise one Info alert each.
    #[test]
    fn unusual_dns_use_raises_its_alerts() {
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};

        // Bits enough for names that look like encoded data.
        fn mix(mut x: u64) -> u64 {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            x ^ (x >> 31)
        }
        let (_dir, history) = history();
        let system = FlowOwner {
            system: true,
            ..installed("com.android.example", None)
        };
        let observer = listen(
            &history,
            vec![
                (53, installed("org.example.tunnel", None)),
                (5353, system),
                (443, installed("org.example.browser", None)),
                (8443, installed("org.example.reader", None)),
                (853, installed("org.example.private", None)),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let tunnel = flow(1, "10.111.222.3:53", None);
        let quiet = flow(2, "10.111.222.3:5353", None);
        for lookups in [&tunnel, &quiet] {
            assert_eq!(events.flow_started(lookups), Verdict::Allow);
        }
        for i in 0..30 {
            let name = format!(
                "{:016x}{:016x}.{:016x}{:016x}.t.tunnel.example",
                mix(4 * i),
                mix(4 * i + 1),
                mix(4 * i + 2),
                mix(4 * i + 3)
            );
            assert_eq!(events.dns_query(&tunnel, &name, 1), Verdict::Allow);
            assert_eq!(events.dns_query(&quiet, &name, 1), Verdict::Allow);
        }
        let by_address = flow(3, "8.8.8.8:443", None);
        let by_name = flow(4, "203.0.113.7:8443", None);
        let dot = flow(5, "203.0.113.8:853", None);
        for connection in [&by_address, &by_name, &dot] {
            assert_eq!(events.flow_started(connection), Verdict::Allow);
        }
        assert_eq!(
            events.hostname_seen(&by_name, "cloudflare-dns.com"),
            Verdict::Allow
        );
        events.flush();

        let alerts = history.alerts(true, 20).unwrap();
        let of = |rule| -> Vec<_> { alerts.iter().filter(|a| a.rule == rule).collect() };
        let tunnels = of(AlertRule::DnsTunnel);
        assert_eq!(tunnels.len(), 1, "{alerts:?}");
        assert_eq!(tunnels[0].severity, AlertSeverity::Warning);
        assert_eq!(
            tunnels[0].evidence[0],
            AlertEvidence::App {
                app: "org.example.tunnel".to_owned()
            }
        );
        assert!(matches!(
            &tunnels[0].evidence[1],
            AlertEvidence::DnsNames { domain, names: 20, .. } if domain == "tunnel.example"
        ));
        let own: Vec<_> = of(AlertRule::OwnEncryptedDns)
            .into_iter()
            .map(|alert| (alert.severity, alert.evidence.clone()))
            .collect();
        let alert = |app: &str, server: &str| {
            (
                AlertSeverity::Info,
                vec![
                    AlertEvidence::App {
                        app: app.to_owned(),
                    },
                    AlertEvidence::EncryptedDns {
                        server: server.to_owned(),
                    },
                ],
            )
        };
        assert_eq!(own.len(), 3, "one for each app: {own:?}");
        assert!(own.contains(&alert("org.example.browser", "8.8.8.8")));
        assert!(own.contains(&alert("org.example.reader", "cloudflare-dns.com")));
        assert!(own.contains(&alert("org.example.private", "203.0.113.8")));
    }

    /// THREAT-MODEL-A D2: an app may have `MAX_FLOWS_PER_APP` flows open; more are
    /// refused and never recorded, the first refusal raises one Warning about the app,
    /// and once a flow ends another may open. Flows of no known app are not counted.
    #[test]
    fn an_app_may_not_open_more_than_its_share_of_flows() {
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};

        let (_dir, history) = history();
        let observer = listen(
            &history,
            vec![
                (443, installed("org.example.flood", None)),
                (80, FlowOwner::unknown()),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let open: Vec<FlowInfo> = (1..=u64::from(MAX_FLOWS_PER_APP))
            .map(|id| flow(id, "203.0.113.9:443", None))
            .collect();
        for flow in &open {
            assert_eq!(events.flow_started(flow), Verdict::Allow);
        }
        let ended = |verdict| FlowTotals {
            bytes_up: 0,
            bytes_down: 0,
            bytes_up_away: 0,
            bytes_down_away: 0,
            ended_ms: 5,
            verdict,
        };
        for id in [10_000, 10_001] {
            let refused = flow(id, "203.0.113.9:443", None);
            assert_eq!(events.flow_started(&refused), Verdict::Block);
            events.flow_ended(&refused, ended(Verdict::Block));
        }
        let unknown = flow(10_002, "203.0.113.10:80", None);
        assert_eq!(events.flow_started(&unknown), Verdict::Allow);
        events.flush();

        let recorded = history.recent_flows(1_000).unwrap();
        assert_eq!(
            recorded.len(),
            open.len() + 1,
            "refused flows are not recorded"
        );
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::FlowLimit);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
        assert_eq!(
            alerts[0].evidence,
            [
                AlertEvidence::App {
                    app: "org.example.flood".to_owned()
                },
                AlertEvidence::FlowLimit {
                    limit: MAX_FLOWS_PER_APP
                }
            ]
        );

        // One ends: another may open.
        events.flow_ended(&open[0], ended(Verdict::Allow));
        assert_eq!(
            events.flow_started(&flow(10_003, "203.0.113.9:443", None)),
            Verdict::Allow
        );
        assert_eq!(
            events.flow_started(&flow(10_004, "203.0.113.9:443", None)),
            Verdict::Block
        );
        events.flush();
        assert_eq!(
            history.alerts(true, 10).unwrap().len(),
            1,
            "one alert a run"
        );
    }

    /// ID-13: a lookup, a TLS server name or a connection that names a known indicator
    /// raises one Critical alert per app and indicator, with its provenance, and blocks
    /// nothing. While its alert is open, the same sighting in a later run raises nothing;
    /// once it is dismissed, it raises another. A list removed at its re-check matches
    /// nothing more.
    #[test]
    fn known_indicators_raise_one_critical_alert_per_app_and_indicator() {
        use crate::alerts::{
            AlertAction, AlertEvidence, AlertRule, AlertSeverity, IndicatorSighting,
            IndicatorThreat,
        };
        use crate::feed::tests::{indicators, open, path, stage};

        let (dir, history) = history();
        let observer = listen(
            &history,
            vec![
                (53, installed("org.example.chat", None)),
                (443, installed("org.example.spy", None)),
                (80, FlowOwner::unknown()),
            ],
        );
        let run = |session| FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), session);
        let events = run(1);
        let dns = flow(1, "10.111.222.3:53", None);
        assert_eq!(events.flow_started(&dns), Verdict::Allow);
        events.dns_query(&dns, "cdn.spy.example", 1);
        events.flush();
        let feed = open(&dir.path().join("feed"));
        events.set_feed(Some(Arc::clone(&feed)));
        events.dns_query(&dns, "cdn.spy.example", 1);
        events.flush();
        assert!(
            observer.heard.lock().unwrap().is_empty(),
            "no feed, then no list in force"
        );

        let staged = stage(
            dir.path(),
            1,
            &[(
                "indicators-lab.json",
                indicators(
                    "lab",
                    &[("domain", "spy.example"), ("address", "198.51.100.7")],
                ),
            )],
        );
        feed.install(path(&staged)).unwrap();
        assert_eq!(
            events.dns_query(&dns, "cdn.spy.example", 1),
            Verdict::Allow,
            "nothing is blocked without the user"
        );
        events.dns_query(&dns, "spy.example", 1);
        events.dns_query(&dns, "other.example", 1);
        let tls = flow(2, "203.0.113.5:443", None);
        events.flow_started(&tls);
        assert_eq!(events.hostname_seen(&tls, "spy.example"), Verdict::Allow);
        let unknown = flow(3, "198.51.100.7:80", None);
        assert_eq!(events.flow_started(&unknown), Verdict::Allow);
        events.flush();

        let heard = observer.heard.lock().unwrap().clone();
        assert_eq!(heard.len(), 3, "one per app and indicator: {heard:?}");
        assert!(
            heard
                .iter()
                .all(|alert| alert.rule == AlertRule::KnownIndicator
                    && alert.severity == AlertSeverity::Critical)
        );
        let provenance = |indicator: &str, seen: &str, sighting| AlertEvidence::Indicator {
            indicator: indicator.into(),
            seen: seen.into(),
            sighting,
            family: "Example".into(),
            threat: IndicatorThreat::Stalkerware,
            source: "Source lab".into(),
            date: "2025-01-31".into(),
            report: "https://example.org/report".into(),
        };
        assert_eq!(
            heard[0].evidence,
            [
                AlertEvidence::App {
                    app: "org.example.chat".into()
                },
                provenance(
                    "spy.example",
                    "cdn.spy.example",
                    IndicatorSighting::DnsQuery
                ),
            ]
        );
        assert_eq!(
            heard[0].actions,
            [
                AlertAction::BlockApp {
                    app: "org.example.chat".into()
                },
                AlertAction::OpenApp {
                    app: "org.example.chat".into()
                }
            ]
        );
        assert_eq!(
            heard[1].evidence,
            [
                AlertEvidence::App {
                    app: "org.example.spy".into()
                },
                provenance("spy.example", "spy.example", IndicatorSighting::ServerName),
            ]
        );
        assert_eq!(
            heard[2].evidence,
            [provenance(
                "198.51.100.7",
                "198.51.100.7",
                IndicatorSighting::Address
            )],
            "an app not known is still reported"
        );
        assert!(heard[2].actions.is_empty());

        // A later run: the open alert already says it.
        let events = run(2);
        events.set_feed(Some(Arc::clone(&feed)));
        let dns = flow(1, "10.111.222.3:53", None);
        events.flow_started(&dns);
        events.dns_query(&dns, "spy.example", 1);
        events.flush();
        assert_eq!(observer.heard.lock().unwrap().len(), 3);
        history.dismiss_alert(heard[0].id).unwrap();
        let events = run(3);
        events.set_feed(Some(Arc::clone(&feed)));
        events.flow_started(&dns);
        events.dns_query(&dns, "spy.example", 1);
        events.flush();
        assert_eq!(
            observer.heard.lock().unwrap().len(),
            4,
            "raised again once dismissed"
        );

        // SP-04: a list changed on the phone is removed, and matches nothing more.
        let file = feed.file("indicators-lab.json".into()).unwrap();
        std::fs::write(file, b"changed").unwrap();
        assert!(feed.recheck().is_err());
        let events = run(4);
        events.set_feed(Some(feed));
        let tls = flow(2, "198.51.100.7:443", None);
        events.flow_started(&tls);
        events.hostname_seen(&tls, "spy.example");
        events.flush();
        assert_eq!(observer.heard.lock().unwrap().len(), 4);
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
            [
                AlertAction::BlockApp {
                    app: "org.example.new".into()
                },
                AlertAction::OpenApp {
                    app: "org.example.new".into()
                }
            ]
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

    /// CM-10: the rules decide each connection with what is known for sure: the app and
    /// the address when it starts, and the TLS server name once seen. The most specific
    /// rule wins; changing the rules applies to the next connection; without a history
    /// nothing is blocked.
    #[test]
    fn rules_block_by_app_address_and_server_name() {
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let (_dir, history) = history();
        let observer = listen(
            &history,
            vec![
                (1, installed("org.example.maps", None)),
                (2, installed("org.example.chat", None)),
            ],
        );
        let rule = |app: Option<&str>, destination: Option<RuleDestination>, action| {
            history
                .set_firewall_rule(
                    FirewallRule {
                        app: app.map(str::to_owned),
                        destination,
                        action,
                    },
                    None,
                )
                .unwrap()
        };
        let domain = |name: &str| Some(RuleDestination::Domain { name: name.into() });
        let maps = rule(Some("org.example.maps"), None, RuleAction::Block);
        rule(None, domain("ads.example"), RuleAction::Block);
        rule(
            None,
            Some(RuleDestination::Network {
                range: "198.51.100.0/24".into(),
            }),
            RuleAction::Block,
        );
        rule(
            Some("org.example.chat"),
            domain("ok.ads.example"),
            RuleAction::Allow,
        );

        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let at = |id: u64, dst: &str| flow(id, dst, None);
        // The maps app is blocked whatever it reaches.
        assert_eq!(events.flow_started(&at(1, "203.0.113.5:1")), Verdict::Block);
        // A blocked range, for every app.
        assert_eq!(
            events.flow_started(&at(2, "198.51.100.9:2")),
            Verdict::Block
        );
        // Allowed when it starts; the server name decides later.
        let named = at(3, "203.0.113.5:2");
        assert_eq!(events.flow_started(&named), Verdict::Allow);
        assert_eq!(
            events.hostname_seen(&named, "x.ads.example"),
            Verdict::Block
        );
        assert_eq!(
            events.hostname_seen(&named, "ok.ads.example"),
            Verdict::Allow
        );
        assert_eq!(events.hostname_seen(&named, "chat.example"), Verdict::Allow);
        // A name from an earlier DNS answer is not matched: it may be another site's.
        let guessed = flow(4, "203.0.113.5:2", Some("ads.example"));
        assert_eq!(events.flow_started(&guessed), Verdict::Allow);
        // Lookups are decided by the app that sends them and the name, not the
        // resolver's address.
        let unowned = at(7, "198.51.100.53:2");
        assert_eq!(
            events.dns_query(&unowned, "x.ads.example", 1),
            Verdict::Block,
            "a domain rule for every app, whoever asks"
        );
        assert_eq!(
            events.dns_query(&unowned, "ok.ads.example", 1),
            Verdict::Block,
            "the chat app's exception needs the chat app"
        );
        assert_eq!(
            events.dns_query(&unowned, "chat.example", 1),
            Verdict::Allow,
            "the range rule needs an address, and a lookup has none"
        );
        let lookup = at(8, "203.0.113.53:2");
        events.flow_started(&lookup);
        assert_eq!(
            events.dns_query(&lookup, "x.ads.example", 1),
            Verdict::Block
        );
        assert_eq!(
            events.dns_query(&lookup, "ok.ads.example", 1),
            Verdict::Allow
        );
        assert_eq!(events.dns_query(&lookup, "chat.example", 1), Verdict::Allow);

        // Taking a rule back applies to the next connection.
        assert!(history.remove_firewall_rule(maps).unwrap());
        assert_eq!(events.flow_started(&at(5, "203.0.113.5:1")), Verdict::Allow);

        // The blocked connection is recorded as blocked when it starts and ends.
        let blocked = at(1, "203.0.113.5:1");
        events.flow_ended(
            &blocked,
            FlowTotals {
                bytes_up: 0,
                bytes_down: 0,
                bytes_up_away: 0,
                bytes_down_away: 0,
                ended_ms: 10,
                verdict: Verdict::Block,
            },
        );
        events.close_all(20);
        let stored = history.recent_flows(10).unwrap();
        let maps_flow = stored
            .iter()
            .find(|f| f.app.as_deref() == Some("org.example.maps") && f.ended_ms == Some(10))
            .unwrap();
        assert!(maps_flow.blocked);

        // No history, no rules: nothing is blocked.
        let bare = FlowEvents::new(observer, None, 2);
        assert_eq!(bare.flow_started(&at(6, "198.51.100.9:2")), Verdict::Allow);
    }

    /// RA-03: isolation lets through DNS, Sentinel itself and apps allowed as a whole,
    /// whatever the mode, until it ends; the rules still apply to what it lets through.
    /// It is kept across reopening the history.
    #[test]
    fn isolation_lets_through_only_dns_sentinel_and_allowed_apps() {
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let (dir, history) = history();
        let old = Some(history.began_ms() - 1);
        let observer = listen(
            &history,
            vec![
                (1, installed("org.example.chat", old)),
                (2, installed("io.github.malekhasan.sentinel", old)),
                (53, installed("org.example.chat", old)),
            ],
        );
        let events = FlowEvents::new(observer, Some(Arc::clone(&history)), 1);
        let at = |id: u64, port: u16| flow(id, &format!("203.0.113.5:{port}"), None);
        assert_eq!(history.isolated_since_ms(), None);
        let before = now_ms();
        history
            .isolate("io.github.malekhasan.sentinel".into())
            .unwrap();
        assert!(
            history
                .isolated_since_ms()
                .is_some_and(|since| since >= before)
        );

        assert_eq!(
            events.flow_started(&at(1, 1)),
            Verdict::Block,
            "any other app"
        );
        assert_eq!(
            events.flow_started(&at(2, 2)),
            Verdict::Allow,
            "Sentinel itself"
        );
        let dns = at(3, 53);
        assert_eq!(events.flow_started(&dns), Verdict::Allow, "DNS");
        assert_eq!(events.dns_query(&dns, "chat.example", 1), Verdict::Allow);
        let rule = |destination, action| FirewallRule {
            app: Some("org.example.chat".into()),
            destination,
            action,
        };
        history
            .set_firewall_rule(
                rule(
                    Some(RuleDestination::Domain {
                        name: "ads.example".into(),
                    }),
                    RuleAction::Block,
                ),
                None,
            )
            .unwrap();
        assert_eq!(
            events.dns_query(&dns, "ads.example", 1),
            Verdict::Block,
            "rules still apply"
        );
        history
            .set_firewall_rule(rule(None, RuleAction::Allow), None)
            .unwrap();
        let allowed = at(4, 1);
        assert_eq!(
            events.flow_started(&allowed),
            Verdict::Allow,
            "allowed as a whole"
        );
        assert_eq!(
            events.hostname_seen(&allowed, "x.ads.example"),
            Verdict::Block
        );

        // Kept across reopening, until it ends.
        drop(events);
        drop(history);
        let path = dir.path().join("history.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![7; 32]).unwrap();
        assert!(history.isolated_since_ms().is_some());
        history.end_isolation().unwrap();
        assert_eq!(history.isolated_since_ms(), None);
        let observer = listen(&history, vec![(1, installed("org.example.maps", old))]);
        let events = FlowEvents::new(observer, Some(Arc::clone(&history)), 2);
        assert_eq!(
            events.flow_started(&at(1, 1)),
            Verdict::Allow,
            "isolation ended"
        );
    }

    /// RA-01: a company rule blocks the names the tracker list gives that company, at a
    /// TLS server name and at a DNS lookup, once a tracker list is set; an app's
    /// exception needs that app.
    #[test]
    fn a_company_rule_blocks_its_names_from_the_tracker_list() {
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let mut builder = sentinel_enrich::TrackerDbBuilder::new();
        let radar = builder.add_source("Tracker Radar test").unwrap();
        builder
            .add_domain(radar, "ads.example", Some("Example Ads"), &["Advertising"])
            .unwrap();
        let (dir, history) = history();
        let path = dir.path().join("trackers.db");
        std::fs::write(&path, builder.build().unwrap()).unwrap();
        let trackers = TrackerDatabase::open(path.to_string_lossy().into_owned()).unwrap();
        let observer = listen(
            &history,
            vec![
                (
                    1,
                    installed("org.example.chat", Some(history.began_ms() - 1)),
                ),
                (
                    2,
                    installed("org.example.maps", Some(history.began_ms() - 1)),
                ),
            ],
        );
        let company = |app: Option<&str>, action| {
            history
                .set_firewall_rule(
                    FirewallRule {
                        app: app.map(str::to_owned),
                        destination: Some(RuleDestination::Company {
                            name: "Example Ads".into(),
                        }),
                        action,
                    },
                    None,
                )
                .unwrap()
        };
        company(None, RuleAction::Block);
        company(Some("org.example.maps"), RuleAction::Allow);
        let events = FlowEvents::new(observer, Some(Arc::clone(&history)), 1);
        let chat = flow(1, "203.0.113.5:1", None);
        let maps = flow(2, "203.0.113.5:2", None);
        events.flow_started(&chat);
        events.flow_started(&maps);
        assert_eq!(
            events.hostname_seen(&chat, "pixel.ads.example"),
            Verdict::Allow,
            "no tracker list, no company"
        );
        events.set_tracker_database(Some(trackers));
        assert_eq!(
            events.hostname_seen(&chat, "pixel.ads.example"),
            Verdict::Block
        );
        assert_eq!(events.dns_query(&chat, "ads.example", 1), Verdict::Block);
        assert_eq!(events.hostname_seen(&chat, "chat.example"), Verdict::Allow);
        assert_eq!(
            events.hostname_seen(&maps, "pixel.ads.example"),
            Verdict::Allow
        );
        assert_eq!(
            history.firewall_rules().unwrap()[0].rule.destination,
            Some(RuleDestination::Company {
                name: "Example Ads".into()
            })
        );
    }

    /// RA-01: when the rules change, an open connection is decided again with what was
    /// known for sure: its app, its address, and its TLS server name once seen. A name
    /// from an earlier DNS answer still does not count. Ended connections are not asked.
    #[test]
    fn open_connections_are_decided_again_with_what_is_known() {
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let (_dir, history) = history();
        let observer = listen(
            &history,
            vec![(
                1,
                installed("org.example.chat", Some(history.began_ms() - 1)),
            )],
        );
        let events = FlowEvents::new(observer, Some(Arc::clone(&history)), 1);
        let named = flow(1, "203.0.113.5:1", None);
        let guessed = flow(2, "203.0.113.6:1", Some("ads.example"));
        assert_eq!(events.flow_started(&named), Verdict::Allow);
        assert_eq!(
            events.hostname_seen(&named, "x.ads.example"),
            Verdict::Allow
        );
        assert_eq!(events.flow_started(&guessed), Verdict::Allow);

        history
            .set_firewall_rule(
                FirewallRule {
                    app: None,
                    destination: Some(RuleDestination::Domain {
                        name: "ads.example".into(),
                    }),
                    action: RuleAction::Block,
                },
                None,
            )
            .unwrap();
        assert_eq!(events.recheck(&named), Verdict::Block, "by its server name");
        assert_eq!(
            events.recheck(&guessed),
            Verdict::Allow,
            "a DNS name is a guess"
        );

        let chat = history
            .set_firewall_rule(
                FirewallRule {
                    app: Some("org.example.chat".into()),
                    destination: None,
                    action: RuleAction::Block,
                },
                None,
            )
            .unwrap();
        assert_eq!(events.recheck(&guessed), Verdict::Block, "by its app");
        assert!(history.remove_firewall_rule(chat).unwrap());
        assert_eq!(events.recheck(&guessed), Verdict::Allow);

        events.flow_ended(
            &guessed,
            FlowTotals {
                bytes_up: 0,
                bytes_down: 0,
                bytes_up_away: 0,
                bytes_down_away: 0,
                ended_ms: 5,
                verdict: Verdict::Allow,
            },
        );
        assert_eq!(events.recheck(&guessed), Verdict::Allow, "no longer open");
    }

    /// CM-08: a new app whose first connection a rule about its destination stopped, in
    /// Monitor mode, was not blocked for being new: its alert does not say so.
    #[test]
    fn a_rule_about_a_place_does_not_make_a_new_app_blocked() {
        use crate::alerts::AlertEvidence;
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let (_dir, history) = history();
        let observer = listen(
            &history,
            vec![(
                1,
                installed("org.example.new", Some(history.began_ms() + 1)),
            )],
        );
        history
            .set_firewall_rule(
                FirewallRule {
                    app: None,
                    destination: Some(RuleDestination::Network {
                        range: "203.0.113.0/24".into(),
                    }),
                    action: RuleAction::Block,
                },
                None,
            )
            .unwrap();
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        assert_eq!(
            events.flow_started(&flow(1, "203.0.113.5:1", None)),
            Verdict::Block
        );
        events.close_all(10);
        let heard = observer.heard.lock().unwrap();
        assert_eq!(heard.len(), 1);
        assert!(!heard[0].evidence.contains(&AlertEvidence::NewAppBlocked));
    }

    /// CM-08: Block-unknown stops the apps installed since it was turned on, from the
    /// next connection and at every moment the engine asks, until a rule allows them.
    /// Apps installed before, and connections whose install time is unknown, get
    /// through. Turning it on again keeps when it was turned on. Monitor lets the new
    /// app through again. The new app's first connection raises an alert that says it
    /// was blocked and offers to allow it.
    #[test]
    fn block_unknown_stops_new_apps_until_they_are_allowed() {
        use crate::alerts::{AlertAction, AlertEvidence, AlertRule};
        use crate::firewall::{FirewallMode, FirewallRule, RuleAction};
        use std::time::Instant;

        let (_dir, history) = history();
        let began = history.began_ms();
        let in_a_minute = now_ms() + 60_000;
        let observer = listen(
            &history,
            vec![
                (1, installed("org.example.new", Some(in_a_minute))),
                (2, installed("org.example.old", Some(began - 1))),
                (3, installed("android.uid.system:1000", None)),
            ],
        );
        let events = FlowEvents::new(observer.clone(), Some(Arc::clone(&history)), 1);
        let at = |id: u64, port: u16| flow(id, &format!("203.0.113.5:{port}"), None);
        let end = |flow: &FlowInfo, verdict| {
            events.flow_ended(
                flow,
                FlowTotals {
                    bytes_up: 0,
                    bytes_down: 0,
                    bytes_up_away: 0,
                    bytes_down_away: 0,
                    ended_ms: 10,
                    verdict,
                },
            )
        };

        assert_eq!(history.firewall_mode(), FirewallMode::Monitor);
        assert_eq!(events.flow_started(&at(1, 2)), Verdict::Allow);

        let switched = Instant::now();
        history
            .set_firewall_mode(FirewallMode::BlockUnknown)
            .unwrap();
        let first = at(2, 1);
        assert_eq!(events.flow_started(&first), Verdict::Block);
        let took = switched.elapsed();
        assert!(took < Duration::from_secs(1), "took {took:?}");
        assert_eq!(history.firewall_mode(), FirewallMode::BlockUnknown);
        assert_eq!(
            events.hostname_seen(&first, "api.new.example"),
            Verdict::Block
        );
        assert_eq!(
            events.dns_query(&first, "api.new.example", 1),
            Verdict::Block
        );
        end(&first, Verdict::Block);
        assert_eq!(
            events.flow_started(&at(3, 2)),
            Verdict::Allow,
            "installed before"
        );
        assert_eq!(
            events.flow_started(&at(4, 3)),
            Verdict::Allow,
            "install time unknown"
        );

        // An app installed after the first switch, before turning it on again, stays new.
        let on = history.mode_in_force();
        let between = now_ms();
        std::thread::sleep(Duration::from_millis(5));
        history
            .set_firewall_mode(FirewallMode::BlockUnknown)
            .unwrap();
        assert_eq!(
            history.mode_in_force(),
            on,
            "on since it was first turned on"
        );
        assert_eq!(on.decide(Some(between)), sentinel_detect::RuleAction::Block);

        events.close_all(20);
        let heard = observer.heard.lock().unwrap().clone();
        let alert = heard
            .iter()
            .find(|alert| alert.rule == AlertRule::FirstNetworkUse)
            .expect("the new app's first connection raises an alert");
        assert_eq!(
            alert.evidence,
            [
                AlertEvidence::App {
                    app: "org.example.new".into()
                },
                AlertEvidence::Destinations {
                    destinations: vec!["203.0.113.5".into()],
                    more: 0
                },
                AlertEvidence::NewAppBlocked,
            ]
        );
        assert_eq!(
            alert.actions[0],
            AlertAction::AllowApp {
                app: "org.example.new".into()
            }
        );

        // What the alert's action does: a rule allowing the app.
        let allowed = history
            .set_firewall_rule(
                FirewallRule {
                    app: Some("org.example.new".into()),
                    destination: None,
                    action: RuleAction::Allow,
                },
                None,
            )
            .unwrap();
        assert_eq!(events.flow_started(&at(5, 1)), Verdict::Allow);
        assert!(history.remove_firewall_rule(allowed).unwrap());
        assert_eq!(events.flow_started(&at(6, 1)), Verdict::Block);
        history.set_firewall_mode(FirewallMode::Monitor).unwrap();
        assert_eq!(events.flow_started(&at(7, 1)), Verdict::Allow);

        events.close_all(30);
        let first_stored = history
            .recent_flows(20)
            .unwrap()
            .into_iter()
            .find(|f| f.app.as_deref() == Some("org.example.new") && f.ended_ms == Some(10))
            .unwrap();
        assert!(first_stored.blocked);
    }
}

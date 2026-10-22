// SPDX-License-Identifier: GPL-3.0-or-later
//! The encrypted local history (SRS §13), as seen from Kotlin.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use sentinel_detect::{FirewallMode as Mode, Isolation, Place, RuleSet};
use sentinel_store::{KEY_LEN, Store, StoreError, Undo};
use zeroize::Zeroizing;

use crate::alerts::{
    AlertDelivery, AlertFeedback, AlertListener, AlertRule, AllowedRule, HistoryAlert,
};
use crate::enrich::{CategoryFact, CompanyFact};
use crate::firewall::{AppAccess, FirewallMode, FirewallRule, HistoryRule};
use crate::flows::{FlowProto, NameSource};
use crate::journal::{JournalEntry, UndoResult};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HistoryError {
    #[error("the key must be {expected} bytes")]
    BadKey { expected: u32 },
    /// The key does not open the database: it was replaced, or the file is damaged.
    #[error("the history cannot be opened with this key")]
    WrongKey,
    #[error("the history failed: {reason}")]
    Failed { reason: String },
    /// A firewall rule that cannot be kept: for example a domain that is not a name, or
    /// a rule with neither an app nor a destination.
    #[error("the rule cannot be kept: {reason}")]
    BadRule { reason: String },
}

impl From<StoreError> for HistoryError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::WrongKey => HistoryError::WrongKey,
            other => HistoryError::Failed {
                reason: other.to_string(),
            },
        }
    }
}

/// A flow read back from the history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryFlow {
    pub id: i64,
    /// Package name of the owning app, if known.
    pub app: Option<String>,
    pub proto: FlowProto,
    pub remote_ip: String,
    pub remote_port: u16,
    pub hostname: Option<String>,
    pub hostname_source: Option<NameSource>,
    pub started_ms: i64,
    pub ended_ms: Option<i64>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub blocked: bool,
}

/// A time when monitoring was wanted but not running (SP-03).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryGap {
    pub started_ms: Option<i64>,
    pub ended_ms: Option<i64>,
    pub reason: String,
}

/// What the history holds about one app (the app detail screen).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryApp {
    pub app: String,
    /// When the app was first seen using the network. A wipe resets it.
    pub first_seen_ms: i64,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    /// Of the above, the bytes carried while the user was away (CM-06).
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
    /// Destinations in the whole history, including those not listed.
    pub destination_count: u32,
    /// Most data sent first.
    pub destinations: Vec<HistoryDestination>,
    /// The companies all of its destinations belong to, as far as the tracker lists
    /// know, most data sent first (DT-06).
    #[uniffi(default = [])]
    pub companies: Vec<HistoryCompany>,
}

/// One app's traffic to one company's destinations (DT-06).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryCompany {
    pub company: String,
    /// The categories of those destinations.
    pub categories: Vec<String>,
    pub destinations: u32,
    pub bytes_up: i64,
    pub bytes_down: i64,
}

/// One app's traffic to one destination, over the whole history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryDestination {
    /// Hostname if known, otherwise the remote address.
    pub destination: String,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
    /// Flows older than the retention period keep only their day: they count from the
    /// start of that day (UTC).
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// How the destination's name was learned (the strongest seen); none for an address.
    #[uniffi(default = None)]
    pub name_source: Option<NameSource>,
    /// The network the destination's address belongs to (DT-01) and where that comes
    /// from (DT-02).
    #[uniffi(default = None)]
    pub asn: Option<u32>,
    #[uniffi(default = None)]
    pub network_owner: Option<String>,
    #[uniffi(default = None)]
    pub network_source: Option<String>,
    /// Approximate country, ISO 3166 two letters, and where that comes from.
    #[uniffi(default = None)]
    pub country: Option<String>,
    #[uniffi(default = None)]
    pub country_source: Option<String>,
    /// The company it belongs to and what kind of service it is, from the tracker lists,
    /// with where each comes from (DT-06).
    #[uniffi(default = None)]
    pub company: Option<CompanyFact>,
    #[uniffi(default = None)]
    pub categories: Option<CategoryFact>,
}

/// What decides where the phone's traffic goes on the network it uses (CM-07). The app
/// reports it whenever it changes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NetworkState {
    /// The network in use, for as long as the phone stays on it: joining it again, or
    /// restarting the phone, must give another value. On Android, the boot count and
    /// the network's id.
    pub network: Option<String>,
    /// The network's DNS servers, in its order.
    pub dns_servers: Vec<String>,
    /// The Private DNS provider the phone is set to use, if one is named.
    pub private_dns: Option<String>,
    /// The proxy set on the network itself, if any.
    pub network_proxy: Option<String>,
    /// The proxy in effect on the network: one set for the whole phone, or the
    /// network's own.
    pub proxy: Option<String>,
}

/// One app's traffic while the user was away (CM-06).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryAway {
    /// Package name, or `None` for connections whose owner is unknown.
    pub app: Option<String>,
    /// Connections that carried data while the user was away.
    pub flows: i64,
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
}

#[derive(uniffi::Object)]
pub struct HistoryStore {
    pub(crate) store: Store,
    alert_listener: Mutex<Option<Arc<dyn AlertListener>>>,
    /// The firewall rules in force, as the engine asks them (CM-10).
    rules: RwLock<Arc<RuleSet>>,
    /// The firewall mode in force (CM-08).
    mode: RwLock<Mode>,
    /// Network isolation, while on (RA-03).
    isolation: RwLock<Option<Arc<Isolation>>>,
    /// Bumped whenever the rules or the mode change, so that running engines ask again
    /// about their open connections.
    firewall_changes: tokio::sync::watch::Sender<u64>,
    /// Held while the history is checked against an indicator list (MS-02).
    pub(crate) hunting: Mutex<()>,
}

/// What to export from the history (SRS §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExportKind {
    /// Each connection kept in full (rolled-up days are not).
    Flows,
    Alerts,
    /// The action journal.
    Actions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// One page of an export: the pages of one export, written out in order, make one JSON
/// array or one CSV table with its header.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportPage {
    pub text: String,
    /// Pass it to get the next page; `None` when this page ends the export.
    pub next: Option<i64>,
}

#[uniffi::export]
impl HistoryStore {
    /// Open or create the history at `path` with a random 32-byte key (on Android,
    /// unwrapped with a Keystore key; see ADR-0009).
    #[uniffi::constructor]
    pub fn open(path: String, key: Vec<u8>) -> Result<Arc<Self>, HistoryError> {
        // Both copies of the key are wiped when dropped (audit A-30).
        let key = Zeroizing::new(key);
        let key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(key.as_slice().try_into().map_err(
            |_| HistoryError::BadKey {
                expected: KEY_LEN as u32,
            },
        )?);
        let store = Store::open(Path::new(&path), &key)?;
        let mode = store.firewall_mode()?;
        let isolation = store.isolation()?.map(Arc::new);
        let history = HistoryStore {
            store,
            alert_listener: Mutex::new(None),
            rules: RwLock::new(Arc::new(RuleSet::default())),
            mode: RwLock::new(mode),
            isolation: RwLock::new(isolation),
            firewall_changes: tokio::sync::watch::Sender::new(0),
            hunting: Mutex::new(()),
        };
        history.reload_rules()?;
        Ok(Arc::new(history))
    }

    /// Keep a firewall rule, replacing one about the same app and destination, and apply
    /// it to connections from now on (CM-10). The journal keeps it (SRS §9), with the
    /// alert it was taken from, if any. Returns its key.
    #[uniffi::method(default(alert = None))]
    pub fn set_firewall_rule(
        &self,
        rule: FirewallRule,
        alert: Option<i64>,
    ) -> Result<String, HistoryError> {
        let rule = sentinel_detect::FirewallRule::try_from(rule)?;
        let key = self.store.set_firewall_rule(&rule, now_ms(), alert)?;
        self.reload_rules()?;
        Ok(key)
    }

    /// Remove the firewall rule with this key, journalled. Returns whether there was one.
    pub fn remove_firewall_rule(&self, key: String) -> Result<bool, HistoryError> {
        let removed = self.store.remove_firewall_rule(&key, now_ms())?;
        self.reload_rules()?;
        Ok(removed)
    }

    /// Put a firewall mode in force for connections from now on (CM-08). Block-unknown
    /// blocks the apps installed from now on until a rule allows them; turning it on
    /// while it is on changes nothing.
    pub fn set_firewall_mode(&self, mode: FirewallMode) -> Result<(), HistoryError> {
        let now = now_ms();
        let mode = match mode {
            FirewallMode::Monitor => Mode::Monitor,
            FirewallMode::BlockUnknown => Mode::BlockUnknown { since: now },
        };
        let mut in_force = self.mode.write().unwrap_or_else(PoisonError::into_inner);
        *in_force = self.store.set_firewall_mode(mode, now)?;
        drop(in_force);
        self.firewall_changed();
        Ok(())
    }

    /// The firewall mode in force.
    pub fn firewall_mode(&self) -> FirewallMode {
        self.mode_in_force().into()
    }

    /// Isolate the phone (RA-03): from now on, and for open connections at once, only
    /// DNS, `own_app` (Sentinel itself) and the apps a rule allows as a whole may use the
    /// network. Kept until [`Self::end_isolation`], across restarts. Isolating while
    /// isolated keeps when it began.
    pub fn isolate(&self, own_app: String) -> Result<(), HistoryError> {
        let now = now_ms();
        let isolation = Isolation {
            since: now,
            own_app,
        };
        let mut in_force = self
            .isolation
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        self.store.set_isolation(Some(&isolation), now)?;
        *in_force = self.store.isolation()?.map(Arc::new);
        drop(in_force);
        self.firewall_changed();
        Ok(())
    }

    /// End isolation: the rules and the mode decide again.
    pub fn end_isolation(&self) -> Result<(), HistoryError> {
        let mut in_force = self
            .isolation
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        self.store.set_isolation(None, now_ms())?;
        *in_force = None;
        drop(in_force);
        self.firewall_changed();
        Ok(())
    }

    /// The action journal, newest first (SRS §9): each change to the firewall rules, the
    /// mode and isolation, at most `limit`.
    pub fn journal(&self, limit: u32) -> Result<Vec<JournalEntry>, HistoryError> {
        Ok(self
            .store
            .journal(limit)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Undo the action `id` from the journal: put its setting back as it was before,
    /// if nothing changed it since, for connections from now on and open ones.
    pub fn undo_action(&self, id: i64) -> Result<UndoResult, HistoryError> {
        let undone = self.store.undo(id, now_ms())?;
        if undone == Undo::Undone {
            self.reload_firewall()?;
        }
        Ok(undone.into())
    }

    /// When isolation began, Unix milliseconds; `None` when the phone is not isolated.
    pub fn isolated_since_ms(&self) -> Option<i64> {
        self.isolation_in_force().map(|isolation| isolation.since)
    }

    /// Whether `app`, installed at `installed_ms` if known, may use the network as a
    /// whole: the rule about it, and whether Block-unknown keeps it off as new.
    pub fn app_access(&self, app: String, installed_ms: Option<i64>) -> AppAccess {
        let rules = self.rule_set();
        AppAccess {
            rule: rules
                .decide(Some(app.as_str()), Place::default())
                .map(Into::into),
            blocked_as_new: rules.blocks_new_app(self.mode_in_force(), app.as_str(), installed_ms),
        }
    }

    /// The firewall rules in force, newest first.
    pub fn firewall_rules(&self) -> Result<Vec<HistoryRule>, HistoryError> {
        Ok(self
            .store
            .firewall_rules()?
            .into_iter()
            .map(|stored| HistoryRule {
                key: stored.key,
                rule: stored.rule.into(),
                created_ms: stored.created,
            })
            .collect())
    }

    /// The most recent flows, newest first.
    pub fn recent_flows(&self, limit: u32) -> Result<Vec<HistoryFlow>, HistoryError> {
        Ok(self
            .store
            .recent_flows(limit)?
            .into_iter()
            .map(|stored| {
                let flow = stored.flow;
                HistoryFlow {
                    id: stored.id,
                    app: flow.app,
                    proto: match flow.proto {
                        sentinel_store::Proto::Tcp => FlowProto::Tcp,
                        sentinel_store::Proto::Udp => FlowProto::Udp,
                    },
                    remote_ip: flow.remote_ip,
                    remote_port: flow.remote_port,
                    hostname: flow.hostname,
                    hostname_source: flow.hostname_src.map(|source| match source {
                        sentinel_store::HostnameSource::Dns => NameSource::Dns,
                        sentinel_store::HostnameSource::Sni => NameSource::Sni,
                    }),
                    started_ms: flow.started,
                    ended_ms: flow.ended,
                    bytes_up: flow.bytes_up,
                    bytes_down: flow.bytes_down,
                    blocked: flow.blocked,
                }
            })
            .collect())
    }

    /// Everything the history holds about `app` (a package name), with at most `limit`
    /// destinations, most data sent first. `None` if the app was never seen. Flows
    /// still open count with the bytes they had when they started.
    pub fn app_summary(&self, app: String, limit: u32) -> Result<Option<HistoryApp>, HistoryError> {
        Ok(self
            .store
            .app_summary(&app, limit)?
            .map(|summary| HistoryApp {
                app: summary.app,
                first_seen_ms: summary.first_seen,
                flows: summary.flows,
                bytes_up: summary.bytes_up,
                bytes_down: summary.bytes_down,
                bytes_up_away: summary.bytes_up_away,
                bytes_down_away: summary.bytes_down_away,
                destination_count: summary.destination_count,
                destinations: summary
                    .destinations
                    .into_iter()
                    .map(|d| HistoryDestination {
                        destination: d.destination,
                        flows: d.flows,
                        bytes_up: d.bytes_up,
                        bytes_down: d.bytes_down,
                        bytes_up_away: d.bytes_up_away,
                        bytes_down_away: d.bytes_down_away,
                        first_seen_ms: d.first_seen,
                        last_seen_ms: d.last_seen,
                        name_source: d.name_source.map(|source| match source {
                            sentinel_store::HostnameSource::Dns => NameSource::Dns,
                            sentinel_store::HostnameSource::Sni => NameSource::Sni,
                        }),
                        asn: d.facts.asn,
                        network_owner: d.facts.network_owner,
                        network_source: d.facts.network_source,
                        country: d.facts.country,
                        country_source: d.facts.country_source,
                        company: d.facts.company.map(Into::into),
                        categories: d.facts.categories.map(Into::into),
                    })
                    .collect(),
                companies: summary
                    .companies
                    .into_iter()
                    .map(|c| HistoryCompany {
                        company: c.company,
                        categories: c.categories,
                        destinations: c.destinations,
                        bytes_up: c.bytes_up,
                        bytes_down: c.bytes_down,
                    })
                    .collect(),
            }))
    }

    /// Apps whose connections carried data while the user was away, among connections
    /// active since `since_ms`, most data sent first, at most `limit` (CM-06).
    pub fn away_totals(&self, since_ms: i64, limit: u32) -> Result<Vec<HistoryAway>, HistoryError> {
        Ok(self
            .store
            .away_totals(since_ms, limit)?
            .into_iter()
            .map(|total| HistoryAway {
                app: total.app,
                flows: total.flows,
                bytes_up_away: total.bytes_up_away,
                bytes_down_away: total.bytes_down_away,
            })
            .collect())
    }

    /// When this history began, Unix milliseconds: when it was created or last wiped.
    /// Only apps installed since then can be new to the network (CM-04).
    pub fn began_ms(&self) -> i64 {
        self.store.began()
    }

    /// Close the database before it is wiped (audit A-28). It waits until nothing is
    /// using it; later calls fail without touching a file, so that nothing still running
    /// reads or writes the wiped history.
    pub fn close_database(&self) -> Result<(), HistoryError> {
        Ok(self.store.close()?)
    }

    /// Start a monitoring gap, unless one is already open. `started_ms` is `None` when
    /// the start is unknown. A new gap raises an alert (SP-03).
    pub fn open_gap(&self, started_ms: Option<i64>, reason: String) -> Result<(), HistoryError> {
        if self.store.open_gap(started_ms, &reason)? {
            let now = now_ms();
            let alert = sentinel_detect::monitoring_interrupted(now, started_ms, &reason);
            self.raise(&alert)?;
            // SP-02: again and again, a Critical alert, once while it is open.
            let window = i64::from(sentinel_detect::REPEATED_GAPS_HOURS) * 60 * 60 * 1000;
            let gaps = self.store.gaps_since(now - window, now)?;
            if let Some(alert) = sentinel_detect::monitoring_keeps_stopping(now, gaps) {
                self.raise_unless_open(&alert, |_, _| true)?;
            }
        }
        Ok(())
    }

    /// Say that this history was started in place of one that could not be opened (its
    /// key is gone, or the file was changed), with an alert in it, so that the loss is not
    /// silent (THREAT-MODEL-A T6). The app calls it once, after opening the new history.
    pub fn started_anew(&self) -> Result<(), HistoryError> {
        self.raise(&sentinel_detect::history_started_anew(now_ms()))
    }

    /// The network settings last seen (CM-07), if any.
    pub fn last_network_state(&self) -> Result<Option<NetworkState>, HistoryError> {
        Ok(self.store.network_state()?.map(|state| NetworkState {
            network: state.network,
            dns_servers: state.dns_servers,
            private_dns: state.private_dns,
            network_proxy: state.network_proxy,
            proxy: state.proxy,
        }))
    }

    /// The network settings as they are now (CM-07). Each change from the settings seen
    /// before, even before Sentinel last stopped, raises an alert. The first state a
    /// history sees raises nothing.
    pub fn network_seen(&self, state: NetworkState) -> Result<(), HistoryError> {
        let state = sentinel_detect::NetworkState {
            network: state.network,
            dns_servers: state.dns_servers,
            private_dns: state.private_dns,
            network_proxy: state.network_proxy,
            proxy: state.proxy,
        };
        let now = now_ms();
        if let Some(before) = self.store.swap_network_state(&state, now)? {
            for alert in sentinel_detect::network_changes(now, &before, &state) {
                self.raise(&alert)?;
            }
        }
        Ok(())
    }

    /// Record what the user said about alert `id`, or take it back with `None` (AL-05).
    /// Any feedback dismisses the alert; allowing it stops its rule from raising alerts
    /// about the same app. A Critical alert cannot be allowed. Returns whether there is
    /// an alert with this id.
    pub fn set_feedback(
        &self,
        id: i64,
        feedback: Option<AlertFeedback>,
    ) -> Result<bool, HistoryError> {
        Ok(self
            .store
            .set_feedback(id, feedback.map(Into::into), now_ms())?)
    }

    /// Everything the user allowed, newest first: a rule for an app each.
    pub fn allowed(&self) -> Result<Vec<AllowedRule>, HistoryError> {
        Ok(self
            .store
            .allowed()?
            .into_iter()
            .map(|entry| AllowedRule {
                rule: entry.rule.into(),
                app: entry.app,
                created_ms: entry.created,
            })
            .collect())
    }

    /// Take back what the user allowed for `app` and `rule`, from the list of what was
    /// allowed (audit A-08): its alerts come again, and the alerts it was allowed from no
    /// longer say it is allowed. Returns whether it was allowed.
    pub fn take_back_allowed(&self, rule: AlertRule, app: String) -> Result<bool, HistoryError> {
        Ok(self.store.take_back(rule.into(), &app)?)
    }

    /// Tell `listener` about every new alert from now on, or no one.
    pub fn set_alert_listener(&self, listener: Option<Arc<dyn AlertListener>>) {
        *self
            .alert_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = listener;
    }

    /// Whether alert `id` gets a notification now (AL-03, AL-04); if so, it is recorded
    /// as notified. `None` if there is no alert with this id.
    pub fn claim_notification(
        &self,
        id: i64,
        do_not_disturb: bool,
    ) -> Result<Option<AlertDelivery>, HistoryError> {
        Ok(self
            .store
            .claim_notification(id, now_ms(), do_not_disturb)?
            .map(AlertDelivery::from))
    }

    /// The most recent alerts, newest first: only the open ones, or all of them.
    pub fn alerts(&self, open_only: bool, limit: u32) -> Result<Vec<HistoryAlert>, HistoryError> {
        Ok(self
            .store
            .alerts(open_only, limit)?
            .into_iter()
            .map(HistoryAlert::from)
            .collect())
    }

    /// One alert, if there is one with this id.
    pub fn alert(&self, id: i64) -> Result<Option<HistoryAlert>, HistoryError> {
        Ok(self.store.alert(id)?.map(HistoryAlert::from))
    }

    /// The user has seen the alert and puts it away. Returns whether there is one with
    /// this id.
    pub fn dismiss_alert(&self, id: i64) -> Result<bool, HistoryError> {
        Ok(self
            .store
            .set_alert_state(id, sentinel_detect::AlertState::Dismissed)?)
    }

    /// Monitoring is back: close the open gap, if any.
    pub fn close_gap(&self, ended_ms: i64) -> Result<(), HistoryError> {
        Ok(self.store.close_gap(ended_ms)?)
    }

    /// The most recent gaps, newest first.
    pub fn recent_gaps(&self, limit: u32) -> Result<Vec<HistoryGap>, HistoryError> {
        Ok(self
            .store
            .recent_gaps(limit)?
            .into_iter()
            .map(|gap| HistoryGap {
                started_ms: gap.started,
                ended_ms: gap.ended,
                reason: gap.reason,
            })
            .collect())
    }

    /// One page of an export (SRS §12.3, ADR-0033): at most `limit` records of `kind`
    /// from `from_ms` (inclusive) to `to_ms` (exclusive), oldest first, as `format`.
    /// `after` is the previous page's `next`, or `None` for the first page. Only ever
    /// called at the user's request (SRS §15.2).
    pub fn export_page(
        &self,
        kind: ExportKind,
        format: ExportFormat,
        from_ms: i64,
        to_ms: i64,
        after: Option<i64>,
        limit: u32,
    ) -> Result<ExportPage, HistoryError> {
        let kind = match kind {
            ExportKind::Flows => sentinel_store::ExportKind::Flows,
            ExportKind::Alerts => sentinel_store::ExportKind::Alerts,
            ExportKind::Actions => sentinel_store::ExportKind::Actions,
        };
        let format = match format {
            ExportFormat::Json => sentinel_store::ExportFormat::Json,
            ExportFormat::Csv => sentinel_store::ExportFormat::Csv,
        };
        let page = self
            .store
            .export_page(kind, format, from_ms, to_ms, after, limit)?;
        Ok(ExportPage {
            text: page.text,
            next: page.next,
        })
    }

    /// Apply the retention periods of SRS §13.2 at `now_ms`: flows older than
    /// [`HistoryStore::flow_keep_days`] are rolled up into daily totals; sensor uses and
    /// gaps go after 90 days, journal entries and alerts the user dealt with after a
    /// year, except those about known indicators. Returns how many records it removed.
    pub fn apply_retention(&self, now_ms: i64) -> Result<u64, HistoryError> {
        let removed = self
            .store
            .apply_retention(now_ms, self.store.flow_keep_days()?)?;
        Ok((removed.flows
            + removed.sensor_uses
            + removed.gaps
            + removed.alerts
            + removed.journal_entries) as u64)
    }

    /// How many days flows are kept before they are rolled up (SRS §13.2): 30 unless
    /// the user chose otherwise.
    pub fn flow_keep_days(&self) -> Result<u32, HistoryError> {
        Ok(self.store.flow_keep_days()?)
    }

    /// Keep flows `days` days from now on, from 1 to 365. Returns false, and keeps the
    /// setting as it was, for any other number. The next retention applies it.
    pub fn set_flow_keep_days(&self, days: u32) -> Result<bool, HistoryError> {
        Ok(self.store.set_flow_keep_days(days)?)
    }
}

/// Delete the history database at `path`, and any set aside (one-tap wipe, SRS §13.2).
/// Close every `HistoryStore` on it first; the app deletes the key.
#[uniffi::export]
pub fn wipe_history(path: String) -> Result<(), HistoryError> {
    Ok(sentinel_store::wipe(Path::new(&path))?)
}

/// Set the history database at `path` aside, so that a new one can start there: for a
/// history that can never be read (audit A-06). It is kept until the next one is set
/// aside, or the wipe. Close every `HistoryStore` on it first.
#[uniffi::export]
pub fn set_aside_history(path: String) -> Result<(), HistoryError> {
    Ok(sentinel_store::set_aside(Path::new(&path))?)
}

impl HistoryStore {
    /// The firewall rules in force. Cheap: the engine asks for every connection.
    pub(crate) fn rule_set(&self) -> Arc<RuleSet> {
        Arc::clone(&self.rules.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Network isolation, while on.
    pub(crate) fn isolation_in_force(&self) -> Option<Arc<Isolation>> {
        self.isolation
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The firewall mode in force, with when it was turned on.
    pub(crate) fn mode_in_force(&self) -> Mode {
        *self.mode.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes whenever the rules or the mode change: an engine's open connections are
    /// then decided again (RA-01).
    pub(crate) fn firewall_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.firewall_changes.subscribe()
    }

    fn firewall_changed(&self) {
        self.firewall_changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    /// Read the rules, the mode and isolation again, after an undo changed one of them.
    fn reload_firewall(&self) -> Result<(), HistoryError> {
        *self.mode.write().unwrap_or_else(PoisonError::into_inner) = self.store.firewall_mode()?;
        *self
            .isolation
            .write()
            .unwrap_or_else(PoisonError::into_inner) = self.store.isolation()?.map(Arc::new);
        self.reload_rules()
    }

    fn reload_rules(&self) -> Result<(), HistoryError> {
        let rules = self
            .store
            .firewall_rules()?
            .into_iter()
            .map(|stored| stored.rule)
            .collect();
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(RuleSet::new(rules));
        self.firewall_changed();
        Ok(())
    }

    /// Keep a new alert and tell the listener, if any, unless the user allowed what it
    /// is about (AL-05). The listener is called without any lock held, so it may read
    /// the history.
    pub(crate) fn raise(&self, alert: &sentinel_detect::Alert) -> Result<(), HistoryError> {
        self.raise_or_join(alert, None)
    }

    /// As [`HistoryStore::raise`], unless an open alert of the same rule already says
    /// what this one would, as `same` decides.
    pub(crate) fn raise_unless_open(
        &self,
        alert: &sentinel_detect::Alert,
        same: impl Fn(&sentinel_detect::Alert, &sentinel_detect::Alert) -> bool,
    ) -> Result<(), HistoryError> {
        let open = self.store.alerts_of(alert.rule, true)?;
        if open.iter().any(|stored| same(alert, &stored.alert)) {
            return Ok(());
        }
        self.raise(alert)
    }

    /// DL-02: a Warning about each app that sent ten times its usual day in the day
    /// before `now`. At most one a day per app: not while its last one is open, nor
    /// within a day of it.
    pub(crate) fn raise_upload_surges(&self, now: i64) -> Result<(), HistoryError> {
        const DAY_MS: i64 = 24 * 60 * 60 * 1000;
        for uploads in self.store.uploads(now)? {
            let Some(alert) = sentinel_detect::upload_surge(now, &uploads) else {
                continue;
            };
            let raised_lately = self
                .store
                .alerts_of(alert.rule, false)?
                .iter()
                .any(|stored| {
                    stored.alert.app() == alert.app() && stored.alert.created > now - DAY_MS
                });
            if !raised_lately {
                self.raise_unless_open(&alert, |new, open| new.app() == open.app())?;
            }
        }
        Ok(())
    }

    /// As [`HistoryStore::raise`], but if the app has an open alert of the same rule
    /// raised at or after `join_since`, the new alert's destinations join it instead,
    /// and the listener is not told again (CM-04).
    pub(crate) fn raise_or_join(
        &self,
        alert: &sentinel_detect::Alert,
        join_since: Option<i64>,
    ) -> Result<(), HistoryError> {
        if self.store.is_allowed(alert.rule, alert.app())? {
            return Ok(());
        }
        if let Some(since) = join_since
            && self.store.join_open_alert(alert, since)?.is_some()
        {
            return Ok(());
        }
        let id = self.store.record_alert(alert)?;
        let listener = self
            .alert_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let (Some(listener), Some(stored)) = (listener, self.store.alert(id)?) {
            listener.raised(stored.into());
        }
        Ok(())
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_short_key_and_opens_with_a_full_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        assert!(matches!(
            HistoryStore::open(path.clone(), vec![1; 16]),
            Err(HistoryError::BadKey { expected: 32 })
        ));
        let history = HistoryStore::open(path.clone(), vec![1; 32]).unwrap();
        history.open_gap(Some(5), "test".into()).unwrap();
        history.close_gap(9).unwrap();
        assert_eq!(
            history.recent_gaps(5).unwrap(),
            vec![HistoryGap {
                started_ms: Some(5),
                ended_ms: Some(9),
                reason: "test".into()
            }]
        );
        drop(history);
        assert!(matches!(
            HistoryStore::open(path.clone(), vec![2; 32]),
            Err(HistoryError::WrongKey)
        ));
        // Set aside, a new history starts at the path; the wipe deletes both (A-06).
        set_aside_history(path.clone()).unwrap();
        let history = HistoryStore::open(path.clone(), vec![2; 32]).unwrap();
        assert!(history.recent_gaps(5).unwrap().is_empty());
        drop(history);
        assert!(std::fs::read_dir(dir.path()).unwrap().count() > 1);
        wipe_history(path).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// SRS §13.2: retention keeps flows as long as the setting says, and the setting
    /// keeps to 1 to 365 days.
    #[test]
    fn retention_follows_the_setting() {
        use sentinel_store::{FlowEvent, FlowRow, Proto};

        const DAY: i64 = 24 * 60 * 60 * 1000;
        const NOW: i64 = 1_791_979_200_000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        assert_eq!(history.flow_keep_days().unwrap(), 30);
        assert!(!history.set_flow_keep_days(0).unwrap());
        assert!(!history.set_flow_keep_days(366).unwrap());
        assert!(history.set_flow_keep_days(7).unwrap());
        assert_eq!(history.flow_keep_days().unwrap(), 7);

        let events = [NOW - 2 * DAY, NOW - 10 * DAY]
            .into_iter()
            .enumerate()
            .map(|(i, started)| FlowEvent {
                engine_id: i as u64,
                flow: FlowRow {
                    app: Some("org.example.app".to_owned()),
                    proto: Proto::Tcp,
                    local_ip: "10.215.173.1".to_owned(),
                    local_port: 40_000,
                    remote_ip: "203.0.113.9".to_owned(),
                    remote_port: 443,
                    hostname: None,
                    hostname_src: None,
                    started,
                    ended: Some(started + 1_000),
                    bytes_up: 1,
                    bytes_down: 1,
                    bytes_up_away: 0,
                    bytes_down_away: 0,
                    blocked: false,
                },
                destination: None,
            })
            .collect::<Vec<_>>();
        history.store.record_flows(1, &events).unwrap();
        history
            .open_gap(Some(NOW - 100 * DAY), "old".into())
            .unwrap();
        history.close_gap(NOW - 95 * DAY).unwrap();

        assert_eq!(
            history.apply_retention(NOW).unwrap(),
            2,
            "the flow from ten days ago and the gap"
        );
        assert_eq!(history.apply_retention(NOW).unwrap(), 0);
        assert_eq!(history.store.recent_flows(10).unwrap().len(), 1);
        assert!(history.recent_gaps(10).unwrap().is_empty());
    }

    /// DL-02: an app that sends ten times its usual day raises one Warning; not again
    /// while it is open or within a day, and again for a surge the next day.
    #[test]
    fn an_upload_surge_raises_one_warning_a_day() {
        use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity};
        use sentinel_store::{FlowEvent, FlowRow, Proto};

        const MIB: i64 = 1024 * 1024;
        const DAY: i64 = 24 * 60 * 60 * 1000;
        const NOW: i64 = 1_791_979_200_000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let mut id = 0;
        let mut sent = |started: i64, bytes_up: i64| {
            id += 1;
            let flow = FlowRow {
                app: Some("org.example.app".to_owned()),
                proto: Proto::Tcp,
                local_ip: "10.215.173.1".to_owned(),
                local_port: 40_000,
                remote_ip: "203.0.113.9".to_owned(),
                remote_port: 443,
                hostname: None,
                hostname_src: None,
                started,
                ended: Some(started + 1_000),
                bytes_up,
                bytes_down: 0,
                bytes_up_away: 0,
                bytes_down_away: 0,
                blocked: false,
            };
            let event = FlowEvent {
                engine_id: id,
                flow,
                destination: None,
            };
            history.store.record_flows(1, &[event]).unwrap();
        };
        sent(NOW - 20 * DAY, 0);
        for days_ago in 2..=14 {
            sent(NOW - days_ago * DAY, MIB);
        }
        sent(NOW - DAY / 2, 12 * MIB);
        let surges = || {
            history
                .store
                .alerts_of(sentinel_detect::Rule::UploadSurge, false)
                .unwrap()
        };

        history.raise_upload_surges(NOW).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::UploadSurge);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
        assert_eq!(
            alerts[0].evidence[1],
            AlertEvidence::UploadSurge {
                last_day: 12 * 1024 * 1024,
                usual_day: 13 * 1024 * 1024 / 14,
                days: 14,
            }
        );
        history.raise_upload_surges(NOW + 60_000).unwrap();
        assert_eq!(surges().len(), 1, "it is open");
        history.dismiss_alert(alerts[0].id).unwrap();
        history.raise_upload_surges(NOW + 60 * 60_000).unwrap();
        assert_eq!(surges().len(), 1, "within a day of the last");

        // Yesterday's surge is now part of the usual days: ten times them is 18 MiB.
        sent(NOW + DAY - DAY / 2, 12 * MIB);
        history.raise_upload_surges(NOW + DAY).unwrap();
        assert_eq!(surges().len(), 1, "no longer ten times the usual day");
        sent(NOW + DAY - DAY / 4, 8 * MIB);
        history.raise_upload_surges(NOW + DAY).unwrap();
        assert_eq!(surges().len(), 2, "the next day's surge");
    }

    /// SRS §12.3: the alerts of a range export through the app's interface, a page at a
    /// time, as one JSON array.
    #[test]
    fn alerts_export_a_page_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        for at in [5, 50] {
            history.open_gap(Some(at), "stopped".into()).unwrap();
            history.close_gap(at + 1).unwrap();
        }
        let first = history
            .export_page(ExportKind::Alerts, ExportFormat::Json, 0, i64::MAX, None, 1)
            .unwrap();
        let next = first.next.expect("a second page");
        let second = history
            .export_page(
                ExportKind::Alerts,
                ExportFormat::Json,
                0,
                i64::MAX,
                Some(next),
                1,
            )
            .unwrap();
        let third = history
            .export_page(
                ExportKind::Alerts,
                ExportFormat::Json,
                0,
                i64::MAX,
                second.next,
                1,
            )
            .unwrap();
        assert_eq!(third.next, None);
        let whole = [first.text, second.text, third.text].concat();
        let alerts: serde_json::Value = serde_json::from_str(&whole).unwrap();
        assert_eq!(alerts.as_array().unwrap().len(), 2, "{whole}");
        assert_eq!(alerts[0]["rule"], "monitoring-interrupted");
    }

    /// SP-03: each new monitoring gap raises one alert, which the user can dismiss.
    #[test]
    fn monitoring_that_keeps_stopping_raises_one_critical_alert() {
        use crate::alerts::{AlertAction, AlertEvidence, AlertRule, AlertSeverity};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let keeps_stopping = |history: &HistoryStore| {
            history
                .alerts(true, 100)
                .unwrap()
                .into_iter()
                .filter(|alert| alert.rule == AlertRule::MonitoringKeepsStopping)
                .collect::<Vec<_>>()
        };
        // Two gaps a day ago, out of the window, and two now: not yet.
        let day = 24 * 60 * 60 * 1000;
        for started in [
            now_ms() - day - 5_000,
            now_ms() - day - 1_000,
            now_ms(),
            now_ms(),
        ] {
            history.open_gap(Some(started), "killed".into()).unwrap();
            history.close_gap(started + 500).unwrap();
        }
        assert!(keeps_stopping(&history).is_empty());
        // The third within a day.
        history.open_gap(None, "killed".into()).unwrap();
        history.close_gap(now_ms()).unwrap();
        let alerts = keeps_stopping(&history);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(
            alerts[0].evidence,
            [AlertEvidence::RepeatedGaps {
                count: 3,
                hours: 24
            }]
        );
        assert_eq!(alerts[0].actions, [AlertAction::OpenKeepRunning]);
        // A fourth while it is open: no second one.
        history.open_gap(None, "killed".into()).unwrap();
        assert_eq!(keeps_stopping(&history).len(), 1);
    }

    #[test]
    fn a_history_started_anew_says_so() {
        use crate::alerts::{AlertRule, AlertSeverity};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        assert!(history.alerts(true, 10).unwrap().is_empty());
        history.started_anew().unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::HistoryStartedAnew);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
        assert!(alerts[0].evidence.is_empty());
        assert!(alerts[0].actions.is_empty());
    }

    #[test]
    fn a_new_gap_raises_one_alert() {
        use crate::alerts::{AlertAction, AlertEvidence, AlertRule, AlertSeverity};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let before = now_ms();
        history.open_gap(Some(5), "revoked".into()).unwrap();
        history.open_gap(Some(6), "again".into()).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1, "the gap was already open");
        let alert = &alerts[0];
        assert_eq!(alert.rule, AlertRule::MonitoringInterrupted);
        assert_eq!(alert.severity, AlertSeverity::Warning);
        assert!((before..=now_ms()).contains(&alert.created_ms));
        assert_eq!(
            alert.evidence,
            [AlertEvidence::Gap {
                started_ms: Some(5),
                reason: "revoked".into()
            }]
        );
        assert_eq!(alert.actions, [AlertAction::StartMonitoring]);
        assert!(alert.open);
        assert_eq!(history.alert(alert.id).unwrap().as_ref(), Some(alert));

        history.close_gap(9).unwrap();
        history.open_gap(None, "killed".into()).unwrap();
        assert_eq!(history.alerts(true, 10).unwrap().len(), 2);

        assert!(history.dismiss_alert(alert.id).unwrap());
        assert!(!history.dismiss_alert(9_999).unwrap());
        let open = history.alerts(true, 10).unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(
            open[0].evidence,
            [AlertEvidence::Gap {
                started_ms: None,
                reason: "killed".into()
            }]
        );
        assert!(!history.alert(alert.id).unwrap().unwrap().open);
        assert_eq!(history.alerts(false, 10).unwrap().len(), 2);
    }

    /// Hears each new alert and, like the app, claims its notification at once: from
    /// inside the call, which must not deadlock.
    struct Notifier {
        history: Mutex<std::sync::Weak<HistoryStore>>,
        do_not_disturb: bool,
        heard: Mutex<Vec<(HistoryAlert, Option<AlertDelivery>)>>,
    }

    impl AlertListener for Notifier {
        fn raised(&self, alert: HistoryAlert) {
            let history = self.history.lock().unwrap().upgrade().unwrap();
            let delivery = history
                .claim_notification(alert.id, self.do_not_disturb)
                .unwrap();
            self.heard.lock().unwrap().push((alert, delivery));
        }
    }

    /// AL-03, AL-04, AL-06: the app hears each new alert; three notifications an hour
    /// pass for the same subject, and Do Not Disturb holds a Warning.
    #[test]
    fn the_app_hears_each_alert_and_notifications_are_limited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let listen = |do_not_disturb: bool| {
            let notifier = Arc::new(Notifier {
                history: Mutex::new(Arc::downgrade(&history)),
                do_not_disturb,
                heard: Mutex::new(Vec::new()),
            });
            history.set_alert_listener(Some(notifier.clone()));
            notifier
        };

        let notifier = listen(false);
        for gap in 0..5 {
            history.open_gap(Some(gap), format!("gap {gap}")).unwrap();
            history.close_gap(gap + 1).unwrap();
        }
        let heard = notifier.heard.lock().unwrap().clone();
        assert_eq!(heard.len(), 5, "one call per new alert");
        let deliveries: Vec<_> = heard.iter().map(|(_, d)| *d).collect();
        assert_eq!(
            deliveries,
            [
                Some(AlertDelivery::Notify),
                Some(AlertDelivery::Notify),
                Some(AlertDelivery::Notify),
                Some(AlertDelivery::HeldForRateLimit),
                Some(AlertDelivery::HeldForRateLimit),
            ]
        );
        let notified = history
            .alerts(false, 10)
            .unwrap()
            .iter()
            .filter(|a| a.notified_ms.is_some())
            .count();
        assert_eq!(notified, 3);

        // Do Not Disturb: the Warning waits in the app.
        let fresh = tempfile::tempdir().unwrap();
        let path = fresh.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let quiet = Arc::new(Notifier {
            history: Mutex::new(Arc::downgrade(&history)),
            do_not_disturb: true,
            heard: Mutex::new(Vec::new()),
        });
        history.set_alert_listener(Some(quiet.clone()));
        history.open_gap(None, "quiet".into()).unwrap();
        assert_eq!(
            quiet.heard.lock().unwrap()[0].1,
            Some(AlertDelivery::HeldForDoNotDisturb)
        );

        // Without a listener nothing is told, and nothing breaks.
        history.set_alert_listener(None);
        history.close_gap(5).unwrap();
        history.open_gap(None, "unheard".into()).unwrap();
        assert_eq!(quiet.heard.lock().unwrap().len(), 1);
        assert_eq!(history.claim_notification(9_999, false).unwrap(), None);
        drop(notifier);
    }

    /// AL-05: allowing an app's alert stops that app's next alerts of the rule, until the
    /// user takes it back, on the alert or from the list of what was allowed; "not
    /// useful" holds the next one's notification. An alert about no app, such as a gap,
    /// cannot be allowed (audit A-08).
    #[test]
    fn feedback_tunes_later_alerts_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let busy = |at: i64| {
            history
                .raise(&sentinel_detect::flow_limit(at, "org.example.app", 512))
                .unwrap();
        };
        let open_count = || history.alerts(true, 10).unwrap().len();

        busy(0);
        let first = history.alerts(true, 10).unwrap()[0].clone();
        assert!(first.can_allow);
        assert!(
            history
                .set_feedback(first.id, Some(AlertFeedback::Allowed))
                .unwrap()
        );
        assert_eq!(open_count(), 0, "allowing dismisses it");
        assert_eq!(
            history.alert(first.id).unwrap().unwrap().feedback,
            Some(AlertFeedback::Allowed)
        );
        let allowed = history.allowed().unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].rule, AlertRule::FlowLimit);
        assert_eq!(allowed[0].app, "org.example.app");
        busy(10);
        assert_eq!(history.alerts(false, 10).unwrap().len(), 1, "no new alert");

        history.set_feedback(first.id, None).unwrap();
        assert!(history.allowed().unwrap().is_empty());
        busy(20);
        assert_eq!(open_count(), 1, "alerts again after taking it back");

        // Taken back from the list of what was allowed.
        let second = history.alerts(true, 10).unwrap()[0].id;
        history
            .set_feedback(second, Some(AlertFeedback::Allowed))
            .unwrap();
        assert!(
            history
                .take_back_allowed(AlertRule::FlowLimit, "org.example.app".into())
                .unwrap()
        );
        assert_eq!(history.alert(second).unwrap().unwrap().feedback, None);
        busy(30);
        assert_eq!(
            open_count(),
            1,
            "alerts again after taking it back from the list"
        );

        // A gap names no app: allowing it would silence gaps for good. It can be marked
        // not useful, which holds the next one's notification.
        history.open_gap(Some(40), "r".into()).unwrap();
        history.close_gap(41).unwrap();
        let gap = history
            .alerts(true, 10)
            .unwrap()
            .into_iter()
            .find(|alert| alert.rule == AlertRule::MonitoringInterrupted)
            .unwrap();
        assert!(!gap.can_allow);
        assert!(matches!(
            history.set_feedback(gap.id, Some(AlertFeedback::Allowed)),
            Err(HistoryError::Failed { .. })
        ));
        history
            .set_feedback(gap.id, Some(AlertFeedback::NotUseful))
            .unwrap();
        history.open_gap(Some(50), "r".into()).unwrap();
        let next = history.alerts(true, 10).unwrap()[0].id;
        assert_eq!(
            history.claim_notification(next, false).unwrap(),
            Some(AlertDelivery::HeldForFeedback)
        );
        assert!(!history.set_feedback(9_999, None).unwrap());
    }

    /// CM-07: each change of the network settings raises one Warning alert offering
    /// the network settings, also when it happened while Sentinel was not running; the
    /// first state seen raises nothing. A change names no app, so it cannot be allowed
    /// (audit A-08).
    #[test]
    fn network_setting_changes_raise_alerts() {
        use crate::alerts::{AlertAction, AlertEvidence, AlertRule, AlertSeverity};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path.clone(), vec![1; 32]).unwrap();
        let home = NetworkState {
            network: Some("3:100".into()),
            dns_servers: vec!["192.168.1.1".into()],
            private_dns: None,
            network_proxy: None,
            proxy: None,
        };
        assert_eq!(history.last_network_state().unwrap(), None);
        history.network_seen(home.clone()).unwrap();
        history.network_seen(home.clone()).unwrap();
        assert!(
            history.alerts(false, 10).unwrap().is_empty(),
            "first and same"
        );
        assert_eq!(history.last_network_state().unwrap(), Some(home.clone()));

        let proxied = NetworkState {
            proxy: Some("192.0.2.10:3128".into()),
            ..home.clone()
        };
        history.network_seen(proxied.clone()).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::ProxyChanged);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
        assert_eq!(
            alerts[0].evidence,
            [AlertEvidence::Proxy {
                before: None,
                after: Some("192.0.2.10:3128".into())
            }]
        );
        assert_eq!(alerts[0].actions, [AlertAction::OpenNetworkSettings]);

        // It cannot be allowed: the next proxy change raises an alert again.
        assert!(
            history
                .set_feedback(alerts[0].id, Some(AlertFeedback::Allowed))
                .is_err()
        );
        history.network_seen(home.clone()).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 2);
        for alert in alerts {
            history.dismiss_alert(alert.id).unwrap();
        }

        // Changed while Sentinel was not running: found when it runs again.
        drop(history);
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let private = NetworkState {
            private_dns: Some("dns.example".into()),
            ..home
        };
        history.network_seen(private).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::PrivateDnsChanged);
        assert_eq!(
            alerts[0].evidence,
            [AlertEvidence::PrivateDns {
                before: None,
                after: Some("dns.example".into())
            }]
        );
    }

    /// RA-01, CM-08: what the app detail screen shows about an app as a whole: the rule
    /// about it, and whether Block-unknown keeps it off as new. Rules about some of its
    /// destinations are not about the app as a whole.
    #[test]
    fn an_apps_access_says_why_it_is_blocked() {
        use crate::firewall::{AppAccess, FirewallMode, FirewallRule, RuleAction, RuleDestination};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let app = || "org.example.chat".to_owned();
        let open = AppAccess {
            rule: None,
            blocked_as_new: false,
        };
        let later = Some(now_ms() + 60_000);
        assert_eq!(history.app_access(app(), later), open);
        history
            .set_firewall_mode(FirewallMode::BlockUnknown)
            .unwrap();
        assert_eq!(
            history.app_access(app(), later),
            AppAccess {
                rule: None,
                blocked_as_new: true
            }
        );
        assert_eq!(history.app_access(app(), Some(0)), open, "installed before");
        let rule = |destination, action| FirewallRule {
            app: Some(app()),
            destination,
            action,
        };
        history
            .set_firewall_rule(
                rule(
                    Some(RuleDestination::Domain {
                        name: "chat.example".into(),
                    }),
                    RuleAction::Allow,
                ),
                None,
            )
            .unwrap();
        assert!(
            history.app_access(app(), later).blocked_as_new,
            "a place is not the app"
        );
        for action in [RuleAction::Allow, RuleAction::Block] {
            history.set_firewall_rule(rule(None, action), None).unwrap();
            assert_eq!(
                history.app_access(app(), later),
                AppAccess {
                    rule: Some(action),
                    blocked_as_new: false
                }
            );
        }
    }

    /// CM-10: rules are checked when kept, listed newest first, replaced by key and
    /// removed; they survive reopening.
    #[test]
    fn firewall_rules_are_kept_checked_and_replaced() {
        use crate::firewall::{FirewallRule, RuleAction, RuleDestination};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path.clone(), vec![1; 32]).unwrap();
        let block_range = FirewallRule {
            app: None,
            destination: Some(RuleDestination::Network {
                range: "192.0.2.0/24".into(),
            }),
            action: RuleAction::Block,
        };
        let key = history
            .set_firewall_rule(block_range.clone(), None)
            .unwrap();
        assert_eq!(key, "* network:192.0.2.0/24");
        let allow_range = FirewallRule {
            action: RuleAction::Allow,
            ..block_range.clone()
        };
        assert_eq!(
            history
                .set_firewall_rule(allow_range.clone(), None)
                .unwrap(),
            key
        );
        let named = FirewallRule {
            app: Some("org.example.chat".into()),
            destination: Some(RuleDestination::Domain {
                name: "Ads.Example.".into(),
            }),
            action: RuleAction::Block,
        };
        history.set_firewall_rule(named, None).unwrap();
        let rules = history.firewall_rules().unwrap();
        assert_eq!(rules.len(), 2);
        let by_key = |key: &str| rules.iter().find(|r| r.key == key).unwrap().rule.clone();
        assert_eq!(
            by_key("org.example.chat domain:ads.example").destination,
            Some(RuleDestination::Domain {
                name: "ads.example".into()
            }),
            "stored as matched: lower case, no trailing dot"
        );
        assert_eq!(by_key(&key), allow_range);

        for bad in [
            FirewallRule {
                app: None,
                destination: None,
                action: RuleAction::Block,
            },
            FirewallRule {
                app: None,
                destination: Some(RuleDestination::Domain {
                    name: "not a name".into(),
                }),
                action: RuleAction::Block,
            },
            FirewallRule {
                app: None,
                destination: Some(RuleDestination::Network {
                    range: "192.0.2.1/24".into(),
                }),
                action: RuleAction::Block,
            },
        ] {
            assert!(matches!(
                history.set_firewall_rule(bad, None),
                Err(HistoryError::BadRule { .. })
            ));
        }

        drop(history);
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        assert_eq!(history.firewall_rules().unwrap().len(), 2);
        assert!(history.remove_firewall_rule(key.clone()).unwrap());
        assert!(!history.remove_firewall_rule(key).unwrap());
        assert_eq!(history.firewall_rules().unwrap().len(), 1);
    }

    /// SRS §9: each change the user makes to the firewall is journalled, with the alert
    /// it was taken from; undoing it puts the setting back for the engine at once, and
    /// running engines decide their open connections again.
    #[test]
    fn each_action_is_journalled_and_undone_at_once() {
        use crate::firewall::{FirewallMode, FirewallRule, RuleAction};
        use crate::journal::{JournalState, UndoResult};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path.clone(), vec![1; 32]).unwrap();
        assert!(history.journal(10).unwrap().is_empty());
        history.open_gap(None, "killed".into()).unwrap();
        let alert = history.alerts(true, 1).unwrap()[0].id;
        let app = "org.example.chat";
        let blocked = || {
            history
                .rule_set()
                .decide(Some(app), Place::default())
                .is_some()
        };

        let block = FirewallRule {
            app: Some(app.into()),
            destination: None,
            action: RuleAction::Block,
        };
        let key = history
            .set_firewall_rule(block.clone(), Some(alert))
            .unwrap();
        let entry = history.journal(10).unwrap().remove(0);
        assert_eq!(entry.alert_id, Some(alert));
        assert_eq!(
            (entry.before, entry.after),
            (
                JournalState::Rule {
                    key: key.clone(),
                    rule: None
                },
                JournalState::Rule {
                    key,
                    rule: Some(block)
                }
            )
        );
        assert!(entry.can_undo && entry.undone_ms.is_none());
        assert!(blocked());
        let mut changes = history.firewall_changes();
        changes.mark_unchanged();
        assert_eq!(history.undo_action(entry.id).unwrap(), UndoResult::Undone);
        assert!(!blocked(), "in force at once");
        assert!(
            changes.has_changed().unwrap(),
            "open connections are asked again"
        );
        assert_eq!(
            history.undo_action(entry.id).unwrap(),
            UndoResult::AlreadyUndone
        );
        let entry = history.journal(1).unwrap().remove(0);
        assert!(!entry.can_undo && entry.undone_ms.is_some());

        history
            .set_firewall_mode(FirewallMode::BlockUnknown)
            .unwrap();
        let since = match history.mode_in_force() {
            Mode::BlockUnknown { since } => since,
            Mode::Monitor => panic!("not switched"),
        };
        let switched = history.journal(1).unwrap().remove(0);
        assert_eq!(
            switched.after,
            JournalState::Mode {
                mode: FirewallMode::BlockUnknown,
                since_ms: Some(since)
            }
        );
        assert_eq!(
            history.undo_action(switched.id).unwrap(),
            UndoResult::Undone
        );
        assert_eq!(history.mode_in_force(), Mode::Monitor);

        history
            .isolate("io.github.malekhasan.sentinel".into())
            .unwrap();
        let began = history.isolated_since_ms().unwrap();
        history.end_isolation().unwrap();
        let ended = history.journal(1).unwrap().remove(0);
        assert_eq!(
            (ended.before, ended.after),
            (
                JournalState::Isolation {
                    since_ms: Some(began)
                },
                JournalState::Isolation { since_ms: None }
            )
        );
        assert_eq!(history.undo_action(ended.id).unwrap(), UndoResult::Undone);
        assert_eq!(history.isolated_since_ms(), Some(began), "since it began");
        assert!(history.isolation_in_force().is_some());
        assert_eq!(history.undo_action(9_999).unwrap(), UndoResult::CannotUndo);

        drop(history);
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        assert_eq!(history.journal(10).unwrap().len(), 4);
        assert_eq!(history.isolated_since_ms(), Some(began));
    }
}

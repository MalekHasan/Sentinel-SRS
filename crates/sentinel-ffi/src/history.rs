// SPDX-License-Identifier: GPL-3.0-or-later
//! The encrypted local history (SRS §13), as seen from Kotlin.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use sentinel_store::{KEY_LEN, Store, StoreError};

use crate::alerts::{AlertDelivery, AlertFeedback, AlertListener, AllowedRule, HistoryAlert};
use crate::enrich::{CategoryFact, CompanyFact};
use crate::flows::{FlowProto, NameSource};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum HistoryError {
    #[error("the key must be {expected} bytes")]
    BadKey { expected: u32 },
    /// The key does not open the database: it was replaced, or the file is damaged.
    #[error("the history cannot be opened with this key")]
    WrongKey,
    #[error("the history failed: {reason}")]
    Failed { reason: String },
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
}

#[uniffi::export]
impl HistoryStore {
    /// Open or create the history at `path` with a random 32-byte key (on Android,
    /// unwrapped with a Keystore key; see ADR-0009).
    #[uniffi::constructor]
    pub fn open(path: String, key: Vec<u8>) -> Result<Arc<Self>, HistoryError> {
        let key: [u8; KEY_LEN] = key.try_into().map_err(|_| HistoryError::BadKey {
            expected: KEY_LEN as u32,
        })?;
        let store = Store::open(Path::new(&path), &key)?;
        Ok(Arc::new(HistoryStore {
            store,
            alert_listener: Mutex::new(None),
        }))
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

    /// Start a monitoring gap, unless one is already open. `started_ms` is `None` when
    /// the start is unknown. A new gap raises an alert (SP-03).
    pub fn open_gap(&self, started_ms: Option<i64>, reason: String) -> Result<(), HistoryError> {
        if self.store.open_gap(started_ms, &reason)? {
            let alert = sentinel_detect::monitoring_interrupted(now_ms(), started_ms, &reason);
            self.raise(&alert)?;
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

    /// Everything the user allowed, newest first.
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

    /// Roll flows older than `keep_days` into daily totals (SRS §13.2). Returns how
    /// many flows were rolled up.
    pub fn apply_retention(&self, now_ms: i64, keep_days: u32) -> Result<u64, HistoryError> {
        Ok(self.store.apply_retention(now_ms, keep_days)? as u64)
    }
}

/// Delete the history database at `path` (one-tap wipe, SRS §13.2). Close every
/// `HistoryStore` on it first; the app deletes the key.
#[uniffi::export]
pub fn wipe_history(path: String) -> Result<(), HistoryError> {
    Ok(sentinel_store::wipe(Path::new(&path))?)
}

impl HistoryStore {
    /// Keep a new alert and tell the listener, if any, unless the user allowed what it
    /// is about (AL-05). The listener is called without any lock held, so it may read
    /// the history.
    pub(crate) fn raise(&self, alert: &sentinel_detect::Alert) -> Result<(), HistoryError> {
        self.raise_or_join(alert, None)
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
        wipe_history(path).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// SP-03: each new monitoring gap raises one alert, which the user can dismiss.
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

    /// AL-05: allowing a gap alert stops the next gaps from raising alerts, until the
    /// user takes it back; "not useful" holds the next one's notification.
    #[test]
    fn feedback_tunes_later_alerts_only() {
        use crate::alerts::AlertRule;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db").to_string_lossy().into_owned();
        let history = HistoryStore::open(path, vec![1; 32]).unwrap();
        let gap = |at: i64| {
            history.open_gap(Some(at), "r".into()).unwrap();
            history.close_gap(at + 1).unwrap();
        };
        let open_count = || history.alerts(true, 10).unwrap().len();

        gap(0);
        let first = history.alerts(true, 10).unwrap()[0].id;
        assert!(
            history
                .set_feedback(first, Some(AlertFeedback::Allowed))
                .unwrap()
        );
        assert_eq!(open_count(), 0, "allowing dismisses it");
        assert_eq!(
            history.alert(first).unwrap().unwrap().feedback,
            Some(AlertFeedback::Allowed)
        );
        assert_eq!(
            history.allowed().unwrap()[0].rule,
            AlertRule::MonitoringInterrupted
        );
        assert_eq!(history.allowed().unwrap()[0].app, None);
        gap(10);
        assert_eq!(history.alerts(false, 10).unwrap().len(), 1, "no new alert");

        history.set_feedback(first, None).unwrap();
        assert!(history.allowed().unwrap().is_empty());
        gap(20);
        assert_eq!(open_count(), 1, "alerts again after taking it back");

        let second = history.alerts(true, 10).unwrap()[0].id;
        history
            .set_feedback(second, Some(AlertFeedback::NotUseful))
            .unwrap();
        gap(30);
        let third = history.alerts(true, 10).unwrap()[0].id;
        assert_eq!(
            history.claim_notification(third, false).unwrap(),
            Some(AlertDelivery::HeldForFeedback)
        );
        assert!(!history.set_feedback(9_999, None).unwrap());
    }
}

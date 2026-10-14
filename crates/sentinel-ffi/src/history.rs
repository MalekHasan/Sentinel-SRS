// SPDX-License-Identifier: GPL-3.0-or-later
//! The encrypted local history (SRS §13), as seen from Kotlin.

use std::path::Path;
use std::sync::Arc;

use sentinel_store::{KEY_LEN, Store, StoreError};

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
        Ok(Arc::new(HistoryStore { store }))
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

    /// Start a monitoring gap, unless one is already open. `started_ms` is `None` when
    /// the start is unknown.
    pub fn open_gap(&self, started_ms: Option<i64>, reason: String) -> Result<(), HistoryError> {
        Ok(self.store.open_gap(started_ms, &reason)?)
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
}

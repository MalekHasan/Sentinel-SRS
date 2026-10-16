// SPDX-License-Identifier: GPL-3.0-or-later
//! Sentinel's local history in an encrypted SQLite database (SQLCipher), following the
//! schema in SRS §13. The same crate serves every edition; only the key storage is
//! platform-specific (on Android, a Keystore-wrapped key; see ADR-0009).
//!
//! The history is itself sensitive (THREAT-MODEL-A I3, I4): it never leaves the device,
//! the file is encrypted with a random 256-bit key, and [`wipe`] deletes it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_detect::{
    Access, Alert, AlertState, Attribution, Change, Delivery, Feedback, FirewallMode, FirewallRule,
    Isolation, NetworkState, Posture, Rule, Sensor, Sent, Setting, Severity,
};
use zeroize::Zeroizing;

mod schema;

/// A flow as the engine reports it, when it starts and again when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvent {
    /// The engine's id for the flow, unique within one engine session.
    pub engine_id: u64,
    pub flow: FlowRow,
    /// What is known about the destination, if anything.
    pub destination: Option<DestinationFacts>,
}

/// What is known about a destination and where each answer comes from: SRS §13.1
/// `destination`, and "why we believe this" (DT-02).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationFacts {
    /// The network (autonomous system) the destination's address belongs to.
    pub asn: Option<u32>,
    pub network_owner: Option<String>,
    /// Where the network and its owner come from, for example "IPtoASN 2026-10-15".
    pub network_source: Option<String>,
    /// Approximate country, ISO 3166 two letters.
    pub country: Option<String>,
    pub country_source: Option<String>,
    /// The company the destination belongs to, from the tracker lists (DT-06).
    pub company: Option<Listed<String>>,
    /// What kind of service it is, from the tracker lists: for example "Advertising",
    /// "Analytics" or "CDN".
    pub categories: Option<Listed<Vec<String>>>,
}

/// An answer from the tracker lists, and why we believe it (DT-02, DT-06). Texts are
/// single lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed<T> {
    pub value: T,
    /// The listed domain the answer comes from: the destination itself or a domain
    /// above it.
    pub domain: String,
    /// The lists that say so, with their dates.
    pub sources: Vec<String>,
}

/// Something a batch of flows showed for the first time (CM-04, ADR-0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstSeen {
    /// The history's first connection by `app`, to `destination`: its name, or its
    /// address if no name was known when it started. `blocked` when the firewall
    /// refused it.
    App {
        app: String,
        destination: String,
        blocked: bool,
    },
    /// `app`'s first connection to the name `destination`. Judged when the connection
    /// ends, by the name it ended with: a name learned from the TLS handshake replaces
    /// one from DNS. `app_first_seen` is when the history first saw the app.
    Destination {
        app: String,
        app_first_seen: i64,
        destination: String,
    },
}

/// A flow read back from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFlow {
    pub id: i64,
    pub flow: FlowRow,
}

/// One flow (SRS §13 `flow`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    /// The app that owns the flow: a package name on Android, a path on desktops.
    pub app: Option<String>,
    pub proto: Proto,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub hostname: Option<String>,
    pub hostname_src: Option<HostnameSource>,
    /// Unix milliseconds.
    pub started: i64,
    /// `None` while the flow is open.
    pub ended: Option<i64>,
    pub bytes_up: i64,
    pub bytes_down: i64,
    /// Of the above, the bytes carried while the user was away (SRS CM-06).
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
    pub blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSource {
    Dns,
    Sni,
}

/// A time when monitoring was wanted but not running (SRS SP-03, NF-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// `None` if the start is unknown.
    pub started: Option<i64>,
    /// `None` while the gap is open.
    pub ended: Option<i64>,
    pub reason: String,
}

/// One use of the microphone or camera (SE-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorUse {
    pub id: i64,
    pub sensor: Sensor,
    pub started: i64,
    /// `None` while in use.
    pub ended: Option<i64>,
    /// The app, as `attribution` found it; `None` when unknown.
    pub app: Option<String>,
    pub attribution: Attribution,
    /// False once the screen was off or locked during the use (SE-04).
    pub user_present: bool,
}

/// Connections the history holds from one app to one name or address (MS-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastDestination {
    /// Package name; `None` when the owner was unknown.
    pub app: Option<String>,
    /// The name the connections were known by, if any.
    pub name: Option<String>,
    /// Their remote address. `None` for rolled-up days of named connections, which keep
    /// only the name.
    pub address: Option<String>,
    /// When the first was made and the last ended, Unix milliseconds.
    pub first: i64,
    pub last: i64,
    pub connections: u64,
}

/// Daily totals that replace flows older than the retention period (SRS §13.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyTotal {
    /// Days since the Unix epoch, UTC.
    pub day: i64,
    pub app: Option<String>,
    /// Hostname if known, otherwise the remote address.
    pub destination: String,
    pub proto: Proto,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
}

/// What the history holds about one app: the app detail screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSummary {
    pub app: String,
    /// When the app was first seen using the network, Unix milliseconds. A wipe resets
    /// it.
    pub first_seen: i64,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    /// Of the above, the bytes carried while the user was away (CM-06).
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
    /// Destinations in the whole history, including those beyond the limit asked for.
    pub destination_count: u32,
    /// Most data sent first.
    pub destinations: Vec<DestinationTotal>,
    /// The companies all of its destinations belong to, as far as the tracker lists
    /// know, most data sent first (DT-06).
    pub companies: Vec<CompanyTotal>,
}

/// One app's traffic to one company's destinations (DT-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyTotal {
    pub company: String,
    /// The categories of those destinations, as first seen.
    pub categories: Vec<String>,
    pub destinations: u32,
    pub bytes_up: i64,
    pub bytes_down: i64,
}

/// One app's traffic to one destination, over the whole history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationTotal {
    /// Hostname if known, otherwise the remote address.
    pub destination: String,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
    /// How the destination's name was learned, for the strongest name seen: the TLS
    /// server name over a DNS answer. `None` for a bare address or rolled-up days.
    pub name_source: Option<HostnameSource>,
    /// The latest facts recorded for the destination.
    pub facts: DestinationFacts,
    /// Unix milliseconds. Flows already rolled up into daily totals keep only their
    /// day, so they count from the start of that day (UTC).
    pub first_seen: i64,
    pub last_seen: i64,
}

/// An alert as stored (SRS §13.1 `alert`), with its row id and state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAlert {
    pub id: i64,
    pub alert: Alert,
    pub state: AlertState,
    /// When a notification was posted for it, Unix milliseconds; `None` if it was kept
    /// in the app only (AL-03, AL-04).
    pub notified: Option<i64>,
    /// What the user said about it (AL-05).
    pub feedback: Option<Feedback>,
}

/// A rule the user allowed for an app, or for Sentinel itself (AL-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedEntry {
    pub rule: Rule,
    /// `None` for alerts about Sentinel itself.
    pub app: Option<String>,
    /// Unix milliseconds.
    pub created: i64,
}

/// One action in the journal (SRS §9): who took it and when, what it changed, and
/// whether it was undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub id: i64,
    /// The alert it was taken from, if any.
    pub alert: Option<i64>,
    /// Who took it: on Android, always the user.
    pub actor: String,
    pub change: Change,
    /// Unix milliseconds.
    pub at: i64,
    pub undone_at: Option<i64>,
    /// Whether [`Store::undo`] would undo it now: it was not undone yet, and its setting
    /// is still as it left it.
    pub can_undo: bool,
}

/// What [`Store::undo`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Undo {
    /// The setting is back as it was before the action.
    Undone,
    /// It was undone before; nothing changed.
    AlreadyUndone,
    /// Something changed the setting since the action; it was left alone.
    ChangedSince,
    /// The action cannot be undone, or this version cannot read it.
    CannotUndo,
    /// The journal has no such action.
    NotFound,
}

/// A firewall rule as stored (CM-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRule {
    /// What the rule is about ([`FirewallRule::key`]); a new rule with the same key
    /// replaces it.
    pub key: String,
    pub rule: FirewallRule,
    /// When it was made or last changed, Unix milliseconds.
    pub created: i64,
}

/// One app's traffic while the user was away (SRS CM-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwayTotal {
    /// `None` for connections whose owner is unknown.
    pub app: Option<String>,
    /// Connections that carried data while the user was away.
    pub flows: i64,
    pub bytes_up_away: i64,
    pub bytes_down_away: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The key does not open this database, or the file is not a Sentinel database.
    #[error("the database cannot be opened with this key")]
    WrongKey,
    #[error("the database was written by a newer version of Sentinel (schema {0})")]
    TooNew(i64),
    /// An alert row this version cannot read: an unknown rule, severity or state, or
    /// evidence that is not the stored format.
    #[error("alert {0} cannot be read")]
    BadAlert(i64),
    /// Feedback that this alert cannot take, such as allowing a Critical alert.
    #[error("alert {0} cannot take this feedback")]
    FeedbackNotAllowed(i64),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub const KEY_LEN: usize = 32;
const PLATFORM: &str = "android";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

pub struct Store {
    conn: Mutex<Connection>,
    /// Database rows of flows that have started and not ended, by (session, engine id).
    open_flows: Mutex<HashMap<(u64, u64), i64>>,
    /// When this history began, Unix milliseconds.
    began: i64,
}

impl Store {
    /// Open or create the database at `path` with a raw 256-bit key.
    ///
    /// The key is random, so SQLCipher's password-stretching step is skipped (raw key
    /// syntax); this keeps opening fast without weakening anything.
    pub fn open(path: &Path, key: &[u8; KEY_LEN]) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::with_connection(conn, key)
    }

    fn with_connection(conn: Connection, key: &[u8; KEY_LEN]) -> Result<Self> {
        let mut hex = Zeroizing::new(String::with_capacity(KEY_LEN * 2 + 3));
        hex.push_str("x'");
        for byte in key {
            hex.push_str(&format!("{byte:02X}"));
        }
        hex.push('\'');
        conn.pragma_update(None, "key", hex.as_str())?;
        // The first real read fails if the key is wrong or the file is not ours.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| StoreError::WrongKey)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&conn)?;
        let began = conn.query_row("SELECT value FROM meta WHERE key = 'began'", [], |r| {
            r.get(0)
        })?;
        Ok(Store {
            conn: Mutex::new(conn),
            open_flows: Mutex::new(HashMap::new()),
            began,
        })
    }

    /// When this history began, Unix milliseconds: when it was created (after a wipe,
    /// the wipe), or upgraded to the version that keeps this. Only apps installed since
    /// then can be new to the network (CM-04).
    pub fn began(&self) -> i64 {
        self.began
    }

    /// The version of the indicator list the history was last checked against (MS-02),
    /// if any.
    pub fn hunted(&self) -> Result<Option<u64>> {
        let value: Option<i64> = lock(&self.conn)
            .query_row("SELECT value FROM meta WHERE key = 'hunted'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(value.and_then(|v| u64::try_from(v).ok()))
    }

    /// Note that the history was checked against version `version` of the indicator list.
    pub fn set_hunted(&self, version: u64) -> Result<()> {
        lock(&self.conn).execute(
            "INSERT INTO meta (key, value) VALUES ('hunted', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [i64::try_from(version).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    /// Every app, name and address the history holds connections to, with when they
    /// were first and last made and how many: to check against indicators that arrived
    /// later (MS-02). Flows still kept give both the name and the address. Older days,
    /// rolled up, give the name, or the address of connections that had none (SRS
    /// §13.2), and midnight UTC of their day.
    pub fn past_destinations(&self) -> Result<Vec<PastDestination>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT a.identifier, g.hostname, g.address, g.daily, min(g.first), max(g.last),
                    sum(g.n)
             FROM (
                 SELECT app_id, hostname, remote_ip AS address, 0 AS daily, started AS first,
                        coalesce(ended, started) AS last, 1 AS n
                 FROM flow
                 UNION ALL
                 SELECT nullif(app_id, 0), destination, NULL, 1, day * ?1, day * ?1, flows
                 FROM flow_daily
             ) g
             LEFT JOIN app a ON a.id = g.app_id
             GROUP BY g.app_id, g.hostname, g.address, g.daily
             ORDER BY min(g.first)",
        )?;
        let rows = stmt
            .query_map([DAY_MS], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .map(|(app, name, address, daily, first, last, n)| {
                // A day's destination is its name, or its address when it had none.
                let (name, address) = match name {
                    Some(d) if daily && d.parse::<std::net::IpAddr>().is_ok() => (None, Some(d)),
                    name => (name, address),
                };
                PastDestination {
                    app,
                    name,
                    address,
                    first,
                    last,
                    connections: u64::try_from(n).unwrap_or(0),
                }
            })
            .collect())
    }

    /// Record flows from engine session `session`. A flow arrives once when it starts
    /// and once when it ends; both are stored in one row. An end whose start was not
    /// seen is stored as a complete row.
    ///
    /// Returns what the flows showed for the first time, in order (CM-04).
    pub fn record_flows(&self, session: u64, events: &[FlowEvent]) -> Result<Vec<FirstSeen>> {
        let mut conn = lock(&self.conn);
        let mut open = lock(&self.open_flows);
        let tx = conn.transaction()?;
        let mut first_seen = Vec::new();
        for FlowEvent {
            engine_id,
            flow: row,
            destination,
        } in events
        {
            if let Some(facts) = destination {
                record_destination(&tx, row, facts)?;
            }
            let key = (session, *engine_id);
            let existing = if row.ended.is_some() {
                open.remove(&key)
            } else {
                open.get(&key).copied()
            };
            match existing {
                Some(id) => update_flow(&tx, id, row)?,
                None => {
                    let (id, new_app) = insert_flow(&tx, row)?;
                    if let (true, Some(app)) = (new_app, &row.app) {
                        first_seen.push(FirstSeen::App {
                            app: app.clone(),
                            destination: row.hostname.clone().unwrap_or(row.remote_ip.clone()),
                            blocked: row.blocked,
                        });
                    }
                    if row.ended.is_none() {
                        open.insert(key, id);
                    }
                }
            }
            if row.ended.is_some() {
                first_seen.extend(first_destination(&tx, row)?);
            }
        }
        tx.commit()?;
        Ok(first_seen)
    }

    /// The most recent flows, newest first.
    pub fn recent_flows(&self, limit: u32) -> Result<Vec<StoredFlow>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT f.id, a.identifier, f.proto, f.local_ip, f.local_port, f.remote_ip,
                    f.remote_port, f.hostname, f.hostname_src, f.started, f.ended,
                    f.bytes_up, f.bytes_down, f.verdict, f.away_up, f.away_down
             FROM flow f LEFT JOIN app a ON a.id = f.app_id
             ORDER BY f.started DESC, f.id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            let flow = FlowRow {
                app: r.get(1)?,
                proto: proto_from(&r.get::<_, String>(2)?),
                local_ip: r.get(3)?,
                local_port: r.get(4)?,
                remote_ip: r.get(5)?,
                remote_port: r.get(6)?,
                hostname: r.get(7)?,
                hostname_src: r
                    .get::<_, Option<String>>(8)?
                    .map(|s| hostname_src_from(&s)),
                started: r.get(9)?,
                ended: r.get(10)?,
                bytes_up: r.get(11)?,
                bytes_down: r.get(12)?,
                bytes_up_away: r.get(14)?,
                bytes_down_away: r.get(15)?,
                blocked: r.get::<_, String>(13)? == "blocked",
            };
            Ok(StoredFlow {
                id: r.get(0)?,
                flow,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Start a gap, unless one is already open. Returns whether it started one.
    pub fn open_gap(&self, started: Option<i64>, reason: &str) -> Result<bool> {
        let conn = lock(&self.conn);
        let open: Option<i64> = conn
            .query_row(
                "SELECT id FROM monitoring_gap WHERE ended IS NULL LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if open.is_none() {
            conn.execute(
                "INSERT INTO monitoring_gap (started, reason) VALUES (?1, ?2)",
                params![started, reason],
            )?;
        }
        Ok(open.is_none())
    }

    /// Keep an alert, open. Returns its id. Its text is not stored: the app writes it
    /// from the rule and the evidence (ADR-0012).
    pub fn record_alert(&self, alert: &Alert) -> Result<i64> {
        let conn = lock(&self.conn);
        conn.execute(
            "INSERT INTO alert (rule_id, severity, evidence, created, state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                alert.rule.id(),
                alert.severity.as_str(),
                sentinel_detect::evidence_to_json(&alert.evidence),
                alert.created,
                AlertState::Open.as_str(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Add a new alert's destinations to the newest open alert of the same rule about
    /// the same app raised at or after `since`, rather than keeping a second alert
    /// (CM-04). Returns that alert's id, or `None` if there is none.
    pub fn join_open_alert(&self, alert: &Alert, since: i64) -> Result<Option<i64>> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare(&format!(
            "{ALERT_COLUMNS} WHERE rule_id = ?1 AND state = 'open' AND created >= ?2
             ORDER BY created DESC, id DESC"
        ))?;
        let rows = stmt
            .query_map(params![alert.rule.id(), since], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for row in rows {
            let mut open = stored_alert(row)?;
            if open.alert.app() != alert.app() {
                continue;
            }
            sentinel_detect::join_destinations(&mut open.alert.evidence, &alert.evidence);
            tx.execute(
                "UPDATE alert SET evidence = ?2 WHERE id = ?1",
                params![
                    open.id,
                    sentinel_detect::evidence_to_json(&open.alert.evidence)
                ],
            )?;
            tx.commit()?;
            return Ok(Some(open.id));
        }
        Ok(None)
    }

    /// The most recent alerts, newest first: only the open ones, or all of them.
    pub fn alerts(&self, open_only: bool, limit: u32) -> Result<Vec<StoredAlert>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(&format!(
            "{ALERT_COLUMNS} WHERE ?1 = 0 OR state = 'open' ORDER BY created DESC, id DESC
             LIMIT ?2"
        ))?;
        let rows = stmt
            .query_map(params![open_only, limit], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(stored_alert).collect()
    }

    /// The alerts raised by `rule`, newest first: only the open ones, or all of them.
    pub fn alerts_of(&self, rule: Rule, open_only: bool) -> Result<Vec<StoredAlert>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(&format!(
            "{ALERT_COLUMNS} WHERE rule_id = ?1 AND (?2 = 0 OR state = 'open')
             ORDER BY created DESC, id DESC"
        ))?;
        let rows = stmt
            .query_map(params![rule.id(), open_only], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(stored_alert).collect()
    }

    /// How many alerts `rule` raised that the history still keeps, open or dismissed.
    pub fn count_alerts(&self, rule: Rule) -> Result<u64> {
        let count: i64 = lock(&self.conn).query_row(
            "SELECT count(*) FROM alert WHERE rule_id = ?1",
            [rule.id()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// One alert, if there is one with this id.
    pub fn alert(&self, id: i64) -> Result<Option<StoredAlert>> {
        let row = lock(&self.conn)
            .query_row(&format!("{ALERT_COLUMNS} WHERE id = ?1"), [id], alert_row)
            .optional()?;
        row.map(stored_alert).transpose()
    }

    /// Decide whether alert `id` is notified now (AL-03, AL-04), and if so record that it
    /// was, in one step so that two callers cannot both pass the rate limit. An alert
    /// already notified stays notified. `None` if there is no alert with this id.
    pub fn claim_notification(
        &self,
        id: i64,
        now: i64,
        do_not_disturb: bool,
    ) -> Result<Option<Delivery>> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let Some(row) = tx
            .query_row(&format!("{ALERT_COLUMNS} WHERE id = ?1"), [id], alert_row)
            .optional()?
        else {
            return Ok(None);
        };
        let stored = stored_alert(row)?;
        if stored.notified.is_some() {
            return Ok(Some(Delivery::Notify));
        }
        let since = now.saturating_sub(sentinel_detect::RATE_WINDOW_MS);
        let mut stmt = tx.prepare(&format!("{ALERT_COLUMNS} WHERE notified > ?1"))?;
        let sent = stmt
            .query_map([since], alert_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|row| {
                stored_alert(row).map(|s| Sent {
                    at: s.notified.unwrap_or_default(),
                    severity: s.alert.severity,
                    app: s.alert.app().map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        drop(stmt);
        let not_useful = marked_not_useful(&tx, &stored.alert)?;
        let delivery =
            sentinel_detect::delivery(&stored.alert, now, do_not_disturb, &sent, not_useful);
        if delivery == Delivery::Notify {
            tx.execute(
                "UPDATE alert SET notified = ?2 WHERE id = ?1",
                params![id, now],
            )?;
        }
        tx.commit()?;
        Ok(Some(delivery))
    }

    /// Record what the user said about alert `id` (AL-05), or take it back with `None`.
    /// Any feedback also dismisses the alert. Allowing it adds its rule and app to the
    /// allow-list; taking that back removes them. Returns whether there is an alert with
    /// this id.
    pub fn set_feedback(&self, id: i64, feedback: Option<Feedback>, now: i64) -> Result<bool> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let Some(row) = tx
            .query_row(&format!("{ALERT_COLUMNS} WHERE id = ?1"), [id], alert_row)
            .optional()?
        else {
            return Ok(false);
        };
        let stored = stored_alert(row)?;
        if feedback.is_some_and(|f| !f.allowed_for(stored.alert.severity)) {
            return Err(StoreError::FeedbackNotAllowed(id));
        }
        let rule = stored.alert.rule.id();
        let subject = stored.alert.app().unwrap_or_default();
        if stored.feedback == Some(Feedback::Allowed) && feedback != Some(Feedback::Allowed) {
            tx.execute(
                "DELETE FROM allowed WHERE rule_id = ?1 AND subject = ?2",
                params![rule, subject],
            )?;
        }
        if feedback == Some(Feedback::Allowed) {
            tx.execute(
                "INSERT OR IGNORE INTO allowed (rule_id, subject, created) VALUES (?1, ?2, ?3)",
                params![rule, subject, now],
            )?;
        }
        tx.execute(
            "UPDATE alert SET user_feedback = ?2 WHERE id = ?1",
            params![id, feedback.map(Feedback::as_str)],
        )?;
        if feedback.is_some() {
            tx.execute(
                "UPDATE alert SET state = ?2 WHERE id = ?1",
                params![id, AlertState::Dismissed.as_str()],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Whether the user allowed `rule` for `app` (`None`: Sentinel itself), so that it
    /// raises no alerts about it (AL-05).
    pub fn is_allowed(&self, rule: Rule, app: Option<&str>) -> Result<bool> {
        let found: Option<i64> = lock(&self.conn)
            .query_row(
                "SELECT 1 FROM allowed WHERE rule_id = ?1 AND subject = ?2",
                params![rule.id(), app.unwrap_or_default()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Everything the user allowed, newest first. Entries for rules this version does
    /// not know are left out.
    pub fn allowed(&self) -> Result<Vec<AllowedEntry>> {
        let conn = lock(&self.conn);
        let mut stmt =
            conn.prepare("SELECT rule_id, subject, created FROM allowed ORDER BY created DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(rule, subject, created)| {
                Some(AllowedEntry {
                    rule: Rule::from_id(&rule)?,
                    app: (!subject.is_empty()).then_some(subject),
                    created,
                })
            })
            .collect())
    }

    /// Change an alert's state. Returns whether there is an alert with this id.
    pub fn set_alert_state(&self, id: i64, state: AlertState) -> Result<bool> {
        let changed = lock(&self.conn).execute(
            "UPDATE alert SET state = ?2 WHERE id = ?1",
            params![id, state.as_str()],
        )?;
        Ok(changed == 1)
    }

    /// The network settings last seen (CM-07), if any. A state this version cannot read
    /// counts as none.
    pub fn network_state(&self) -> Result<Option<NetworkState>> {
        let json: Option<String> = lock(&self.conn)
            .query_row("SELECT state FROM network_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(json.and_then(|json| NetworkState::from_json(&json).ok()))
    }

    /// Keep `state` as the network settings last seen (CM-07) and return the ones seen
    /// before, if any. A state this version cannot read counts as none.
    pub fn swap_network_state(
        &self,
        state: &NetworkState,
        now: i64,
    ) -> Result<Option<NetworkState>> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let previous: Option<String> = tx
            .query_row("SELECT state FROM network_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        tx.execute(
            "INSERT INTO network_state (id, state, updated) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET state = excluded.state, updated = excluded.updated",
            params![state.to_json(), now],
        )?;
        tx.commit()?;
        Ok(previous.and_then(|json| NetworkState::from_json(&json).ok()))
    }

    /// A sensor came into use at `started` (SE-01), by `app` as `attribution` found it,
    /// with the user present or not (SE-04). Returns the use's id.
    pub fn sensor_started(
        &self,
        sensor: Sensor,
        started: i64,
        app: Option<&str>,
        attribution: Attribution,
        user_present: bool,
    ) -> Result<i64> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let app_id = app_id(&tx, app, started)?.map(|(id, _)| id);
        tx.execute(
            "INSERT INTO sensor_use (app_id, sensor, started, user_present, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                app_id,
                sensor.as_str(),
                started,
                user_present,
                attribution.as_str()
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// The screen was off or locked during use `id` (SE-04). Returns the use the first
    /// time only, while it is still in use.
    pub fn sensor_away(&self, id: i64) -> Result<Option<SensorUse>> {
        let changed = lock(&self.conn).execute(
            "UPDATE sensor_use SET user_present = 0
             WHERE id = ?1 AND user_present = 1 AND ended IS NULL",
            [id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(self.sensor_uses(Some(id), 1)?.pop())
    }

    /// Use `id` ended at `ended`, unless it already had.
    pub fn sensor_ended(&self, id: i64, ended: i64) -> Result<()> {
        lock(&self.conn).execute(
            "UPDATE sensor_use SET ended = ?2 WHERE id = ?1 AND ended IS NULL",
            params![id, ended],
        )?;
        Ok(())
    }

    /// Every use still open ended at `ended`: monitoring stopped, so their end is not
    /// known better.
    pub fn end_sensor_uses(&self, ended: i64) -> Result<()> {
        lock(&self.conn).execute(
            "UPDATE sensor_use SET ended = ?1 WHERE ended IS NULL",
            [ended],
        )?;
        Ok(())
    }

    /// The most recent sensor uses, newest first.
    pub fn recent_sensor_uses(&self, limit: u32) -> Result<Vec<SensorUse>> {
        self.sensor_uses(None, limit)
    }

    fn sensor_uses(&self, id: Option<i64>, limit: u32) -> Result<Vec<SensorUse>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT s.id, s.sensor, s.started, s.ended, a.identifier, s.source, s.user_present
             FROM sensor_use s LEFT JOIN app a ON a.id = s.app_id
             WHERE ?1 IS NULL OR s.id = ?1
             ORDER BY s.started DESC, s.id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![id, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, bool>(6)?,
            ))
        })?;
        let mut uses = Vec::new();
        for row in rows {
            let (id, sensor, started, ended, app, source, user_present) = row?;
            // A sensor this version cannot name is left out.
            let Some(sensor) = Sensor::from_name(&sensor) else {
                continue;
            };
            uses.push(SensorUse {
                id,
                sensor,
                started,
                ended,
                app,
                attribution: Attribution::from_name(&source).unwrap_or(Attribution::Unknown),
                user_present,
            });
        }
        Ok(uses)
    }

    /// Keep `posture` as the device settings last seen (ID-03, ID-10) and return the
    /// ones seen before, if any. A state this version cannot read counts as none.
    pub fn swap_posture(&self, posture: &Posture, now: i64) -> Result<Option<Posture>> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let previous: Option<String> = tx
            .query_row("SELECT state FROM posture_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        tx.execute(
            "INSERT INTO posture_state (id, state, updated) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET state = excluded.state, updated = excluded.updated",
            params![posture.to_json(), now],
        )?;
        tx.commit()?;
        Ok(previous.and_then(|json| Posture::from_json(&json).ok()))
    }

    /// Keep `held` as the special access apps hold (ID-12) and return what of it they
    /// did not hold at the last check, in the order given. Nothing is written when
    /// nothing changed. Access this version cannot name counts as not held.
    pub fn swap_access(&self, held: &[(String, Access)]) -> Result<Vec<(String, Access)>> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let mut before = HashSet::new();
        {
            let mut rows = tx.prepare("SELECT app, access FROM app_access")?;
            let rows =
                rows.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            for row in rows {
                let (app, access) = row?;
                if let Some(access) = Access::from_name(&access) {
                    before.insert((app, access));
                }
            }
        }
        let now: HashSet<&(String, Access)> = held.iter().collect();
        if now.len() != before.len() || !now.iter().all(|entry| before.contains(*entry)) {
            tx.execute("DELETE FROM app_access", [])?;
            for (app, access) in &now {
                tx.execute(
                    "INSERT INTO app_access (app, access) VALUES (?1, ?2)",
                    params![app, access.as_str()],
                )?;
            }
        }
        tx.commit()?;
        let mut gained: Vec<(String, Access)> = Vec::new();
        for entry in held {
            if !before.contains(entry) && !gained.contains(entry) {
                gained.push(entry.clone());
            }
        }
        Ok(gained)
    }

    /// Keep a firewall rule, replacing one about the same app and destination (CM-10),
    /// and journal it (SRS §9) with the alert it was taken from, if any. Returns its key.
    pub fn set_firewall_rule(
        &self,
        rule: &FirewallRule,
        now: i64,
        alert: Option<i64>,
    ) -> Result<String> {
        let key = rule.key();
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let after = Setting::Rule {
            key: key.clone(),
            rule: Some(rule.clone()),
        };
        change(&tx, after, now, alert)?;
        tx.commit()?;
        Ok(key)
    }

    /// The firewall mode (CM-08): Monitor until another is set. A mode this version
    /// cannot read counts as Monitor, which blocks nothing on its own.
    pub fn firewall_mode(&self) -> Result<FirewallMode> {
        let conn = lock(&self.conn);
        Ok(read_firewall_mode(&conn)?.unwrap_or(FirewallMode::Monitor))
    }

    /// Put `mode` in force, journalled, and return the mode now in force. Setting the
    /// mode already in force changes nothing, so Block-unknown keeps the time it was
    /// turned on.
    pub fn set_firewall_mode(&self, mode: FirewallMode, now: i64) -> Result<FirewallMode> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        if read_firewall_mode(&tx)?
            .unwrap_or(FirewallMode::Monitor)
            .id()
            != mode.id()
        {
            change(&tx, Setting::Mode(mode), now, None)?;
        }
        let now_in_force = read_firewall_mode(&tx)?.unwrap_or(FirewallMode::Monitor);
        tx.commit()?;
        Ok(now_in_force)
    }

    /// Network isolation (RA-03), while it is on.
    pub fn isolation(&self) -> Result<Option<Isolation>> {
        read_isolation(&lock(&self.conn))
    }

    /// Turn isolation on, or off with `None`, journalled. Turning it on while it is on
    /// keeps when it was turned on.
    pub fn set_isolation(&self, isolation: Option<&Isolation>, now: i64) -> Result<()> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let after = match (isolation, read_isolation(&tx)?) {
            (Some(isolation), Some(in_force)) => Some(Isolation {
                since: in_force.since,
                own_app: isolation.own_app.clone(),
            }),
            (isolation, _) => isolation.cloned(),
        };
        change(&tx, Setting::Isolation(after), now, None)?;
        tx.commit()?;
        Ok(())
    }

    /// Remove the firewall rule with this key, journalled. Returns whether there was one.
    pub fn remove_firewall_rule(&self, key: &str, now: i64) -> Result<bool> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let after = Setting::Rule {
            key: key.to_owned(),
            rule: None,
        };
        let removed = change(&tx, after, now, None)?;
        tx.commit()?;
        Ok(removed)
    }

    /// The action journal, newest first (SRS §9). An entry this version cannot read is
    /// left out.
    pub fn journal(&self, limit: u32) -> Result<Vec<JournalEntry>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, alert_id, actor, before_state, after_state, undo IS NOT NULL, at,
                    undone_at
             FROM action_journal ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut entries = Vec::with_capacity(rows.len());
        for (id, alert, actor, before, after, undoable, at, undone_at) in rows {
            let Some(change) = read_change(&before, &after) else {
                continue;
            };
            let can_undo = undoable
                && undone_at.is_none()
                && read_setting(&conn, change.after())? == *change.after();
            entries.push(JournalEntry {
                id,
                alert,
                actor,
                change,
                at,
                undone_at,
                can_undo,
            });
        }
        Ok(entries)
    }

    /// Undo the journalled action `id`: put its setting back as it was before, if the
    /// setting is still as the action left it, and record when it was undone.
    pub fn undo(&self, id: i64, now: i64) -> Result<Undo> {
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let row = tx
            .query_row(
                "SELECT before_state, after_state, undo IS NOT NULL, undone_at
                 FROM action_journal WHERE id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((before, after, undoable, undone_at)) = row else {
            return Ok(Undo::NotFound);
        };
        if undone_at.is_some() {
            return Ok(Undo::AlreadyUndone);
        }
        let Some(change) = read_change(&before, &after).filter(|_| undoable) else {
            return Ok(Undo::CannotUndo);
        };
        if read_setting(&tx, change.after())? != *change.after() {
            return Ok(Undo::ChangedSince);
        }
        write_setting(&tx, change.before(), now)?;
        tx.execute(
            "UPDATE action_journal SET undone_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        tx.commit()?;
        Ok(Undo::Undone)
    }

    /// The firewall rules in force, newest first. A rule this version cannot read is
    /// left out.
    pub fn firewall_rules(&self) -> Result<Vec<StoredRule>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, body, created FROM rule WHERE kind = 'firewall' AND enabled = 1
             ORDER BY created DESC, id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|(key, body, created)| {
                Some(StoredRule {
                    key,
                    rule: FirewallRule::from_json(&body)?,
                    created,
                })
            })
            .collect())
    }

    /// Monitoring is back: close the open gap, if any.
    pub fn close_gap(&self, ended: i64) -> Result<()> {
        lock(&self.conn).execute(
            "UPDATE monitoring_gap SET ended = ?1 WHERE ended IS NULL",
            [ended],
        )?;
        Ok(())
    }

    /// The most recent gaps, newest first.
    pub fn recent_gaps(&self, limit: u32) -> Result<Vec<Gap>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT started, ended, reason FROM monitoring_gap ORDER BY id DESC LIMIT ?1",
        )?;
        let gaps = stmt.query_map([limit], |r| {
            Ok(Gap {
                started: r.get(0)?,
                ended: r.get(1)?,
                reason: r.get(2)?,
            })
        })?;
        Ok(gaps.collect::<rusqlite::Result<_>>()?)
    }

    /// Roll flows that started more than `keep_days` before `now` up into daily totals
    /// per app, destination and protocol, then delete them (SRS §13.2). Returns the
    /// number of flows rolled up.
    pub fn apply_retention(&self, now: i64, keep_days: u32) -> Result<usize> {
        let cutoff = now - i64::from(keep_days) * DAY_MS;
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO flow_daily (day, app_id, destination, proto, flows, bytes_up, bytes_down,
                                     away_up, away_down)
             SELECT started / ?2, coalesce(app_id, 0), coalesce(hostname, remote_ip), proto,
                    count(*), sum(bytes_up), sum(bytes_down), sum(away_up), sum(away_down)
             FROM flow WHERE started < ?1
             GROUP BY started / ?2, coalesce(app_id, 0), coalesce(hostname, remote_ip), proto
             ON CONFLICT (day, app_id, destination, proto) DO UPDATE SET
                 flows = flows + excluded.flows,
                 bytes_up = bytes_up + excluded.bytes_up,
                 bytes_down = bytes_down + excluded.bytes_down,
                 away_up = away_up + excluded.away_up,
                 away_down = away_down + excluded.away_down",
            params![cutoff, DAY_MS],
        )?;
        let removed = tx.execute("DELETE FROM flow WHERE started < ?1", [cutoff])?;
        tx.commit()?;
        Ok(removed)
    }

    /// Everything the history holds about `app`, with at most `limit` destinations,
    /// most data sent first. Rolled-up days count too. `None` if the app was never
    /// seen. Open flows count with the bytes stored when they started.
    pub fn app_summary(&self, app: &str, limit: u32) -> Result<Option<AppSummary>> {
        let conn = lock(&self.conn);
        let Some((id, first_seen)) = conn
            .query_row(
                "SELECT id, first_seen FROM app WHERE platform = ?1 AND identifier = ?2",
                params![PLATFORM, app],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut stmt = conn.prepare(
            "SELECT g.destination, g.flows, g.up, g.down, g.first, g.last, g.away_up,
                    g.away_down, g.name_src, d.asn, d.net_owner, d.net_source, d.country,
                    d.country_source, d.company, d.company_domain, d.company_source,
                    d.category, d.category_domain, d.category_source
             FROM (
                 SELECT destination, sum(flows) AS flows, sum(up) AS up, sum(down) AS down,
                        min(first) AS first, max(last) AS last, sum(away_up) AS away_up,
                        sum(away_down) AS away_down, max(name_src) AS name_src
                 FROM (
                     SELECT coalesce(hostname, remote_ip) AS destination, 1 AS flows,
                            bytes_up AS up, bytes_down AS down, started AS first,
                            coalesce(ended, started) AS last, away_up, away_down,
                            hostname_src AS name_src
                     FROM flow WHERE app_id = ?1
                     UNION ALL
                     SELECT destination, flows, bytes_up, bytes_down, day * ?2, day * ?2,
                            away_up, away_down, NULL
                     FROM flow_daily WHERE app_id = ?1
                 )
                 GROUP BY destination
             ) g
             LEFT JOIN destination d ON d.hostname = g.destination
             ORDER BY g.up DESC, g.up + g.down DESC, g.destination",
        )?;
        let all = stmt
            .query_map(params![id, DAY_MS], |r| {
                Ok(DestinationTotal {
                    destination: r.get(0)?,
                    flows: r.get(1)?,
                    bytes_up: r.get(2)?,
                    bytes_down: r.get(3)?,
                    first_seen: r.get(4)?,
                    last_seen: r.get(5)?,
                    bytes_up_away: r.get(6)?,
                    bytes_down_away: r.get(7)?,
                    // "sni" sorts after "dns", so the strongest source wins.
                    name_source: r
                        .get::<_, Option<String>>(8)?
                        .map(|s| hostname_src_from(&s)),
                    facts: DestinationFacts {
                        asn: r.get(9)?,
                        network_owner: r.get(10)?,
                        network_source: r.get(11)?,
                        country: r.get(12)?,
                        country_source: r.get(13)?,
                        company: listed(r.get(14)?, r.get(15)?, r.get(16)?),
                        categories: listed(
                            r.get::<_, Option<String>>(17)?.map(|c| lines(&c)),
                            r.get(18)?,
                            r.get(19)?,
                        ),
                    },
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(AppSummary {
            app: app.to_owned(),
            first_seen,
            flows: all.iter().map(|d| d.flows).sum(),
            bytes_up: all.iter().map(|d| d.bytes_up).sum(),
            bytes_down: all.iter().map(|d| d.bytes_down).sum(),
            bytes_up_away: all.iter().map(|d| d.bytes_up_away).sum(),
            bytes_down_away: all.iter().map(|d| d.bytes_down_away).sum(),
            destination_count: u32::try_from(all.len()).unwrap_or(u32::MAX),
            companies: companies(&all),
            destinations: all.into_iter().take(limit as usize).collect(),
        }))
    }

    /// Apps whose connections carried data while the user was away, among flows active
    /// since `since` (Unix ms), most data sent first, at most `limit` (CM-06).
    pub fn away_totals(&self, since: i64, limit: u32) -> Result<Vec<AwayTotal>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT a.identifier, count(*), sum(f.away_up), sum(f.away_down)
             FROM flow f LEFT JOIN app a ON a.id = f.app_id
             WHERE coalesce(f.ended, f.started) >= ?1 AND f.away_up + f.away_down > 0
             GROUP BY f.app_id
             ORDER BY sum(f.away_up) DESC, sum(f.away_up) + sum(f.away_down) DESC,
                      a.identifier
             LIMIT ?2",
        )?;
        let totals = stmt.query_map(params![since, limit], |r| {
            Ok(AwayTotal {
                app: r.get(0)?,
                flows: r.get(1)?,
                bytes_up_away: r.get(2)?,
                bytes_down_away: r.get(3)?,
            })
        })?;
        Ok(totals.collect::<rusqlite::Result<_>>()?)
    }

    /// Daily totals, newest day first.
    pub fn daily_totals(&self, limit: u32) -> Result<Vec<DailyTotal>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT d.day, a.identifier, d.destination, d.proto, d.flows, d.bytes_up, d.bytes_down,
                    d.away_up, d.away_down
             FROM flow_daily d LEFT JOIN app a ON a.id = d.app_id
             ORDER BY d.day DESC, d.destination LIMIT ?1",
        )?;
        let totals = stmt.query_map([limit], |r| {
            Ok(DailyTotal {
                day: r.get(0)?,
                app: r.get(1)?,
                destination: r.get(2)?,
                proto: proto_from(&r.get::<_, String>(3)?),
                flows: r.get(4)?,
                bytes_up: r.get(5)?,
                bytes_down: r.get(6)?,
                bytes_up_away: r.get(7)?,
                bytes_down_away: r.get(8)?,
            })
        })?;
        Ok(totals.collect::<rusqlite::Result<_>>()?)
    }
}

/// Delete the database at `path` and its journal files (SRS §13.2 one-tap wipe). The
/// caller deletes the key. Missing files are not an error.
pub fn wipe(path: &Path) -> Result<()> {
    let mut names = vec![path.as_os_str().to_owned()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        names.push(name);
    }
    for name in names {
        match std::fs::remove_file(&name) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The app's row id, and whether the history saw it for the first time and added it.
fn app_id(tx: &Transaction<'_>, app: Option<&str>, now: i64) -> Result<Option<(i64, bool)>> {
    let Some(identifier) = app else {
        return Ok(None);
    };
    let added = tx.execute(
        "INSERT INTO app (platform, identifier, first_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT (platform, identifier) DO NOTHING",
        params![PLATFORM, identifier, now],
    )? == 1;
    let id = tx.query_row(
        "SELECT id FROM app WHERE platform = ?1 AND identifier = ?2",
        params![PLATFORM, identifier],
        |r| r.get(0),
    )?;
    Ok(Some((id, added)))
}

/// Note that a finished flow's app connected to its name. Returns the news if the app
/// never had before. Flows known only by their address are not counted: large services
/// change addresses often (ADR-0013).
fn first_destination(tx: &Transaction<'_>, row: &FlowRow) -> Result<Option<FirstSeen>> {
    let (Some(app), Some(hostname)) = (&row.app, &row.hostname) else {
        return Ok(None);
    };
    let Some((id, app_first_seen)) = tx
        .query_row(
            "SELECT id, first_seen FROM app WHERE platform = ?1 AND identifier = ?2",
            params![PLATFORM, app],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let added = tx.execute(
        "INSERT INTO app_destination (app_id, destination, first_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT (app_id, destination) DO NOTHING",
        params![id, hostname, row.started],
    )? == 1;
    Ok(added.then(|| FirstSeen::Destination {
        app: app.clone(),
        app_first_seen,
        destination: hostname.clone(),
    }))
}

/// Keep the latest facts about a flow's destination: its hostname, or its address
/// when no name is known.
fn record_destination(tx: &Transaction<'_>, row: &FlowRow, facts: &DestinationFacts) -> Result<()> {
    if facts.asn.is_none()
        && facts.country.is_none()
        && facts.company.is_none()
        && facts.categories.is_none()
    {
        return Ok(());
    }
    let company = facts.company.as_ref();
    let categories = facts.categories.as_ref();
    tx.execute(
        "INSERT INTO destination (hostname, asn, net_owner, net_source, country, country_source,
                                  company, company_domain, company_source, category,
                                  category_domain, category_source, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT (hostname) DO UPDATE SET
             asn = excluded.asn, net_owner = excluded.net_owner,
             net_source = excluded.net_source, country = excluded.country,
             country_source = excluded.country_source, company = excluded.company,
             company_domain = excluded.company_domain,
             company_source = excluded.company_source, category = excluded.category,
             category_domain = excluded.category_domain,
             category_source = excluded.category_source, updated = excluded.updated
         WHERE excluded.updated >= coalesce(destination.updated, 0)",
        params![
            row.hostname.as_deref().unwrap_or(&row.remote_ip),
            facts.asn,
            facts.network_owner,
            facts.network_source,
            facts.country,
            facts.country_source,
            company.map(|c| &c.value),
            company.map(|c| &c.domain),
            company.map(|c| c.sources.join("\n")),
            categories.map(|c| c.value.join("\n")),
            categories.map(|c| &c.domain),
            categories.map(|c| c.sources.join("\n")),
            row.ended.unwrap_or(row.started),
        ],
    )?;
    Ok(())
}

/// A list stored one item per line.
fn lines(text: &str) -> Vec<String> {
    text.lines().map(str::to_owned).collect()
}

/// An answer from the tracker lists, from its three columns; `None` if any is missing.
fn listed<T>(
    value: Option<T>,
    domain: Option<String>,
    sources: Option<String>,
) -> Option<Listed<T>> {
    Some(Listed {
        value: value?,
        domain: domain?,
        sources: lines(&sources?),
    })
}

/// The companies of an app's destinations, most data sent first.
fn companies(destinations: &[DestinationTotal]) -> Vec<CompanyTotal> {
    let mut companies: Vec<CompanyTotal> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for destination in destinations {
        let Some(company) = &destination.facts.company else {
            continue;
        };
        let i = *index.entry(&company.value).or_insert_with(|| {
            companies.push(CompanyTotal {
                company: company.value.clone(),
                categories: Vec::new(),
                destinations: 0,
                bytes_up: 0,
                bytes_down: 0,
            });
            companies.len() - 1
        });
        let total = &mut companies[i];
        total.destinations += 1;
        total.bytes_up += destination.bytes_up;
        total.bytes_down += destination.bytes_down;
        for category in destination.facts.categories.iter().flat_map(|c| &c.value) {
            if !total.categories.contains(category) {
                total.categories.push(category.clone());
            }
        }
    }
    companies.sort_by(|a, b| {
        (b.bytes_up, b.bytes_up + b.bytes_down, &a.company).cmp(&(
            a.bytes_up,
            a.bytes_up + a.bytes_down,
            &b.company,
        ))
    });
    companies
}

/// Returns the new row's id, and whether its app is new to the history.
/// The stored firewall mode; `None` when none is set or it cannot be read.
fn read_firewall_mode(conn: &Connection) -> Result<Option<FirewallMode>> {
    let row: Option<(String, Option<i64>)> = conn
        .query_row(
            "SELECT mode, since FROM firewall_mode WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(mode, since)| FirewallMode::from_id(&mode, since)))
}

fn read_isolation(conn: &Connection) -> Result<Option<Isolation>> {
    Ok(conn
        .query_row(
            "SELECT since, own_app FROM isolation WHERE id = 1",
            [],
            |r| {
                Ok(Isolation {
                    since: r.get(0)?,
                    own_app: r.get(1)?,
                })
            },
        )
        .optional()?)
}

/// The firewall rule kept under `key`, if this version can read it.
fn read_rule(conn: &Connection, key: &str) -> Result<Option<FirewallRule>> {
    let body: Option<String> = conn
        .query_row(
            "SELECT body FROM rule WHERE id = ?1 AND kind = 'firewall'",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(body.and_then(|body| FirewallRule::from_json(&body)))
}

/// The state in force of the setting `like` is a state of.
fn read_setting(conn: &Connection, like: &Setting) -> Result<Setting> {
    Ok(match like {
        Setting::Rule { key, .. } => Setting::Rule {
            key: key.clone(),
            rule: read_rule(conn, key)?,
        },
        Setting::Mode(_) => {
            Setting::Mode(read_firewall_mode(conn)?.unwrap_or(FirewallMode::Monitor))
        }
        Setting::Isolation(_) => Setting::Isolation(read_isolation(conn)?),
    })
}

/// Put `setting` in force as it is, at `now`.
fn write_setting(conn: &Connection, setting: &Setting, now: i64) -> Result<()> {
    match setting {
        Setting::Rule {
            key,
            rule: Some(rule),
        } => conn.execute(
            "INSERT INTO rule (id, kind, body, enabled, source, version, created)
             VALUES (?1, 'firewall', ?2, 1, 'user', 1, ?3)
             ON CONFLICT (id) DO UPDATE SET body = excluded.body, created = excluded.created",
            params![key, rule.to_json(), now],
        )?,
        Setting::Rule { key, rule: None } => conn.execute(
            "DELETE FROM rule WHERE id = ?1 AND kind = 'firewall'",
            [key],
        )?,
        Setting::Mode(mode) => {
            let since = match mode {
                FirewallMode::Monitor => None,
                FirewallMode::BlockUnknown { since } => Some(*since),
            };
            conn.execute(
                "INSERT INTO firewall_mode (id, mode, since) VALUES (1, ?1, ?2)
                 ON CONFLICT (id) DO UPDATE SET mode = excluded.mode, since = excluded.since",
                params![mode.id(), since],
            )?
        }
        Setting::Isolation(Some(isolation)) => conn.execute(
            "INSERT INTO isolation (id, since, own_app) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET since = excluded.since, own_app = excluded.own_app",
            params![isolation.since, isolation.own_app],
        )?,
        Setting::Isolation(None) => conn.execute("DELETE FROM isolation", [])?,
    };
    Ok(())
}

/// Put `after` in force and journal the change from the state in force (SRS §9), as
/// the user's action, taken from `alert` if it exists. Returns whether anything
/// changed: nothing is journalled when nothing did.
fn change(tx: &Transaction<'_>, after: Setting, now: i64, alert: Option<i64>) -> Result<bool> {
    let before = read_setting(tx, &after)?;
    let Some(change) = Change::new(before, after) else {
        return Ok(false);
    };
    write_setting(tx, change.after(), now)?;
    tx.execute(
        "INSERT INTO action_journal (alert_id, action, actor, before_state, after_state, undo, at)
         VALUES ((SELECT id FROM alert WHERE id = ?1), ?2, 'user', ?3, ?4, ?5, ?6)",
        params![
            alert,
            change.action(),
            change.before().to_json(),
            change.after().to_json(),
            change.undo().action(),
            now
        ],
    )?;
    Ok(true)
}

fn read_change(before: &str, after: &str) -> Option<Change> {
    Change::new(Setting::from_json(before)?, Setting::from_json(after)?)
}

fn insert_flow(tx: &Transaction<'_>, row: &FlowRow) -> Result<(i64, bool)> {
    let app = app_id(tx, row.app.as_deref(), row.started)?;
    let new_app = app.is_some_and(|(_, added)| added);
    let app = app.map(|(id, _)| id);
    tx.execute(
        "INSERT INTO flow (app_id, proto, direction, local_ip, local_port, remote_ip,
                           remote_port, hostname, hostname_src, started, ended, bytes_up,
                           bytes_down, verdict, away_up, away_down, while_away)
         VALUES (?1, ?2, 'out', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                 ?14 + ?15 > 0)",
        params![
            app,
            proto_name(row.proto),
            row.local_ip,
            row.local_port,
            row.remote_ip,
            row.remote_port,
            row.hostname,
            row.hostname_src.map(hostname_src_name),
            row.started,
            row.ended,
            row.bytes_up,
            row.bytes_down,
            verdict_name(row.blocked),
            row.bytes_up_away,
            row.bytes_down_away,
        ],
    )?;
    Ok((tx.last_insert_rowid(), new_app))
}

fn update_flow(tx: &Transaction<'_>, id: i64, row: &FlowRow) -> Result<()> {
    // The hostname can be learned late (from the TLS ClientHello), so keep a known one.
    tx.execute(
        "UPDATE flow SET hostname = coalesce(?2, hostname),
                         hostname_src = coalesce(?3, hostname_src),
                         ended = ?4, bytes_up = ?5, bytes_down = ?6, verdict = ?7,
                         away_up = ?8, away_down = ?9, while_away = ?8 + ?9 > 0
         WHERE id = ?1",
        params![
            id,
            row.hostname,
            row.hostname_src.map(hostname_src_name),
            row.ended,
            row.bytes_up,
            row.bytes_down,
            verdict_name(row.blocked),
            row.bytes_up_away,
            row.bytes_down_away,
        ],
    )?;
    Ok(())
}

fn proto_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn proto_from(name: &str) -> Proto {
    if name == "udp" {
        Proto::Udp
    } else {
        Proto::Tcp
    }
}

/// The columns [`alert_row`] reads.
const ALERT_COLUMNS: &str = "SELECT id, rule_id, severity, evidence, created, state, notified,
                                    user_feedback FROM alert";

/// An alert row as read, before its names are checked.
struct AlertRow {
    id: i64,
    rule: String,
    severity: String,
    evidence: String,
    created: i64,
    state: String,
    notified: Option<i64>,
    feedback: Option<String>,
}

fn alert_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
    Ok(AlertRow {
        id: r.get(0)?,
        rule: r.get(1)?,
        severity: r.get(2)?,
        evidence: r.get(3)?,
        created: r.get(4)?,
        state: r.get(5)?,
        notified: r.get(6)?,
        feedback: r.get(7)?,
    })
}

fn stored_alert(row: AlertRow) -> Result<StoredAlert> {
    let bad = || StoreError::BadAlert(row.id);
    Ok(StoredAlert {
        id: row.id,
        alert: Alert {
            rule: Rule::from_id(&row.rule).ok_or_else(bad)?,
            severity: Severity::from_name(&row.severity).ok_or_else(bad)?,
            created: row.created,
            evidence: sentinel_detect::evidence_from_json(&row.evidence).map_err(|_| bad())?,
        },
        state: AlertState::from_name(&row.state).ok_or_else(bad)?,
        notified: row.notified,
        feedback: match row.feedback {
            Some(name) => Some(Feedback::from_name(&name).ok_or_else(bad)?),
            None => None,
        },
    })
}

/// Whether the user marked an alert of the same rule about the same app "not useful".
fn marked_not_useful(tx: &Transaction<'_>, alert: &Alert) -> Result<bool> {
    let mut stmt = tx.prepare(&format!(
        "{ALERT_COLUMNS} WHERE rule_id = ?1 AND user_feedback = ?2"
    ))?;
    let rows = stmt
        .query_map(
            params![alert.rule.id(), Feedback::NotUseful.as_str()],
            alert_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for row in rows {
        if stored_alert(row)?.alert.app() == alert.app() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hostname_src_name(source: HostnameSource) -> &'static str {
    match source {
        HostnameSource::Dns => "dns",
        HostnameSource::Sni => "sni",
    }
}

fn hostname_src_from(name: &str) -> HostnameSource {
    if name == "sni" {
        HostnameSource::Sni
    } else {
        HostnameSource::Dns
    }
}

fn verdict_name(blocked: bool) -> &'static str {
    if blocked { "blocked" } else { "allowed" }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Sentinel's local history in an encrypted SQLite database (SQLCipher), following the
//! schema in SRS §13. The same crate serves every edition; only the key storage is
//! platform-specific (on Android, a Keystore-wrapped key; see ADR-0009).
//!
//! The history is itself sensitive (THREAT-MODEL-A I3, I4): it never leaves the device,
//! the file is encrypted with a random 256-bit key, and [`wipe`] deletes it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use zeroize::Zeroizing;

mod schema;

/// A flow as the engine reports it, when it starts and again when it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvent {
    /// The engine's id for the flow, unique within one engine session.
    pub engine_id: u64,
    pub flow: FlowRow,
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
    /// Destinations in the whole history, including those beyond the limit asked for.
    pub destination_count: u32,
    /// Most data sent first.
    pub destinations: Vec<DestinationTotal>,
}

/// One app's traffic to one destination, over the whole history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationTotal {
    /// Hostname if known, otherwise the remote address.
    pub destination: String,
    pub flows: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    /// Unix milliseconds. Flows already rolled up into daily totals keep only their
    /// day, so they count from the start of that day (UTC).
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The key does not open this database, or the file is not a Sentinel database.
    #[error("the database cannot be opened with this key")]
    WrongKey,
    #[error("the database was written by a newer version of Sentinel (schema {0})")]
    TooNew(i64),
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
        Ok(Store {
            conn: Mutex::new(conn),
            open_flows: Mutex::new(HashMap::new()),
        })
    }

    /// Record flows from engine session `session`. A flow arrives once when it starts
    /// and once when it ends; both are stored in one row. An end whose start was not
    /// seen is stored as a complete row.
    pub fn record_flows(&self, session: u64, events: &[FlowEvent]) -> Result<()> {
        let mut conn = lock(&self.conn);
        let mut open = lock(&self.open_flows);
        let tx = conn.transaction()?;
        for FlowEvent {
            engine_id,
            flow: row,
        } in events
        {
            let key = (session, *engine_id);
            let existing = if row.ended.is_some() {
                open.remove(&key)
            } else {
                open.get(&key).copied()
            };
            match existing {
                Some(id) => update_flow(&tx, id, row)?,
                None => {
                    let id = insert_flow(&tx, row)?;
                    if row.ended.is_none() {
                        open.insert(key, id);
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The most recent flows, newest first.
    pub fn recent_flows(&self, limit: u32) -> Result<Vec<StoredFlow>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT f.id, a.identifier, f.proto, f.local_ip, f.local_port, f.remote_ip,
                    f.remote_port, f.hostname, f.hostname_src, f.started, f.ended,
                    f.bytes_up, f.bytes_down, f.verdict
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
                blocked: r.get::<_, String>(13)? == "blocked",
            };
            Ok(StoredFlow {
                id: r.get(0)?,
                flow,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Start a gap, unless one is already open.
    pub fn open_gap(&self, started: Option<i64>, reason: &str) -> Result<()> {
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
        Ok(())
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
            "INSERT INTO flow_daily (day, app_id, destination, proto, flows, bytes_up, bytes_down)
             SELECT started / ?2, coalesce(app_id, 0), coalesce(hostname, remote_ip), proto,
                    count(*), sum(bytes_up), sum(bytes_down)
             FROM flow WHERE started < ?1
             GROUP BY started / ?2, coalesce(app_id, 0), coalesce(hostname, remote_ip), proto
             ON CONFLICT (day, app_id, destination, proto) DO UPDATE SET
                 flows = flows + excluded.flows,
                 bytes_up = bytes_up + excluded.bytes_up,
                 bytes_down = bytes_down + excluded.bytes_down",
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
            "SELECT destination, sum(flows), sum(up), sum(down), min(first), max(last)
             FROM (
                 SELECT coalesce(hostname, remote_ip) AS destination, 1 AS flows,
                        bytes_up AS up, bytes_down AS down, started AS first,
                        coalesce(ended, started) AS last
                 FROM flow WHERE app_id = ?1
                 UNION ALL
                 SELECT destination, flows, bytes_up, bytes_down, day * ?2, day * ?2
                 FROM flow_daily WHERE app_id = ?1
             )
             GROUP BY destination
             ORDER BY sum(up) DESC, sum(up) + sum(down) DESC, destination",
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
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(AppSummary {
            app: app.to_owned(),
            first_seen,
            flows: all.iter().map(|d| d.flows).sum(),
            bytes_up: all.iter().map(|d| d.bytes_up).sum(),
            bytes_down: all.iter().map(|d| d.bytes_down).sum(),
            destination_count: u32::try_from(all.len()).unwrap_or(u32::MAX),
            destinations: all.into_iter().take(limit as usize).collect(),
        }))
    }

    /// Daily totals, newest day first.
    pub fn daily_totals(&self, limit: u32) -> Result<Vec<DailyTotal>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT d.day, a.identifier, d.destination, d.proto, d.flows, d.bytes_up, d.bytes_down
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

fn app_id(tx: &Transaction<'_>, app: Option<&str>, now: i64) -> Result<Option<i64>> {
    let Some(identifier) = app else {
        return Ok(None);
    };
    tx.execute(
        "INSERT INTO app (platform, identifier, first_seen) VALUES (?1, ?2, ?3)
         ON CONFLICT (platform, identifier) DO NOTHING",
        params![PLATFORM, identifier, now],
    )?;
    Ok(Some(tx.query_row(
        "SELECT id FROM app WHERE platform = ?1 AND identifier = ?2",
        params![PLATFORM, identifier],
        |r| r.get(0),
    )?))
}

fn insert_flow(tx: &Transaction<'_>, row: &FlowRow) -> Result<i64> {
    let app = app_id(tx, row.app.as_deref(), row.started)?;
    tx.execute(
        "INSERT INTO flow (app_id, proto, direction, local_ip, local_port, remote_ip,
                           remote_port, hostname, hostname_src, started, ended, bytes_up,
                           bytes_down, verdict)
         VALUES (?1, ?2, 'out', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

fn update_flow(tx: &Transaction<'_>, id: i64, row: &FlowRow) -> Result<()> {
    // The hostname can be learned late (from the TLS ClientHello), so keep a known one.
    tx.execute(
        "UPDATE flow SET hostname = coalesce(?2, hostname),
                         hostname_src = coalesce(?3, hostname_src),
                         ended = ?4, bytes_up = ?5, bytes_down = ?6, verdict = ?7
         WHERE id = ?1",
        params![
            id,
            row.hostname,
            row.hostname_src.map(hostname_src_name),
            row.ended,
            row.bytes_up,
            row.bytes_down,
            verdict_name(row.blocked),
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

// SPDX-License-Identifier: GPL-3.0-or-later
//! Schema versions. Each step runs once, in order, inside a transaction; the version is
//! kept in `PRAGMA user_version`.

use rusqlite::Connection;

use crate::{Result, StoreError};

/// The tables from SRS §13.1 that Phase A uses so far, plus the §13.2 roll-up and
/// monitoring gaps (SP-03), which the SRS does not give a table for.
const V1: &str = "
CREATE TABLE app (
  id INTEGER PRIMARY KEY,
  platform TEXT NOT NULL,
  identifier TEXT NOT NULL,          -- package name or path
  signer TEXT,
  sha256 TEXT,
  first_seen INTEGER NOT NULL,
  trust TEXT NOT NULL DEFAULT 'unknown',  -- trusted|unknown|blocked
  UNIQUE (platform, identifier)
);
CREATE TABLE flow (
  id INTEGER PRIMARY KEY,
  app_id INTEGER REFERENCES app(id),
  user_sid TEXT,
  proto TEXT NOT NULL,
  direction TEXT NOT NULL,
  local_ip TEXT,
  local_port INTEGER,
  remote_ip TEXT NOT NULL,
  remote_port INTEGER NOT NULL,
  hostname TEXT,
  hostname_src TEXT,                 -- dns|sni|rdns
  iface TEXT,
  net_profile TEXT,
  started INTEGER NOT NULL,
  ended INTEGER,
  bytes_up INTEGER NOT NULL DEFAULT 0,
  bytes_down INTEGER NOT NULL DEFAULT 0,
  while_away INTEGER,
  verdict TEXT NOT NULL              -- allowed|blocked|prompted
);
CREATE INDEX flow_by_start ON flow (started);
CREATE INDEX flow_by_app ON flow (app_id, started);
CREATE TABLE flow_daily (
  day INTEGER NOT NULL,              -- days since 1970-01-01 UTC
  app_id INTEGER NOT NULL,           -- 0 when the owner was unknown
  destination TEXT NOT NULL,         -- hostname, or the remote address
  proto TEXT NOT NULL,
  flows INTEGER NOT NULL,
  bytes_up INTEGER NOT NULL,
  bytes_down INTEGER NOT NULL,
  PRIMARY KEY (day, app_id, destination, proto)
);
CREATE TABLE monitoring_gap (
  id INTEGER PRIMARY KEY,
  started INTEGER,                   -- NULL when unknown
  ended INTEGER,                     -- NULL while open
  reason TEXT NOT NULL
);
";

/// The app detail screen reads one app's daily totals.
const V2: &str = "CREATE INDEX flow_daily_by_app ON flow_daily (app_id, day);";

/// Bytes carried while the user was away, per flow and per daily total (CM-06).
/// `flow.while_away` (V1) is set when a flow carried any.
const V3: &str = "
ALTER TABLE flow ADD COLUMN away_up INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flow ADD COLUMN away_down INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flow_daily ADD COLUMN away_up INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flow_daily ADD COLUMN away_down INTEGER NOT NULL DEFAULT 0;
";

/// What is known about each destination (SRS §13.1 `destination`), plus where the
/// network and country come from (DT-02). Keyed by hostname, or by address when no
/// name is known.
const V4: &str = "
CREATE TABLE destination (
  hostname TEXT PRIMARY KEY,
  etld1 TEXT,
  asn INTEGER,
  net_owner TEXT,
  company TEXT,
  category TEXT,
  country TEXT,
  confidence REAL,
  updated INTEGER,
  net_source TEXT,
  country_source TEXT
);
";

/// Where each destination's company and categories come from (DT-06): the listed domain
/// that matched and the lists that say so, one per line. `category` holds one category
/// per line.
const V5: &str = "
ALTER TABLE destination ADD COLUMN company_domain TEXT;
ALTER TABLE destination ADD COLUMN company_source TEXT;
ALTER TABLE destination ADD COLUMN category_domain TEXT;
ALTER TABLE destination ADD COLUMN category_source TEXT;
";

/// Alerts (SRS §13.1 `alert`, AL-01, AL-02). `title` and `body` stay empty: the app
/// writes an alert's text in the user's language from `rule_id` and `evidence`
/// (ADR-0012). `evidence` is a JSON array; `state` is "open" or "dismissed".
const V6: &str = "
CREATE TABLE alert (
  id INTEGER PRIMARY KEY,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT,
  body TEXT,
  evidence TEXT NOT NULL,
  created INTEGER NOT NULL,
  state TEXT NOT NULL,
  user_feedback TEXT
);
CREATE INDEX alert_by_created ON alert (created);
";

/// When each alert was notified (AL-03, AL-04): NULL if it was kept in the app only.
const V7: &str = "ALTER TABLE alert ADD COLUMN notified INTEGER;";

const STEPS: &[&str] = &[V1, V2, V3, V4, V5, V6, V7];

pub(crate) fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let latest = STEPS.len() as i64;
    if version > latest {
        return Err(StoreError::TooNew(version));
    }
    for (index, step) in STEPS.iter().enumerate().skip(version as usize) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", index as i64 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_a_version_1_database_and_keeps_its_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO monitoring_gap (started, reason) VALUES (1, 'kept')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, STEPS.len() as i64);
        let index: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'flow_daily_by_app'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);
        let reason: String = conn
            .query_row("SELECT reason FROM monitoring_gap", [], |r| r.get(0))
            .unwrap();
        assert_eq!(reason, "kept");
        let away_columns: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info('flow_daily')
                 WHERE name IN ('away_up', 'away_down')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(away_columns, 2);
        let destination: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'destination'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(destination, 1);
    }
}

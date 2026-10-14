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

const STEPS: &[&str] = &[V1];

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

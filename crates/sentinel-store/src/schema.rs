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

/// What the user allowed (AL-05): a rule for an app, or for Sentinel itself (an empty
/// `subject`). `alert.user_feedback` (V6) holds "not_useful" or "allowed".
const V8: &str = "
CREATE TABLE allowed (
  rule_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  created INTEGER NOT NULL,
  PRIMARY KEY (rule_id, subject)
);
";

/// First network use and first-seen destinations (CM-04, ADR-0013).
///
/// `meta` holds when this history began: when it was created, or upgraded to this
/// version. Only apps installed since then can be new to the network.
///
/// `app_destination` holds each name an app has connected to, and when first. It is
/// filled from the flows and daily totals already kept; destinations known only by
/// their address are left out (a daily total's destination is an address when it has
/// a colon or only digits and dots).
const V9: &str = "
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
INSERT INTO meta (key, value)
  VALUES ('began', CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER));
CREATE TABLE app_destination (
  app_id INTEGER NOT NULL REFERENCES app(id),
  destination TEXT NOT NULL,         -- hostname
  first_seen INTEGER NOT NULL,
  PRIMARY KEY (app_id, destination)
) WITHOUT ROWID;
INSERT INTO app_destination (app_id, destination, first_seen)
  SELECT app_id, destination, min(first_seen) FROM (
    SELECT app_id, hostname AS destination, started AS first_seen
    FROM flow WHERE app_id IS NOT NULL AND hostname IS NOT NULL
    UNION ALL
    SELECT app_id, destination, day * 86400000
    FROM flow_daily
    WHERE app_id != 0 AND instr(destination, ':') = 0 AND destination GLOB '*[^0-9.]*'
  )
  GROUP BY app_id, destination;
";

/// The network settings last seen (CM-07, ADR-0014): one row, the state as JSON, so
/// that a change is found even when it happened while Sentinel was not running.
const V10: &str = "
CREATE TABLE network_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL,
  updated INTEGER NOT NULL
);
";

/// Rules (SRS §13.1 `rule`): firewall rules for now (CM-10, ADR-0015), keyed by what
/// they are about, with the rule as JSON in `body`. `created` is not in the SRS.
const V11: &str = "
CREATE TABLE rule (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                -- firewall|detection|auto_response
  body TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT,
  version INTEGER,
  created INTEGER NOT NULL
);
";

/// The firewall mode (CM-08, ADR-0016): one row, absent until the user picks a mode,
/// which means Monitor. `since` is when Block-unknown was turned on: it blocks the apps
/// installed since then.
const V12: &str = "
CREATE TABLE firewall_mode (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,                -- monitor|block-unknown
  since INTEGER
);
";

/// Network isolation (RA-03, ADR-0017): one row while it is on, with when it was turned
/// on and Sentinel's own app, which keeps the network.
const V13: &str = "
CREATE TABLE isolation (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  since INTEGER NOT NULL,
  own_app TEXT NOT NULL
);
";

/// The action journal (SRS §9 and §13.1 `action_journal`, ADR-0018): each change to the
/// firewall rules, the mode or isolation, with the setting before and after as JSON
/// (`sentinel_detect::Setting`). `undo` names the action that undoes it, or is NULL if
/// it cannot be undone; `undone_at` is set once it was.
const V14: &str = "
CREATE TABLE action_journal (
  id INTEGER PRIMARY KEY,
  alert_id INTEGER REFERENCES alert(id) ON DELETE SET NULL,  -- the alert it was taken from
  action TEXT NOT NULL,              -- keep_rule|remove_rule|set_mode|isolate|end_isolation
  actor TEXT NOT NULL,               -- user
  before_state TEXT NOT NULL,
  after_state TEXT NOT NULL,
  undo TEXT,
  at INTEGER NOT NULL,
  undone_at INTEGER
);
";

/// The special access each app held at the last check (ID-12, ADR-0024): accessibility,
/// device admin or notification access, by its `sentinel_detect::Access` name. An app
/// that gains one is reported, also when it was turned on while Sentinel was not
/// running.
const V15: &str = "
CREATE TABLE app_access (
  app TEXT NOT NULL,
  access TEXT NOT NULL,              -- accessibility|device_admin|notification_listener
  PRIMARY KEY (app, access)
);
";

/// The device settings last seen (ID-03, ID-10, ADR-0025): one row, the state as JSON
/// (`sentinel_detect::Posture`), so that wireless debugging turned on, or a certificate
/// added, is found even when it happened while Sentinel was not running.
const V16: &str = "
CREATE TABLE posture_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state TEXT NOT NULL,
  updated INTEGER NOT NULL
);
";

/// The SRS `sensor_use` table (SE-01, ADR-0027): each use of the microphone or camera.
/// `app_id` is the app when known, or guessed when `source` says so; `user_present`
/// turns 0 once the screen was off or locked during the use (SE-04).
const V17: &str = "
CREATE TABLE sensor_use (
  id INTEGER PRIMARY KEY,
  app_id INTEGER REFERENCES app(id),
  sensor TEXT NOT NULL,              -- mic|camera
  started INTEGER NOT NULL,
  ended INTEGER,
  user_present INTEGER NOT NULL,
  source TEXT NOT NULL               -- unknown|foreground|exact: how the app was found
);
";

/// What of a rule was allowed for an app, when the rule says more than the app (AL-05):
/// for special access, the kind (ID-12), by its `sentinel_detect::Access` name, so that
/// allowing one kind does not silence another (audit A-38). Empty for other rules.
///
/// What was allowed for special access before takes the kinds of the alerts it was
/// allowed from. One whose alerts are gone no longer counts: its app is reported again.
const V18: &str = "
CREATE TABLE allowed_by_detail (
  rule_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL,
  PRIMARY KEY (rule_id, subject, detail)
);
INSERT INTO allowed_by_detail (rule_id, subject, created)
  SELECT rule_id, subject, created FROM allowed WHERE rule_id <> 'special-access';
INSERT OR IGNORE INTO allowed_by_detail (rule_id, subject, detail, created)
  SELECT allowed.rule_id, allowed.subject, json_extract(access.value, '$.access'),
         allowed.created
  FROM allowed
  JOIN alert ON alert.rule_id = allowed.rule_id AND alert.user_feedback = 'allowed'
  JOIN json_each(alert.evidence) AS app
    ON json_extract(app.value, '$.type') = 'app'
   AND json_extract(app.value, '$.package') = allowed.subject
  JOIN json_each(alert.evidence) AS access
    ON json_extract(access.value, '$.type') = 'access'
  WHERE allowed.rule_id = 'special-access';
DROP TABLE allowed;
ALTER TABLE allowed_by_detail RENAME TO allowed;
";

const STEPS: &[&str] = &[
    V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18,
];

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
        // Flows and daily totals from before V9 fill the destinations each app used.
        conn.execute_batch(
            "INSERT INTO app (id, platform, identifier, first_seen)
               VALUES (1, 'android', 'org.example.chat', 100);
             INSERT INTO flow (app_id, proto, direction, remote_ip, remote_port, hostname,
                               started, verdict)
               VALUES (1, 'tcp', 'out', '192.0.2.1', 443, 'chat.example', 500, 'allowed'),
                      (1, 'tcp', 'out', '192.0.2.2', 443, NULL, 600, 'allowed');
             INSERT INTO flow_daily (day, app_id, destination, proto, flows, bytes_up, bytes_down)
               VALUES (0, 1, 'chat.example', 'tcp', 1, 0, 0),
                      (0, 1, 'old.example', 'tcp', 1, 0, 0),
                      (0, 1, '192.0.2.3', 'tcp', 1, 0, 0),
                      (0, 1, '2001:db8::1', 'udp', 1, 0, 0),
                      (0, 0, 'unknown-owner.example', 'tcp', 1, 0, 0);",
        )
        .unwrap();

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
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

        let began: i64 = conn
            .query_row("SELECT value FROM meta WHERE key = 'began'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            (before - 1_000..before + 60_000).contains(&began),
            "{began} vs {before}"
        );
        let mut stmt = conn
            .prepare("SELECT destination, first_seen FROM app_destination ORDER BY destination")
            .unwrap();
        let used: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            used,
            [
                ("chat.example".to_owned(), 0),
                ("old.example".to_owned(), 0)
            ]
        );
    }

    /// Audit A-38: special access allowed before V18 takes the kinds of the alerts it was
    /// allowed from, and no other; one whose alerts are gone no longer counts. What was
    /// allowed for other rules stays as it was.
    #[test]
    fn special_access_allowed_before_keeps_only_the_kinds_it_was_allowed_from() {
        use sentinel_detect::{Access, Evidence, evidence_to_json};

        let conn = Connection::open_in_memory().unwrap();
        for step in &STEPS[..17] {
            conn.execute_batch(step).unwrap();
        }
        conn.pragma_update(None, "user_version", 17).unwrap();
        let about = |app: &str, access: Access| {
            evidence_to_json(&[
                Evidence::App {
                    package: app.to_owned(),
                },
                Evidence::Access { access },
            ])
        };
        let mut alert = conn
            .prepare(
                "INSERT INTO alert (rule_id, severity, evidence, created, state, user_feedback)
                 VALUES ('special-access', 'high', ?1, 1, 'dismissed', ?2)",
            )
            .unwrap();
        for (app, access, feedback) in [
            (
                "org.example.keyboard",
                Access::Accessibility,
                Some("allowed"),
            ),
            // Not allowed from: gained later, or only dismissed.
            ("org.example.keyboard", Access::DeviceAdmin, None),
            (
                "org.example.keyboard",
                Access::NotificationListener,
                Some("not_useful"),
            ),
            // Allowed from, but taken back from the list.
            (
                "org.example.other",
                Access::NotificationListener,
                Some("allowed"),
            ),
        ] {
            alert
                .execute(rusqlite::params![about(app, access), feedback])
                .unwrap();
        }
        drop(alert);
        conn.execute_batch(
            "INSERT INTO allowed (rule_id, subject, created) VALUES
               ('special-access', 'org.example.keyboard', 10),
               ('special-access', 'org.example.gone', 11),
               ('flow-limit', 'org.example.chat', 12);",
        )
        .unwrap();

        migrate(&conn).unwrap();
        let mut stmt = conn
            .prepare("SELECT rule_id, subject, detail, created FROM allowed ORDER BY created")
            .unwrap();
        let allowed: Vec<(String, String, String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let row = |rule: &str, app: &str, detail: &str, created| {
            (rule.to_owned(), app.to_owned(), detail.to_owned(), created)
        };
        assert_eq!(
            allowed,
            [
                row(
                    "special-access",
                    "org.example.keyboard",
                    "accessibility",
                    10
                ),
                row("flow-limit", "org.example.chat", "", 12),
            ]
        );
    }
}

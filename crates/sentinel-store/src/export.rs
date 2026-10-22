// SPDX-License-Identifier: GPL-3.0-or-later
//! Export of the history (SRS §12.3 and `Export(range, format)`, ADR-0033): the flows,
//! alerts and actions of a time range, as JSON or CSV. Only ever at the user's request
//! (SRS §15.2); nothing here sends anything anywhere.
//!
//! An export is written a page at a time, so that a long history never has to be held
//! in memory at once. The pages of one export, joined in order, make one document: a
//! JSON array, or a CSV table with a header row (RFC 4180).

use rusqlite::params;
use serde_json::{Value, json};

use crate::{HostnameSource, Result, Store, hostname_src_from, lock, proto_from, proto_name};

/// What to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    /// Each connection kept in full (rolled-up days are not).
    Flows,
    Alerts,
    /// The action journal (SRS §9).
    Actions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// One page of an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPage {
    /// The page's part of the document.
    pub text: String,
    /// Where the next page starts; `None` when this page ends the document.
    pub next: Option<i64>,
}

const FLOW_COLUMNS: &[&str] = &[
    "id",
    "app",
    "protocol",
    "local_ip",
    "local_port",
    "remote_ip",
    "remote_port",
    "hostname",
    "hostname_source",
    "started",
    "ended",
    "bytes_up",
    "bytes_down",
    "bytes_up_while_away",
    "bytes_down_while_away",
    "blocked",
];
const ALERT_COLUMNS: &[&str] = &[
    "id", "created", "rule", "severity", "state", "app", "evidence", "notified", "feedback",
];
const ACTION_COLUMNS: &[&str] = &["id", "at", "actor", "alert", "before", "after", "undone"];

impl Store {
    /// One page of an export of `kind` as `format`: at most `limit` records begun,
    /// raised or taken from `from` (inclusive) to `to` (exclusive), Unix ms, oldest
    /// first. `after` is the previous page's [`ExportPage::next`], or `None` for the
    /// first page.
    pub fn export_page(
        &self,
        kind: ExportKind,
        format: ExportFormat,
        from: i64,
        to: i64,
        after: Option<i64>,
        limit: u32,
    ) -> Result<ExportPage> {
        let records = match kind {
            ExportKind::Flows => self.flow_records(from, to, after, limit)?,
            ExportKind::Alerts => self.alert_records(from, to, after, limit)?,
            ExportKind::Actions => self.action_records(from, to, after, limit)?,
        };
        let columns = match kind {
            ExportKind::Flows => FLOW_COLUMNS,
            ExportKind::Alerts => ALERT_COLUMNS,
            ExportKind::Actions => ACTION_COLUMNS,
        };
        let next = (records.len() == limit as usize)
            .then(|| records.last().map(|&(id, _)| id))
            .flatten();
        let first = after.is_none();
        let mut text = String::new();
        match format {
            ExportFormat::Json => {
                if first {
                    text.push('[');
                }
                for (i, (_, record)) in records.iter().enumerate() {
                    if !(first && i == 0) {
                        text.push(',');
                    }
                    text.push_str(&record.to_string());
                }
                if next.is_none() {
                    text.push(']');
                }
            }
            ExportFormat::Csv => {
                if first {
                    push_row(&mut text, columns.iter().map(|c| Value::from(*c)));
                }
                for (_, record) in &records {
                    push_row(&mut text, columns.iter().map(|c| record[*c].clone()));
                }
            }
        }
        Ok(ExportPage { text, next })
    }

    fn flow_records(
        &self,
        from: i64,
        to: i64,
        after: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, Value)>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT f.id, a.identifier, f.proto, f.local_ip, f.local_port, f.remote_ip,
                    f.remote_port, f.hostname, f.hostname_src, f.started, f.ended,
                    f.bytes_up, f.bytes_down, f.away_up, f.away_down, f.verdict
             FROM flow f LEFT JOIN app a ON a.id = f.app_id
             WHERE f.started >= ?1 AND f.started < ?2 AND f.id > ?3
             ORDER BY f.id LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![from, to, after.unwrap_or(0), limit], |r| {
            let id: i64 = r.get(0)?;
            let source = r
                .get::<_, Option<String>>(8)?
                .map(|s| match hostname_src_from(&s) {
                    HostnameSource::Dns => "dns",
                    HostnameSource::Sni => "sni",
                });
            Ok((
                id,
                json!({
                    "id": id,
                    "app": r.get::<_, Option<String>>(1)?,
                    "protocol": proto_name(proto_from(&r.get::<_, String>(2)?)),
                    "local_ip": r.get::<_, String>(3)?,
                    "local_port": r.get::<_, u16>(4)?,
                    "remote_ip": r.get::<_, String>(5)?,
                    "remote_port": r.get::<_, u16>(6)?,
                    "hostname": r.get::<_, Option<String>>(7)?,
                    "hostname_source": source,
                    "started": iso(r.get(9)?),
                    "ended": r.get::<_, Option<i64>>(10)?.map(iso),
                    "bytes_up": r.get::<_, i64>(11)?,
                    "bytes_down": r.get::<_, i64>(12)?,
                    "bytes_up_while_away": r.get::<_, i64>(13)?,
                    "bytes_down_while_away": r.get::<_, i64>(14)?,
                    "blocked": r.get::<_, String>(15)? == "blocked",
                }),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn alert_records(
        &self,
        from: i64,
        to: i64,
        after: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, Value)>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, created, rule_id, severity, state, evidence, notified, user_feedback
             FROM alert WHERE created >= ?1 AND created < ?2 AND id > ?3
             ORDER BY id LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![from, to, after.unwrap_or(0), limit], |r| {
            let id: i64 = r.get(0)?;
            // As stored: an export must not lose an alert this version cannot read.
            let evidence = stored_json(&r.get::<_, String>(5)?);
            let app = evidence.as_array().and_then(|items| {
                items
                    .iter()
                    .find(|item| item["type"] == "app")
                    .and_then(|item| item["package"].as_str().map(str::to_owned))
            });
            Ok((
                id,
                json!({
                    "id": id,
                    "created": iso(r.get(1)?),
                    "rule": r.get::<_, String>(2)?,
                    "severity": r.get::<_, String>(3)?,
                    "state": r.get::<_, String>(4)?,
                    "app": app,
                    "evidence": evidence,
                    "notified": r.get::<_, Option<i64>>(6)?.map(iso),
                    "feedback": r.get::<_, Option<String>>(7)?,
                }),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn action_records(
        &self,
        from: i64,
        to: i64,
        after: Option<i64>,
        limit: u32,
    ) -> Result<Vec<(i64, Value)>> {
        let conn = lock(&self.conn);
        let mut stmt = conn.prepare(
            "SELECT id, at, actor, alert_id, before_state, after_state, undone_at
             FROM action_journal WHERE at >= ?1 AND at < ?2 AND id > ?3
             ORDER BY id LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![from, to, after.unwrap_or(0), limit], |r| {
            let id: i64 = r.get(0)?;
            Ok((
                id,
                json!({
                    "id": id,
                    "at": iso(r.get(1)?),
                    "actor": r.get::<_, String>(2)?,
                    "alert": r.get::<_, Option<i64>>(3)?,
                    "before": stored_json(&r.get::<_, String>(4)?),
                    "after": stored_json(&r.get::<_, String>(5)?),
                    "undone": r.get::<_, Option<i64>>(6)?.map(iso),
                }),
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

/// JSON kept in the history, as a value; text that is not JSON stays text.
fn stored_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::from(text))
}

/// One CSV row (RFC 4180): fields quoted where needed, lines ended with CRLF.
fn push_row(text: &mut String, cells: impl Iterator<Item = Value>) {
    let cells: Vec<String> = cells.map(|cell| csv_cell(&cell)).collect();
    text.push_str(&cells.join(","));
    text.push_str("\r\n");
}

fn csv_cell(value: &Value) -> String {
    let plain = match value {
        Value::Null => return String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(_) | Value::Number(_) => return value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    };
    // A spreadsheet runs a cell that starts like a formula; names in the history come
    // from the network and may be made to (CSV injection). A leading quote keeps it text.
    // Spreadsheets skip the space before a formula, so it counts too (audit A-31).
    let formula = plain.trim_start().starts_with(['=', '+', '-', '@']);
    let plain = if formula || plain.starts_with(['\t', '\r', '\n']) {
        format!("'{plain}")
    } else {
        plain
    };
    if plain.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", plain.replace('"', "\"\""))
    } else {
        plain
    }
}

/// Unix milliseconds as an ISO 8601 time in UTC, to the millisecond.
pub(crate) fn iso(ms: i64) -> String {
    let (seconds, millis) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Days to a civil date (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_iso_8601_in_utc() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso(1_792_179_246_474), "2026-10-16T19:34:06.474Z");
        assert_eq!(iso(-1), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn csv_cells_are_quoted_and_cannot_be_formulas() {
        assert_eq!(csv_cell(&Value::Null), "");
        assert_eq!(csv_cell(&json!(42)), "42");
        assert_eq!(csv_cell(&json!(true)), "true");
        assert_eq!(csv_cell(&json!("plain.example")), "plain.example");
        assert_eq!(csv_cell(&json!("a,b")), "\"a,b\"");
        assert_eq!(csv_cell(&json!("say \"hi\"")), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell(&json!("two\nlines")), "\"two\nlines\"");
        assert_eq!(
            csv_cell(&json!("=HYPERLINK(\"x\")")),
            "\"'=HYPERLINK(\"\"x\"\")\""
        );
        assert_eq!(csv_cell(&json!("-2+3")), "'-2+3");
        assert_eq!(csv_cell(&json!(" =1+1")), "' =1+1");
        assert_eq!(csv_cell(&json!("\n=1+1")), "\"'\n=1+1\"");
        assert_eq!(csv_cell(&json!("\u{a0}@SUM(A1)")), "'\u{a0}@SUM(A1)");
        assert_eq!(csv_cell(&json!("a = b")), "a = b");
        assert_eq!(
            csv_cell(&json!([{"type": "app"}])),
            "\"[{\"\"type\"\":\"\"app\"\"}]\""
        );
    }
}

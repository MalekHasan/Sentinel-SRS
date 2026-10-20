// SPDX-License-Identifier: GPL-3.0-or-later
//! Upload surges (DL-02, ADR-0034): an app that sent far more in the last day than it
//! usually sends in a day, measured against the fourteen days before.

use crate::{Alert, Evidence, Rule, Severity};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Days an app's usual upload is measured over.
pub const BASELINE_DAYS: u32 = 14;
/// How many times its usual day an app must send in a day to stand out.
pub const SURGE_FACTOR: u64 = 10;
/// The least a usual day is taken to be: an app that usually sends almost nothing must
/// still send ten times this in a day to stand out.
pub const MIN_USUAL_DAY_BYTES: u64 = 1024 * 1024;

/// What an app sent: in the last day, and in the [`BASELINE_DAYS`] before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploads {
    pub app: String,
    /// When the history first saw the app, Unix ms.
    pub first_seen: i64,
    /// Bytes sent in the day before now.
    pub last_day: u64,
    /// Bytes sent in the [`BASELINE_DAYS`] before that.
    pub baseline: u64,
}

/// The least an app must send in a day to stand out at all: [`SURGE_FACTOR`] times
/// [`MIN_USUAL_DAY_BYTES`]. Apps that sent less need not be looked at.
pub const MIN_SURGE_BYTES: u64 = SURGE_FACTOR * MIN_USUAL_DAY_BYTES;

/// When the last day began and the baseline began, for `now`: the windows [`Uploads`]
/// are measured over.
pub fn upload_windows(now: i64) -> (i64, i64) {
    let last_day = now - DAY_MS;
    (last_day, last_day - i64::from(BASELINE_DAYS) * DAY_MS)
}

/// DL-02: an alert if, at `now`, the app sent at least [`SURGE_FACTOR`] times its usual
/// day in the last day. Only for an app the history has known for the whole baseline:
/// before that, its usual day is not known.
pub fn upload_surge(now: i64, uploads: &Uploads) -> Option<Alert> {
    let (_, baseline_began) = upload_windows(now);
    if uploads.first_seen > baseline_began {
        return None;
    }
    let usual = uploads.baseline / u64::from(BASELINE_DAYS);
    let threshold = usual.max(MIN_USUAL_DAY_BYTES).saturating_mul(SURGE_FACTOR);
    (uploads.last_day >= threshold).then(|| Alert {
        rule: Rule::UploadSurge,
        severity: Severity::Warning,
        created: now,
        evidence: vec![
            Evidence::App {
                package: uploads.app.clone(),
            },
            Evidence::UploadSurge {
                last_day: uploads.last_day,
                usual_day: usual,
                days: BASELINE_DAYS,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_791_979_200_000;
    const MIB: u64 = 1024 * 1024;

    fn uploads(first_seen_days_ago: i64, last_day: u64, baseline: u64) -> Uploads {
        Uploads {
            app: "org.example.app".to_owned(),
            first_seen: NOW - first_seen_days_ago * DAY_MS,
            last_day,
            baseline,
        }
    }

    /// The acceptance test: ten times the usual day over a 14-day baseline.
    #[test]
    fn ten_times_the_usual_day_is_a_surge() {
        let usual = 3 * MIB;
        let alert = upload_surge(NOW, &uploads(30, 10 * usual, 14 * usual)).unwrap();
        assert_eq!(alert.rule, Rule::UploadSurge);
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.app(), Some("org.example.app"));
        assert_eq!(
            alert.evidence[1],
            Evidence::UploadSurge {
                last_day: 10 * usual,
                usual_day: usual,
                days: 14,
            }
        );
        assert_eq!(
            upload_surge(NOW, &uploads(30, 10 * usual - 1, 14 * usual)),
            None
        );
    }

    #[test]
    fn an_app_that_usually_sends_little_must_still_send_ten_mebibytes() {
        assert_eq!(upload_surge(NOW, &uploads(30, 10 * MIB - 1, 0)), None);
        assert!(upload_surge(NOW, &uploads(30, 10 * MIB, 0)).is_some());
        assert_eq!(MIN_SURGE_BYTES, 10 * MIB);
    }

    #[test]
    fn an_app_known_for_less_than_the_baseline_is_not_judged() {
        assert_eq!(upload_surge(NOW, &uploads(14, 500 * MIB, 0)), None);
        assert!(upload_surge(NOW, &uploads(15, 500 * MIB, 0)).is_some());
    }

    #[test]
    fn the_windows_are_the_last_day_and_the_fourteen_before() {
        assert_eq!(upload_windows(NOW), (NOW - DAY_MS, NOW - 15 * DAY_MS));
    }

    #[test]
    fn the_evidence_is_stored_as_json() {
        assert_eq!(
            crate::evidence_to_json(&[Evidence::UploadSurge {
                last_day: 20,
                usual_day: 2,
                days: 14
            }]),
            r#"[{"type":"upload_surge","last_day":20,"usual_day":2,"days":14}]"#
        );
    }
}

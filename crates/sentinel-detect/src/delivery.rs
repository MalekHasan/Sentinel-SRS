// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether a new alert is worth a notification now (AL-03, AL-04). Alerts that are not
//! notified are still kept and shown in the app.

use crate::{Alert, Severity};

/// Non-critical notifications allowed per app in [`RATE_WINDOW_MS`] (AL-03).
pub const RATE_LIMIT: usize = 3;
/// One hour.
pub const RATE_WINDOW_MS: i64 = 60 * 60 * 1000;

/// How a new alert reaches the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Post a notification.
    Notify,
    /// Do Not Disturb is on and the alert is below High: keep it in the app (AL-04).
    HoldForDoNotDisturb,
    /// The app already had [`RATE_LIMIT`] non-critical notifications as severe or more
    /// in the last hour: keep it in the app (AL-03).
    HoldForRateLimit,
    /// The user said alerts like this are not useful: keep it in the app (AL-05).
    HoldForFeedback,
}

/// A notification already posted, for the rate limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// Unix milliseconds.
    pub at: i64,
    pub severity: Severity,
    /// The app the alert was about, if any; alerts about Sentinel itself count together.
    pub app: Option<String>,
}

/// Decide how `alert` reaches the user at `now`, given whether Do Not Disturb is on, the
/// notifications already posted, and whether the user marked alerts like it "not
/// useful". Critical alerts always notify; High alerts notify through Do Not Disturb but
/// count against the rate limit; Info and Warning alerts wait in the app while Do Not
/// Disturb is on.
///
/// The rate limit counts only notifications as severe as the alert or more: an app that
/// raised three cheap Info alerts must not keep its High alert, such as accessibility
/// access gained, from being notified (audit A-16). One app can therefore have three
/// notifications an hour at each non-critical severity, as its alerts grow more severe.
pub fn delivery(
    alert: &Alert,
    now: i64,
    do_not_disturb: bool,
    sent: &[Sent],
    not_useful: bool,
) -> Delivery {
    if alert.severity == Severity::Critical {
        return Delivery::Notify;
    }
    if not_useful {
        return Delivery::HoldForFeedback;
    }
    if do_not_disturb && alert.severity < Severity::High {
        return Delivery::HoldForDoNotDisturb;
    }
    let since = now.saturating_sub(RATE_WINDOW_MS);
    let recent = sent
        .iter()
        .filter(|s| s.severity != Severity::Critical && s.at > since && s.at <= now)
        .filter(|s| s.severity >= alert.severity)
        .filter(|s| s.app.as_deref() == alert.app())
        .count();
    if recent >= RATE_LIMIT {
        Delivery::HoldForRateLimit
    } else {
        Delivery::Notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Evidence, Rule};

    const NOW: i64 = 10 * RATE_WINDOW_MS;

    fn alert(severity: Severity, app: Option<&str>) -> Alert {
        Alert {
            rule: Rule::MonitoringInterrupted,
            severity,
            created: NOW,
            evidence: app
                .map(|package| Evidence::App {
                    package: package.to_owned(),
                })
                .into_iter()
                .collect(),
        }
    }

    fn sent(at: i64, severity: Severity, app: Option<&str>) -> Sent {
        Sent {
            at,
            severity,
            app: app.map(str::to_owned),
        }
    }

    #[test]
    fn do_not_disturb_holds_info_and_warning_only() {
        for (severity, expected) in [
            (Severity::Info, Delivery::HoldForDoNotDisturb),
            (Severity::Warning, Delivery::HoldForDoNotDisturb),
            (Severity::High, Delivery::Notify),
            (Severity::Critical, Delivery::Notify),
        ] {
            assert_eq!(
                delivery(&alert(severity, None), NOW, true, &[], false),
                expected,
                "{severity:?}"
            );
            assert_eq!(
                delivery(&alert(severity, None), NOW, false, &[], false),
                Delivery::Notify
            );
        }
    }

    #[test]
    fn three_non_critical_notifications_per_hour_per_app() {
        let chat = Some("org.example.chat");
        let three: Vec<Sent> = (1..=3)
            .map(|i| sent(NOW - i * 60_000, Severity::Warning, chat))
            .collect();
        assert_eq!(
            delivery(&alert(Severity::Warning, chat), NOW, false, &three, false),
            Delivery::HoldForRateLimit
        );
        assert_eq!(
            delivery(&alert(Severity::Info, chat), NOW, false, &three, false),
            Delivery::HoldForRateLimit,
            "less severe"
        );
        assert_eq!(
            delivery(&alert(Severity::Critical, chat), NOW, false, &three, false),
            Delivery::Notify,
            "Critical is never held"
        );
        // Other apps, and Sentinel's own alerts, have their own count.
        assert_eq!(
            delivery(
                &alert(Severity::Warning, Some("org.example.mail")),
                NOW,
                false,
                &three,
                false
            ),
            Delivery::Notify
        );
        assert_eq!(
            delivery(&alert(Severity::Warning, None), NOW, false, &three, false),
            Delivery::Notify
        );
        // Critical notifications do not use up the allowance.
        let criticals: Vec<Sent> = (1..=5)
            .map(|i| sent(NOW - i, Severity::Critical, chat))
            .collect();
        assert_eq!(
            delivery(
                &alert(Severity::Warning, chat),
                NOW,
                false,
                &criticals,
                false
            ),
            Delivery::Notify
        );
    }

    /// Audit A-16: notifications less severe than an alert do not use up its allowance,
    /// so three cheap Info alerts cannot keep an app's High alert quiet. High ones still
    /// count against each other.
    #[test]
    fn less_severe_notifications_do_not_use_up_a_more_severe_alerts_allowance() {
        let app = Some("org.example.spy");
        let infos: Vec<Sent> = (1..=3)
            .map(|i| sent(NOW - i * 60_000, Severity::Info, app))
            .collect();
        assert_eq!(
            delivery(&alert(Severity::Info, app), NOW, false, &infos, false),
            Delivery::HoldForRateLimit
        );
        for severity in [Severity::Warning, Severity::High] {
            assert_eq!(
                delivery(&alert(severity, app), NOW, false, &infos, false),
                Delivery::Notify,
                "{severity:?}"
            );
        }
        let highs: Vec<Sent> = (1..=3)
            .map(|i| sent(NOW - i * 60_000, Severity::High, app))
            .collect();
        for severity in [Severity::Info, Severity::Warning, Severity::High] {
            assert_eq!(
                delivery(&alert(severity, app), NOW, false, &highs, false),
                Delivery::HoldForRateLimit,
                "{severity:?}"
            );
        }
    }

    #[test]
    fn the_window_is_one_hour() {
        let app = Some("org.example.chat");
        let edge: Vec<Sent> = (0..3)
            .map(|i| sent(NOW - RATE_WINDOW_MS + i, Severity::Info, app))
            .collect();
        // The first of the three is exactly an hour old: no longer counted.
        assert_eq!(
            delivery(&alert(Severity::Info, app), NOW, false, &edge, false),
            Delivery::Notify
        );
        assert_eq!(
            delivery(&alert(Severity::Info, app), NOW - 1, false, &edge, false),
            Delivery::HoldForRateLimit
        );
    }

    /// AL-05: "not useful" keeps later non-critical alerts in the app.
    #[test]
    fn not_useful_holds_all_but_critical() {
        for severity in [Severity::Info, Severity::Warning, Severity::High] {
            assert_eq!(
                delivery(&alert(severity, None), NOW, false, &[], true),
                Delivery::HoldForFeedback,
                "{severity:?}"
            );
        }
        assert_eq!(
            delivery(&alert(Severity::Critical, None), NOW, false, &[], true),
            Delivery::Notify
        );
    }

    /// AL-03's load test: a flood of alerts for one app, one every second for two
    /// hours, gives exactly three notifications per hour; critical ones all notify.
    #[test]
    fn a_flood_of_alerts_gives_three_notifications_an_hour() {
        let app = Some("org.example.noisy");
        let mut posted: Vec<Sent> = Vec::new();
        let start = NOW;
        for second in 0..2 * 3_600 {
            let at = start + second * 1_000;
            // Every hundredth is critical.
            let severity = if second % 100 == 0 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            let mut new = alert(severity, app);
            new.created = at;
            if delivery(&new, at, false, &posted, false) == Delivery::Notify {
                posted.push(sent(at, severity, app));
            }
        }
        let non_critical: Vec<i64> = posted
            .iter()
            .filter(|s| s.severity != Severity::Critical)
            .map(|s| s.at)
            .collect();
        assert_eq!(non_critical.len(), 6, "{non_critical:?}");
        for window in 0..2 {
            let from = start + window * RATE_WINDOW_MS;
            let in_window = non_critical
                .iter()
                .filter(|at| (from..from + RATE_WINDOW_MS).contains(*at))
                .count();
            assert_eq!(in_window, RATE_LIMIT, "hour {window}");
        }
        assert_eq!(
            posted
                .iter()
                .filter(|s| s.severity == Severity::Critical)
                .count(),
            72
        );
    }
}

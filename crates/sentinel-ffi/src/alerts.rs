// SPDX-License-Identifier: GPL-3.0-or-later
//! Alerts (SRS §12.1) as seen from Kotlin. The app writes each alert's title and
//! explanation in the user's language from its rule and evidence (ADR-0012).

use sentinel_detect::{Action, AlertState, Delivery, Evidence, Rule, Severity};
use sentinel_store::StoredAlert;

/// How urgent an alert is (AL-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertSeverity {
    Info,
    Warning,
    High,
    Critical,
}

/// The rule that raised an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertRule {
    /// Monitoring stopped although the user wanted it on (SP-03).
    MonitoringInterrupted,
}

/// What an alert rests on.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AlertEvidence {
    /// A time monitoring was wanted but not running, with its recorded reason.
    Gap {
        started_ms: Option<i64>,
        reason: String,
    },
    /// An app, by package name.
    App { app: String },
}

/// What the user can do from an alert (SRS §9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AlertAction {
    StartMonitoring,
    /// Open the app's detail screen.
    OpenApp {
        app: String,
    },
}

/// One alert from the history.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryAlert {
    pub id: i64,
    pub rule: AlertRule,
    pub severity: AlertSeverity,
    /// When it was raised, Unix milliseconds.
    pub created_ms: i64,
    pub evidence: Vec<AlertEvidence>,
    /// Most useful first.
    pub actions: Vec<AlertAction>,
    /// False once the user has dismissed it.
    pub open: bool,
    /// When a notification was posted for it; `None` if it was kept in the app only.
    #[uniffi(default = None)]
    pub notified_ms: Option<i64>,
}

/// How a new alert reaches the user (AL-03, AL-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertDelivery {
    /// Post a notification.
    Notify,
    /// Do Not Disturb is on and the alert is below High: it waits in the app.
    HeldForDoNotDisturb,
    /// The app it is about already had three non-critical notifications this hour.
    HeldForRateLimit,
}

impl From<Delivery> for AlertDelivery {
    fn from(delivery: Delivery) -> Self {
        match delivery {
            Delivery::Notify => AlertDelivery::Notify,
            Delivery::HoldForDoNotDisturb => AlertDelivery::HeldForDoNotDisturb,
            Delivery::HoldForRateLimit => AlertDelivery::HeldForRateLimit,
        }
    }
}

/// Implemented by the app: told about each new alert, to notify the user (AL-06).
/// Called on the thread that raised it, after it is stored.
#[uniffi::export(with_foreign)]
pub trait AlertListener: Send + Sync {
    fn raised(&self, alert: HistoryAlert);
}

impl From<StoredAlert> for HistoryAlert {
    fn from(stored: StoredAlert) -> Self {
        let alert = stored.alert;
        HistoryAlert {
            id: stored.id,
            rule: match alert.rule {
                Rule::MonitoringInterrupted => AlertRule::MonitoringInterrupted,
            },
            severity: match alert.severity {
                Severity::Info => AlertSeverity::Info,
                Severity::Warning => AlertSeverity::Warning,
                Severity::High => AlertSeverity::High,
                Severity::Critical => AlertSeverity::Critical,
            },
            created_ms: alert.created,
            actions: alert
                .actions()
                .into_iter()
                .map(|action| match action {
                    Action::StartMonitoring => AlertAction::StartMonitoring,
                    Action::OpenApp { package } => AlertAction::OpenApp { app: package },
                })
                .collect(),
            evidence: alert
                .evidence
                .into_iter()
                .map(|evidence| match evidence {
                    Evidence::Gap { started, reason } => AlertEvidence::Gap {
                        started_ms: started,
                        reason,
                    },
                    Evidence::App { package } => AlertEvidence::App { app: package },
                })
                .collect(),
            open: stored.state == AlertState::Open,
            notified_ms: stored.notified,
        }
    }
}

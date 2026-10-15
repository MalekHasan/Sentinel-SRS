// SPDX-License-Identifier: GPL-3.0-or-later
//! Alerts (SRS §12.1) as seen from Kotlin. The app writes each alert's title and
//! explanation in the user's language from its rule and evidence (ADR-0012).

use sentinel_detect::{Action, AlertState, Delivery, Evidence, Feedback, Rule, Severity};
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
    /// An app installed since the history began used the network for the first time
    /// (CM-04).
    FirstNetworkUse,
    /// An app connected to names it had not used before (CM-04).
    NewDestination,
    /// The DNS servers of the network in use changed (CM-07).
    DnsServersChanged,
    /// The phone's Private DNS provider changed (CM-07).
    PrivateDnsChanged,
    /// The proxy in effect changed (CM-07).
    ProxyChanged,
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
    /// Where an app connected: names, or an address when no name was known, in the
    /// order seen. `more` counts those not listed.
    Destinations {
        destinations: Vec<String>,
        more: u32,
    },
    /// The network's DNS servers before and after a change.
    DnsServers {
        before: Vec<String>,
        after: Vec<String>,
    },
    /// The Private DNS provider before and after a change; `None` when none is named.
    PrivateDns {
        before: Option<String>,
        after: Option<String>,
    },
    /// The proxy in effect before and after a change; `None` for no proxy.
    Proxy {
        before: Option<String>,
        after: Option<String>,
    },
    /// Block-unknown kept the app off the network: it was installed since the mode was
    /// turned on, and no rule allows it.
    NewAppBlocked,
}

/// What the user can do from an alert (SRS §9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AlertAction {
    StartMonitoring,
    /// Open the app's detail screen.
    OpenApp {
        app: String,
    },
    /// Open Android's network settings.
    OpenNetworkSettings,
    /// Let the app use the network: keep a firewall rule allowing it
    /// (`HistoryStore.set_firewall_rule`).
    AllowApp {
        app: String,
    },
    /// Stop the app using the network, open connections included: keep a firewall rule
    /// blocking it (`HistoryStore.set_firewall_rule`).
    BlockApp {
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
    /// What the user said about it (AL-05).
    #[uniffi(default = None)]
    pub feedback: Option<AlertFeedback>,
}

/// What the user says about an alert (AL-05). Kept on the device only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AlertFeedback {
    /// Later alerts like it wait in the app instead of notifying; Critical ones still
    /// notify.
    NotUseful,
    /// No more alerts from this rule about the same app. Not for Critical alerts.
    Allowed,
}

impl From<AlertFeedback> for Feedback {
    fn from(feedback: AlertFeedback) -> Self {
        match feedback {
            AlertFeedback::NotUseful => Feedback::NotUseful,
            AlertFeedback::Allowed => Feedback::Allowed,
        }
    }
}

impl From<Feedback> for AlertFeedback {
    fn from(feedback: Feedback) -> Self {
        match feedback {
            Feedback::NotUseful => AlertFeedback::NotUseful,
            Feedback::Allowed => AlertFeedback::Allowed,
        }
    }
}

/// A rule the user allowed for an app, or for Sentinel itself.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AllowedRule {
    pub rule: AlertRule,
    /// `None` for alerts about Sentinel itself.
    pub app: Option<String>,
    pub created_ms: i64,
}

impl From<Rule> for AlertRule {
    fn from(rule: Rule) -> Self {
        match rule {
            Rule::MonitoringInterrupted => AlertRule::MonitoringInterrupted,
            Rule::FirstNetworkUse => AlertRule::FirstNetworkUse,
            Rule::NewDestination => AlertRule::NewDestination,
            Rule::DnsServersChanged => AlertRule::DnsServersChanged,
            Rule::PrivateDnsChanged => AlertRule::PrivateDnsChanged,
            Rule::ProxyChanged => AlertRule::ProxyChanged,
        }
    }
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
    /// The user said alerts like it are not useful.
    HeldForFeedback,
}

impl From<Delivery> for AlertDelivery {
    fn from(delivery: Delivery) -> Self {
        match delivery {
            Delivery::Notify => AlertDelivery::Notify,
            Delivery::HoldForDoNotDisturb => AlertDelivery::HeldForDoNotDisturb,
            Delivery::HoldForRateLimit => AlertDelivery::HeldForRateLimit,
            Delivery::HoldForFeedback => AlertDelivery::HeldForFeedback,
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
            rule: alert.rule.into(),
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
                    Action::OpenNetworkSettings => AlertAction::OpenNetworkSettings,
                    Action::AllowApp { package } => AlertAction::AllowApp { app: package },
                    Action::BlockApp { package } => AlertAction::BlockApp { app: package },
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
                    Evidence::Destinations { destinations, more } => {
                        AlertEvidence::Destinations { destinations, more }
                    }
                    Evidence::DnsServers { before, after } => {
                        AlertEvidence::DnsServers { before, after }
                    }
                    Evidence::PrivateDns { before, after } => {
                        AlertEvidence::PrivateDns { before, after }
                    }
                    Evidence::Proxy { before, after } => AlertEvidence::Proxy { before, after },
                    Evidence::NewAppBlocked => AlertEvidence::NewAppBlocked,
                })
                .collect(),
            open: stored.state == AlertState::Open,
            notified_ms: stored.notified,
            feedback: stored.feedback.map(Into::into),
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Alerts (SRS §12.1) and the rules that raise them.
//!
//! An alert records which rule raised it, how severe it is (AL-01) and the evidence it
//! rests on. It holds no text: the app writes the title and the one-sentence explanation
//! in the user's language from the rule and the evidence, and offers the rule's actions
//! (AL-02, ADR-0012).

use serde::{Deserialize, Serialize};

mod delivery;
mod firewall;
mod first_seen;
mod network;

pub use delivery::{Delivery, RATE_LIMIT, RATE_WINDOW_MS, Sent, delivery};
pub use firewall::{
    Destination, FirewallMode, FirewallRule, Network, Place, RuleAction, RuleError, RuleSet,
};
pub use first_seen::{
    GROUP_WINDOW_MS, LEARNING_MS, MAX_LISTED, add_destinations, first_network_use,
    join_destinations, new_destinations,
};
pub use network::{NetworkState, network_changes};

/// How urgent an alert is (AL-01). Ordered from least to most urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

impl Severity {
    /// The name stored in the history.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_name(name: &str) -> Option<Severity> {
        [
            Severity::Info,
            Severity::Warning,
            Severity::High,
            Severity::Critical,
        ]
        .into_iter()
        .find(|s| s.as_str() == name)
    }
}

/// The rules that raise alerts. Their ids are stored in the history, so an id never
/// changes or moves to another rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
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

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::MonitoringInterrupted => "monitoring-interrupted",
            Rule::FirstNetworkUse => "first-network-use",
            Rule::NewDestination => "new-destination",
            Rule::DnsServersChanged => "dns-servers-changed",
            Rule::PrivateDnsChanged => "private-dns-changed",
            Rule::ProxyChanged => "proxy-changed",
        }
    }

    pub fn from_id(id: &str) -> Option<Rule> {
        [
            Rule::MonitoringInterrupted,
            Rule::FirstNetworkUse,
            Rule::NewDestination,
            Rule::DnsServersChanged,
            Rule::PrivateDnsChanged,
            Rule::ProxyChanged,
        ]
        .into_iter()
        .find(|r| r.id() == id)
    }

    /// What the user can do about an alert from this rule, most useful first (SRS §9).
    pub fn actions(self, evidence: &[Evidence]) -> Vec<Action> {
        let mut actions = match self {
            Rule::MonitoringInterrupted => vec![Action::StartMonitoring],
            Rule::FirstNetworkUse | Rule::NewDestination => Vec::new(),
            Rule::DnsServersChanged | Rule::PrivateDnsChanged | Rule::ProxyChanged => {
                vec![Action::OpenNetworkSettings]
            }
        };
        // A new app that Block-unknown stopped can be let through (CM-08); an app new to
        // the network, or to some places, can be stopped (RA-01).
        let blocked = evidence.contains(&Evidence::NewAppBlocked);
        let blockable = matches!(self, Rule::FirstNetworkUse | Rule::NewDestination);
        actions.extend(evidence.iter().filter_map(|e| match e {
            Evidence::App { package } if blocked => Some(Action::AllowApp {
                package: package.clone(),
            }),
            Evidence::App { package } if blockable => Some(Action::BlockApp {
                package: package.clone(),
            }),
            _ => None,
        }));
        // Any app the alert is about can be looked at.
        actions.extend(evidence.iter().filter_map(|e| match e {
            Evidence::App { package } => Some(Action::OpenApp {
                package: package.clone(),
            }),
            _ => None,
        }));
        actions
    }
}

/// What an alert rests on: things the history holds or the app saw. Stored as JSON
/// (SRS §13.1 `alert.evidence`); the field names are part of the stored format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// A time monitoring was wanted but not running (SP-03). `started` is Unix
    /// milliseconds, `None` when unknown; `reason` is as recorded with the gap.
    Gap {
        started: Option<i64>,
        reason: String,
    },
    /// An app, by package name.
    App { package: String },
    /// Where an app connected: names, or an address when no name is known, in the
    /// order seen. `more` counts those not listed (see [`MAX_LISTED`]).
    Destinations {
        destinations: Vec<String>,
        more: u32,
    },
    /// The DNS servers of the network in use, before and after a change.
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
    /// Block-unknown kept the app the alert is about off the network: it was installed
    /// since the mode was turned on, and no rule allows it (CM-08).
    NewAppBlocked,
}

/// What the user can do from an alert (SRS §9). Actions that change the device come
/// with the rules that need them (blocking, Sprint 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    StartMonitoring,
    /// Look at what an app did: the app detail screen.
    OpenApp {
        package: String,
    },
    /// Android's network settings, where DNS, Private DNS and proxies are set.
    OpenNetworkSettings,
    /// Let an app use the network: a firewall rule allowing it (CM-08, CM-10).
    AllowApp {
        package: String,
    },
    /// Stop an app using the network, open connections included: a firewall rule
    /// blocking it (RA-01).
    BlockApp {
        package: String,
    },
}

/// One alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub rule: Rule,
    pub severity: Severity,
    /// When it was raised, Unix milliseconds.
    pub created: i64,
    pub evidence: Vec<Evidence>,
}

impl Alert {
    pub fn actions(&self) -> Vec<Action> {
        self.rule.actions(&self.evidence)
    }

    /// The app the alert is about: the first app in its evidence. `None` for alerts
    /// about Sentinel itself, such as a monitoring gap.
    pub fn app(&self) -> Option<&str> {
        self.evidence.iter().find_map(|e| match e {
            Evidence::App { package } => Some(package.as_str()),
            _ => None,
        })
    }
}

/// What the user said about an alert (AL-05). It stays on the device and changes only
/// how Sentinel alerts this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    /// Alerts like this are not useful: later ones about the same app wait in the app
    /// instead of notifying. Critical alerts still notify.
    NotUseful,
    /// Allow what the alert was about: no more alerts from this rule about the same app.
    /// Not offered for Critical alerts (see [`Feedback::allowed_for`]).
    Allowed,
}

impl Feedback {
    pub fn as_str(self) -> &'static str {
        match self {
            Feedback::NotUseful => "not_useful",
            Feedback::Allowed => "allowed",
        }
    }

    pub fn from_name(name: &str) -> Option<Feedback> {
        [Feedback::NotUseful, Feedback::Allowed]
            .into_iter()
            .find(|f| f.as_str() == name)
    }

    /// Whether this feedback may be given on an alert of `severity`. A Critical alert
    /// cannot be allowed: someone else holding the phone could otherwise silence what
    /// it found for good.
    pub fn allowed_for(self, severity: Severity) -> bool {
        self != Feedback::Allowed || severity < Severity::Critical
    }
}

/// Whether an alert still asks for attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    Open,
    /// The user has seen it and put it away.
    Dismissed,
}

impl AlertState {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertState::Open => "open",
            AlertState::Dismissed => "dismissed",
        }
    }

    pub fn from_name(name: &str) -> Option<AlertState> {
        [AlertState::Open, AlertState::Dismissed]
            .into_iter()
            .find(|s| s.as_str() == name)
    }
}

/// Evidence as stored.
pub fn evidence_to_json(evidence: &[Evidence]) -> String {
    // Serializing these types cannot fail: no maps with non-string keys, no floats.
    serde_json::to_string(evidence).unwrap_or_else(|_| "[]".to_owned())
}

pub fn evidence_from_json(json: &str) -> Result<Vec<Evidence>, serde_json::Error> {
    serde_json::from_str(json)
}

/// SP-03: monitoring stopped while the user wanted it on, at `started` (if known), for
/// `reason`. A stop the user asked for is not a gap and raises nothing.
pub fn monitoring_interrupted(now: i64, started: Option<i64>, reason: &str) -> Alert {
    Alert {
        rule: Rule::MonitoringInterrupted,
        severity: Severity::Warning,
        created: now,
        evidence: vec![Evidence::Gap {
            started,
            reason: reason.to_owned(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_ordered_and_named() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::High);
        assert!(Severity::High < Severity::Critical);
        for severity in [
            Severity::Info,
            Severity::Warning,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_name(severity.as_str()), Some(severity));
        }
        assert_eq!(Severity::from_name("Warning"), None);
    }

    #[test]
    fn rule_ids_and_states_are_stable() {
        assert_eq!(Rule::MonitoringInterrupted.id(), "monitoring-interrupted");
        assert_eq!(
            Rule::from_id("monitoring-interrupted"),
            Some(Rule::MonitoringInterrupted)
        );
        assert_eq!(Rule::from_id("no-such-rule"), None);
        for state in [AlertState::Open, AlertState::Dismissed] {
            assert_eq!(AlertState::from_name(state.as_str()), Some(state));
        }
    }

    /// The stored form is part of the history's format: it must not change by accident.
    #[test]
    fn evidence_is_stored_as_tagged_json() {
        let evidence = vec![
            Evidence::Gap {
                started: Some(1_000),
                reason: "revoked".to_owned(),
            },
            Evidence::Gap {
                started: None,
                reason: "killed".to_owned(),
            },
            Evidence::App {
                package: "org.example.chat".to_owned(),
            },
            Evidence::Destinations {
                destinations: vec!["a.example".to_owned(), "192.0.2.1".to_owned()],
                more: 3,
            },
            Evidence::NewAppBlocked,
        ];
        let json = evidence_to_json(&evidence);
        assert_eq!(
            json,
            r#"[{"type":"gap","started":1000,"reason":"revoked"},{"type":"gap","started":null,"reason":"killed"},{"type":"app","package":"org.example.chat"},{"type":"destinations","destinations":["a.example","192.0.2.1"],"more":3},{"type":"new_app_blocked"}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), evidence);
        assert!(evidence_from_json(r#"[{"type":"unknown"}]"#).is_err());
        assert!(evidence_from_json("not json").is_err());
    }

    #[test]
    fn feedback_is_named_and_critical_alerts_cannot_be_allowed() {
        for feedback in [Feedback::NotUseful, Feedback::Allowed] {
            assert_eq!(Feedback::from_name(feedback.as_str()), Some(feedback));
            assert!(feedback.allowed_for(Severity::High));
        }
        assert!(Feedback::NotUseful.allowed_for(Severity::Critical));
        assert!(!Feedback::Allowed.allowed_for(Severity::Critical));
        assert_eq!(Feedback::from_name("useful"), None);
    }

    #[test]
    fn monitoring_interrupted_is_a_warning_offering_to_start_again() {
        let alert = monitoring_interrupted(5_000, Some(4_000), "revoked");
        assert_eq!(alert.rule, Rule::MonitoringInterrupted);
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.created, 5_000);
        assert_eq!(
            alert.evidence,
            [Evidence::Gap {
                started: Some(4_000),
                reason: "revoked".to_owned()
            }]
        );
        assert_eq!(alert.actions(), [Action::StartMonitoring]);
    }

    #[test]
    fn apps_in_the_evidence_can_be_opened() {
        let evidence = [
            Evidence::App {
                package: "org.example.a".to_owned(),
            },
            Evidence::Gap {
                started: None,
                reason: "r".to_owned(),
            },
        ];
        assert_eq!(
            Rule::MonitoringInterrupted.actions(&evidence),
            [
                Action::StartMonitoring,
                Action::OpenApp {
                    package: "org.example.a".to_owned()
                }
            ]
        );
    }
}

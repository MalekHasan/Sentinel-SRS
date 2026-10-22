// SPDX-License-Identifier: GPL-3.0-or-later
//! Alerts (SRS §12.1) and the rules that raise them.
//!
//! An alert records which rule raised it, how severe it is (AL-01) and the evidence it
//! rests on. It holds no text: the app writes the title and the one-sentence explanation
//! in the user's language from the rule and the evidence, and offers the rule's actions
//! (AL-02, ADR-0012).

use serde::{Deserialize, Serialize};

mod access;
mod beacon;
mod delivery;
mod dns_use;
mod firewall;
mod first_seen;
mod hardening;
mod indicator;
mod journal;
mod network;
mod posture;
mod sensor;
mod sharing;
mod upload;

pub use access::{Access, special_access};
pub use beacon::{
    BEACON_CHECK_INS, BEACON_MAX_BYTES, BEACON_MAX_INTERVAL_MS, BEACON_MIN_INTERVAL_MS, Beacon,
    Beacons, beacon_like,
};
pub use delivery::{Delivery, RATE_LIMIT, RATE_WINDOW_MS, Sent, delivery};
pub use dns_use::{
    DNS_WINDOW_MS, DnsTunnel, DnsWatch, QTYPE_TXT, TUNNEL_NAMES, TUNNEL_TXT_LOOKUPS, dns_tunnel,
    encrypted_dns, own_encrypted_dns,
};
pub use firewall::{
    Destination, FirewallMode, FirewallRule, Isolation, Network, Owner, Place, RuleAction,
    RuleError, RuleSet,
};
pub use first_seen::{
    GROUP_WINDOW_MS, LEARNING_MS, MAX_LISTED, add_destinations, first_network_use,
    join_destinations, new_destinations,
};
pub use hardening::{Facts, Item, Status, Step, UPDATE_MAX_AGE_DAYS, checklist};
pub use indicator::{
    IndicatorMatch, Sighting, Threat, known_indicator, known_indicator_in_history, same_sighting,
};
pub use journal::{Change, Setting};
pub use network::{NetworkState, network_changes};
pub use posture::{Certificate, Posture, RemoteAccess, posture_changes};
pub use sensor::{Attribution, Sensor, sensor_while_away};
pub use sharing::{SHARING_UPLOAD_BYTES, SharingSite, sharing_site, sharing_site_upload};
pub use upload::{
    BASELINE_DAYS, MIN_SURGE_BYTES, MIN_USUAL_DAY_BYTES, SURGE_FACTOR, Uploads, upload_surge,
    upload_windows,
};

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
    /// An app's traffic named a known indicator of spyware or stalkerware (ID-13).
    KnownIndicator,
    /// An app gained accessibility, device admin or notification access (ID-12).
    SpecialAccess,
    /// A way in from the network was turned on, such as wireless debugging (ID-03).
    RemoteAccessExposed,
    /// The user added a certificate authority to the trusted ones (ID-10).
    NewRootCertificate,
    /// The microphone or camera was in use while the screen was off or locked (SE-04).
    SensorWhileAway,
    /// An app had as many connections open as it may; Sentinel refused more
    /// (THREAT-MODEL-A D2).
    FlowLimit,
    /// An app connects to the same place at a fixed interval with little data each time,
    /// as spyware checking in does (DL-04).
    BeaconLike,
    /// An app's DNS lookups look like data hidden in them, as DNS tunnels carry it
    /// (DL-05).
    DnsTunnel,
    /// An app reached an encrypted DNS service itself, by-passing the phone's resolver
    /// (DL-05).
    OwnEncryptedDns,
    /// An app sent far more in a day than it usually does (DL-02).
    UploadSurge,
    /// An app uploaded to a file-sharing, paste or anonymous drop service not its own
    /// (DL-06).
    SharingSiteUpload,
    /// The history could not be opened, so a new one was started: what the old one held
    /// is gone (THREAT-MODEL-A T6).
    HistoryStartedAnew,
    /// Monitoring stopped again and again although the user wanted it on (SP-02).
    MonitoringKeepsStopping,
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
            Rule::KnownIndicator => "known-indicator",
            Rule::SpecialAccess => "special-access",
            Rule::RemoteAccessExposed => "remote-access-exposed",
            Rule::NewRootCertificate => "new-root-certificate",
            Rule::SensorWhileAway => "sensor-while-away",
            Rule::FlowLimit => "flow-limit",
            Rule::BeaconLike => "beacon-like",
            Rule::DnsTunnel => "dns-tunnel",
            Rule::OwnEncryptedDns => "own-encrypted-dns",
            Rule::UploadSurge => "upload-surge",
            Rule::SharingSiteUpload => "sharing-site-upload",
            Rule::HistoryStartedAnew => "history-started-anew",
            Rule::MonitoringKeepsStopping => "monitoring-keeps-stopping",
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
            Rule::KnownIndicator,
            Rule::SpecialAccess,
            Rule::RemoteAccessExposed,
            Rule::NewRootCertificate,
            Rule::SensorWhileAway,
            Rule::FlowLimit,
            Rule::BeaconLike,
            Rule::DnsTunnel,
            Rule::OwnEncryptedDns,
            Rule::UploadSurge,
            Rule::SharingSiteUpload,
            Rule::HistoryStartedAnew,
            Rule::MonitoringKeepsStopping,
        ]
        .into_iter()
        .find(|r| r.id() == id)
    }

    /// What the user can do about an alert from this rule, most useful first (SRS §9).
    pub fn actions(self, evidence: &[Evidence]) -> Vec<Action> {
        let mut actions = match self {
            Rule::MonitoringInterrupted => vec![Action::StartMonitoring],
            // The steps that keep monitoring running, the phone maker's among them.
            Rule::MonitoringKeepsStopping => vec![Action::OpenKeepRunning],
            Rule::FirstNetworkUse
            | Rule::NewDestination
            | Rule::KnownIndicator
            | Rule::FlowLimit
            | Rule::BeaconLike
            | Rule::DnsTunnel
            | Rule::OwnEncryptedDns
            | Rule::UploadSurge
            | Rule::SharingSiteUpload
            | Rule::HistoryStartedAnew => Vec::new(),
            Rule::DnsServersChanged | Rule::PrivateDnsChanged | Rule::ProxyChanged => {
                vec![Action::OpenNetworkSettings]
            }
            // Where the access can be turned off (ID-12).
            Rule::SpecialAccess => evidence
                .iter()
                .filter_map(|e| match e {
                    Evidence::Access { access } => {
                        Some(Action::OpenAccessSettings { access: *access })
                    }
                    _ => None,
                })
                .collect(),
            // Where it can be turned off (ID-03) or the certificate removed (ID-10).
            Rule::RemoteAccessExposed => vec![Action::OpenDeveloperSettings],
            Rule::NewRootCertificate => vec![Action::OpenCertificateSettings],
            // Android's privacy dashboard knows which app it was (SE-01 basic, AM-15).
            Rule::SensorWhileAway => vec![Action::OpenPrivacySettings],
        };
        // A new app that Block-unknown stopped can be let through (CM-08); an app new to
        // the network, or to some places, seen with a known indicator, or that gained
        // special access, can be stopped (RA-01).
        let blocked = evidence.contains(&Evidence::NewAppBlocked);
        let blockable = matches!(
            self,
            Rule::FirstNetworkUse
                | Rule::NewDestination
                | Rule::KnownIndicator
                | Rule::SpecialAccess
                | Rule::FlowLimit
                | Rule::BeaconLike
                | Rule::DnsTunnel
                | Rule::OwnEncryptedDns
                | Rule::UploadSurge
                | Rule::SharingSiteUpload
        );
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
    /// A known indicator the app's traffic named, with its provenance (ID-13, MS-10).
    Indicator(IndicatorMatch),
    /// The traffic was found in the history, after the fact (MS-02): `connections`
    /// connections, the first made at `first` and the last ended at `last`, Unix
    /// milliseconds. Rolled-up days count from their midnight UTC.
    PastConnections {
        first: i64,
        last: i64,
        connections: u64,
    },
    /// Special access the app the alert is about holds (ID-12).
    Access { access: Access },
    /// A way in from the network that is on (ID-03).
    RemoteAccess { service: RemoteAccess },
    /// A certificate authority the user added to the trusted ones (ID-10): its SHA-256
    /// in lower-case hex, and who it was issued to.
    Certificate { sha256: String, subject: String },
    /// The app had `limit` connections open at once, as many as it may; more were
    /// refused (THREAT-MODEL-A D2).
    FlowLimit { limit: u32 },
    /// Monitoring stopped `count` times in the last `hours` hours, though the user
    /// wanted it on (SP-02).
    RepeatedGaps { count: u32, hours: u32 },
    /// The app connected to `destination` (a name, or an address when no name is known)
    /// `check_ins` times in a row, typically every `interval_ms` milliseconds, each time
    /// with at most `max_bytes` both ways (DL-04).
    Beacon {
        destination: String,
        interval_ms: i64,
        check_ins: u32,
        max_bytes: u64,
    },
    /// The app looked up `names` different random-looking names under `domain` within
    /// a few minutes, such as `example` (DL-05).
    DnsNames {
        domain: String,
        names: u32,
        example: String,
    },
    /// The app made `lookups` TXT lookups within a few minutes (DL-05).
    DnsTxtLookups { lookups: u32 },
    /// The app reached `server`, an encrypted DNS service, itself (DL-05).
    EncryptedDns { server: String },
    /// The app sent `last_day` bytes in the last day, where it usually sends `usual_day`
    /// a day, over the `days` before (DL-02).
    UploadSurge {
        last_day: u64,
        usual_day: u64,
        days: u32,
    },
    /// The app sent `bytes_up` in one connection to `destination`, a sharing service of
    /// the kind `site` (DL-06).
    SharingSite {
        destination: String,
        site: SharingSite,
        bytes_up: u64,
    },
    /// A sensor in use since `started` (Unix ms) (SE-01). `guess` is the app that was on
    /// screen when the use began, if known: a guess, not the app's identity (AM-15).
    Sensor {
        sensor: Sensor,
        started: i64,
        guess: Option<String>,
    },
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
    /// Android's settings for a kind of special access, where it can be turned off
    /// (ID-12).
    OpenAccessSettings {
        access: Access,
    },
    /// Android's developer options, where wireless debugging is turned off (ID-03).
    OpenDeveloperSettings,
    /// Android's trusted certificates, where one can be removed (ID-10).
    OpenCertificateSettings,
    /// Android's privacy settings, whose dashboard names the apps that used a sensor
    /// (SE-01 basic).
    OpenPrivacySettings,
    /// Sentinel's "Keep monitoring running" steps: battery settings, always-on VPN and
    /// the phone maker's own (SP-03, ADR-0030).
    OpenKeepRunning,
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

    /// What allowing the alert allows besides its rule and app (AL-05): for special
    /// access, the kind it is about and no other, so that an app allowed to read
    /// notifications is still reported once it can see the screen (audit A-38). `None`
    /// for other rules.
    pub fn allowed_access(&self) -> Option<Access> {
        if self.rule != Rule::SpecialAccess {
            return None;
        }
        self.evidence.iter().find_map(|e| match e {
            Evidence::Access { access } => Some(*access),
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
    /// Allow what the alert was about: no more alerts from this rule about the same app,
    /// and for special access, the same kind of it (see [`Alert::allowed_access`]). Only
    /// for an alert about an app, and not a Critical one (see [`Feedback::allowed_on`]).
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

    /// Whether this feedback may be given on `alert`. Allowing silences one rule's alerts
    /// about one app for good, so it is refused for a Critical alert, which someone else
    /// holding the phone could otherwise silence, and for an alert about no app, which
    /// would silence the rule for the whole phone: the microphone used while the screen
    /// is off, a gap, a certificate added (audit A-08).
    pub fn allowed_on(self, alert: &Alert) -> bool {
        self != Feedback::Allowed || (alert.severity < Severity::Critical && alert.app().is_some())
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

/// THREAT-MODEL-A D2: `app` had `limit` connections open at once, and Sentinel refused
/// more. A Warning: the app may simply be busy, or may be flooding the network.
pub fn flow_limit(now: i64, app: &str, limit: u32) -> Alert {
    Alert {
        rule: Rule::FlowLimit,
        severity: Severity::Warning,
        created: now,
        evidence: vec![
            Evidence::App {
                package: app.to_owned(),
            },
            Evidence::FlowLimit { limit },
        ],
    }
}

/// How many gaps, within [`REPEATED_GAPS_HOURS`], make monitoring "keep stopping"
/// (SP-02).
pub const REPEATED_GAPS: u32 = 3;
/// The window [`REPEATED_GAPS`] are counted in.
pub const REPEATED_GAPS_HOURS: u32 = 24;

/// SP-02: monitoring stopped `count` times in the last [`REPEATED_GAPS_HOURS`] hours. A
/// Critical alert from [`REPEATED_GAPS`] on: while monitoring keeps stopping, the phone
/// is not watched, whether its maker's battery settings, another app or a fault in
/// Sentinel stop it.
pub fn monitoring_keeps_stopping(now: i64, count: u32) -> Option<Alert> {
    (count >= REPEATED_GAPS).then(|| Alert {
        rule: Rule::MonitoringKeepsStopping,
        severity: Severity::Critical,
        created: now,
        evidence: vec![Evidence::RepeatedGaps {
            count,
            hours: REPEATED_GAPS_HOURS,
        }],
    })
}

/// THREAT-MODEL-A T6: the history could not be opened (its key is gone, or the file was
/// changed), so a new one was started. Raised in the new history, so that the loss of
/// the old one is not silent.
pub fn history_started_anew(now: i64) -> Alert {
    Alert {
        rule: Rule::HistoryStartedAnew,
        severity: Severity::Warning,
        created: now,
        evidence: Vec::new(),
    }
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
        assert_eq!(Rule::from_id("special-access"), Some(Rule::SpecialAccess));
        assert_eq!(
            Rule::from_id("remote-access-exposed"),
            Some(Rule::RemoteAccessExposed)
        );
        assert_eq!(
            Rule::from_id("new-root-certificate"),
            Some(Rule::NewRootCertificate)
        );
        assert_eq!(
            Rule::from_id("sensor-while-away"),
            Some(Rule::SensorWhileAway)
        );
        assert_eq!(Rule::from_id("flow-limit"), Some(Rule::FlowLimit));
        assert_eq!(Rule::from_id("beacon-like"), Some(Rule::BeaconLike));
        assert_eq!(Rule::from_id("dns-tunnel"), Some(Rule::DnsTunnel));
        assert_eq!(Rule::from_id("upload-surge"), Some(Rule::UploadSurge));
        assert_eq!(
            Rule::from_id("sharing-site-upload"),
            Some(Rule::SharingSiteUpload)
        );
        assert_eq!(
            Rule::from_id("own-encrypted-dns"),
            Some(Rule::OwnEncryptedDns)
        );
        assert_eq!(
            Rule::from_id("history-started-anew"),
            Some(Rule::HistoryStartedAnew)
        );
        assert_eq!(
            Rule::from_id("monitoring-keeps-stopping"),
            Some(Rule::MonitoringKeepsStopping)
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

    /// AL-05: feedback is stored by name. Only an alert about an app, and not a Critical
    /// one, can be allowed (audit A-08); any can be marked not useful.
    #[test]
    fn feedback_is_named_and_only_an_apps_alerts_below_critical_can_be_allowed() {
        let about = |app: Option<&str>, severity| Alert {
            rule: Rule::SensorWhileAway,
            severity,
            created: 0,
            evidence: app
                .map(|package| Evidence::App {
                    package: package.to_owned(),
                })
                .into_iter()
                .collect(),
        };
        for feedback in [Feedback::NotUseful, Feedback::Allowed] {
            assert_eq!(Feedback::from_name(feedback.as_str()), Some(feedback));
            assert!(feedback.allowed_on(&about(Some("org.example.app"), Severity::High)));
        }
        assert!(!Feedback::Allowed.allowed_on(&about(Some("org.example.app"), Severity::Critical)));
        assert!(
            !Feedback::Allowed.allowed_on(&about(None, Severity::High)),
            "no app"
        );
        assert!(Feedback::NotUseful.allowed_on(&about(None, Severity::Critical)));
        assert_eq!(Feedback::from_name("useful"), None);
    }

    /// THREAT-MODEL-A D2: a Warning about the app, which can be blocked or looked at,
    /// stored with its limit.
    #[test]
    fn an_app_at_its_flow_limit_raises_a_warning() {
        let alert = flow_limit(3, "org.example.flood", 256);
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.app(), Some("org.example.flood"));
        let app = || "org.example.flood".to_owned();
        assert_eq!(
            alert.actions(),
            [
                Action::BlockApp { package: app() },
                Action::OpenApp { package: app() }
            ]
        );
        let json = evidence_to_json(&alert.evidence);
        assert_eq!(
            json,
            r#"[{"type":"app","package":"org.example.flood"},{"type":"flow_limit","limit":256}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), alert.evidence);
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
    fn monitoring_that_keeps_stopping_is_critical_from_the_third_gap() {
        assert_eq!(monitoring_keeps_stopping(9, REPEATED_GAPS - 1), None);
        let alert = monitoring_keeps_stopping(9, REPEATED_GAPS).unwrap();
        assert_eq!(alert.rule, Rule::MonitoringKeepsStopping);
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.app(), None);
        assert_eq!(alert.actions(), [Action::OpenKeepRunning]);
        assert_eq!(
            evidence_to_json(&alert.evidence),
            r#"[{"type":"repeated_gaps","count":3,"hours":24}]"#
        );
    }

    #[test]
    fn a_history_started_anew_is_a_warning_about_no_app() {
        let alert = history_started_anew(5_000);
        assert_eq!(alert.rule, Rule::HistoryStartedAnew);
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.created, 5_000);
        assert_eq!(alert.app(), None);
        assert!(alert.evidence.is_empty());
        assert!(alert.actions().is_empty());
        assert_eq!(evidence_to_json(&alert.evidence), "[]");
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

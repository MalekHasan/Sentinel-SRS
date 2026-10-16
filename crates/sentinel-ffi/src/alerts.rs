// SPDX-License-Identifier: GPL-3.0-or-later
//! Alerts (SRS §12.1) as seen from Kotlin. The app writes each alert's title and
//! explanation in the user's language from its rule and evidence (ADR-0012).

use sentinel_detect::{
    Access, Action, AlertState, Delivery, Evidence, Feedback, RemoteAccess, Rule, Sensor, Severity,
    Sighting, Threat,
};
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
    /// An app had as many connections open as it may; more were refused
    /// (THREAT-MODEL-A D2).
    FlowLimit,
    /// An app connects to the same place at a fixed interval with little data each time
    /// (DL-04).
    BeaconLike,
    /// An app's DNS lookups look like data hidden in them (DL-05).
    DnsTunnel,
    /// An app reached an encrypted DNS service itself (DL-05).
    OwnEncryptedDns,
}

/// A sensor whose use is recorded (SE-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SensorKind {
    Microphone,
    Camera,
}

impl From<SensorKind> for Sensor {
    fn from(sensor: SensorKind) -> Self {
        match sensor {
            SensorKind::Microphone => Sensor::Microphone,
            SensorKind::Camera => Sensor::Camera,
        }
    }
}

impl From<Sensor> for SensorKind {
    fn from(sensor: Sensor) -> Self {
        match sensor {
            Sensor::Microphone => SensorKind::Microphone,
            Sensor::Camera => SensorKind::Camera,
        }
    }
}

/// A way in from the network that the user can turn on (ID-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemoteAccessService {
    /// ADB over Wi-Fi.
    WirelessDebugging,
}

/// Special access an app holds (ID-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SpecialAccess {
    /// An accessibility service: the app can read the screen and act for the user.
    Accessibility,
    /// A device admin app: it can lock or wipe the phone, and cannot be uninstalled
    /// while it is one.
    DeviceAdmin,
    /// Notification access: the app reads every notification.
    NotificationListener,
}

impl From<SpecialAccess> for Access {
    fn from(access: SpecialAccess) -> Self {
        match access {
            SpecialAccess::Accessibility => Access::Accessibility,
            SpecialAccess::DeviceAdmin => Access::DeviceAdmin,
            SpecialAccess::NotificationListener => Access::NotificationListener,
        }
    }
}

impl From<Access> for SpecialAccess {
    fn from(access: Access) -> Self {
        match access {
            Access::Accessibility => SpecialAccess::Accessibility,
            Access::DeviceAdmin => SpecialAccess::DeviceAdmin,
            Access::NotificationListener => SpecialAccess::NotificationListener,
        }
    }
}

/// How the traffic showed an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IndicatorSighting {
    /// The app looked the name up.
    DnsQuery,
    /// The app named the server when it opened a TLS connection.
    ServerName,
    /// The app connected to the address.
    Address,
    /// The history holds the app's connections to this name, learned from a DNS answer
    /// or a TLS handshake.
    ConnectionName,
    /// The app is installed under this package name.
    InstalledPackage,
    /// The app is signed with the certificate whose SHA-256 this is.
    SigningCertificate,
}

/// The kind of threat an indicator belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum IndicatorThreat {
    /// Mercenary spyware, such as Pegasus or Predator.
    Spyware,
    /// Stalkerware and remote-access tools sold to watch a partner or relative.
    Stalkerware,
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
    /// A known indicator the traffic named, with its provenance (MS-10): the family and
    /// threat, the source that lists it, and the report that names it, with its date
    /// (`YYYY-MM-DD`).
    Indicator {
        /// The indicator as the list gives it: a domain or an address.
        indicator: String,
        /// What the traffic named: the domain or a name below it, or the address.
        seen: String,
        sighting: IndicatorSighting,
        family: String,
        threat: IndicatorThreat,
        source: String,
        date: String,
        report: String,
    },
    /// Found in the history after the fact (MS-02): `connections` connections, the
    /// first made at `first_ms` and the last ended at `last_ms`. Rolled-up days count
    /// from their midnight UTC.
    PastConnections {
        first_ms: i64,
        last_ms: i64,
        connections: u64,
    },
    /// Special access the app holds (ID-12).
    Access { access: SpecialAccess },
    /// A way in from the network that is on (ID-03).
    RemoteAccess { service: RemoteAccessService },
    /// A certificate authority the user added to the trusted ones (ID-10): its SHA-256
    /// in lower-case hex, and who it was issued to.
    Certificate { sha256: String, subject: String },
    /// The app had `limit` connections open at once, as many as it may; more were
    /// refused.
    FlowLimit { limit: u32 },
    /// The app connected to `destination` (a name, or an address when no name is known)
    /// `check_ins` times in a row, typically every `interval_ms`, each time with at most
    /// `max_bytes` both ways (DL-04).
    Beacon {
        destination: String,
        interval_ms: i64,
        check_ins: u32,
        max_bytes: u64,
    },
    /// The app looked up `names` different random-looking names under `domain` within a
    /// few minutes, such as `example` (DL-05).
    DnsNames {
        domain: String,
        names: u32,
        example: String,
    },
    /// The app made `lookups` TXT lookups within a few minutes (DL-05).
    DnsTxtLookups { lookups: u32 },
    /// The app reached `server`, an encrypted DNS service, itself (DL-05).
    EncryptedDns { server: String },
    /// A sensor in use since `started_ms` (SE-01). `guess` is the app that was on screen
    /// when the use began, if known: a guess, not the app's identity.
    Sensor {
        sensor: SensorKind,
        started_ms: i64,
        guess: Option<String>,
    },
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
    /// Open Android's settings for this kind of special access, where it can be turned
    /// off (ID-12).
    OpenAccessSettings {
        access: SpecialAccess,
    },
    /// Open Android's developer options, where wireless debugging is turned off (ID-03).
    OpenDeveloperSettings,
    /// Open Android's trusted certificates, where one can be removed (ID-10).
    OpenCertificateSettings,
    /// Open Android's privacy settings, whose dashboard names the apps that used a
    /// sensor (SE-01 basic).
    OpenPrivacySettings,
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
            Rule::KnownIndicator => AlertRule::KnownIndicator,
            Rule::SpecialAccess => AlertRule::SpecialAccess,
            Rule::RemoteAccessExposed => AlertRule::RemoteAccessExposed,
            Rule::NewRootCertificate => AlertRule::NewRootCertificate,
            Rule::SensorWhileAway => AlertRule::SensorWhileAway,
            Rule::FlowLimit => AlertRule::FlowLimit,
            Rule::BeaconLike => AlertRule::BeaconLike,
            Rule::DnsTunnel => AlertRule::DnsTunnel,
            Rule::OwnEncryptedDns => AlertRule::OwnEncryptedDns,
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
                    Action::OpenAccessSettings { access } => AlertAction::OpenAccessSettings {
                        access: access.into(),
                    },
                    Action::OpenDeveloperSettings => AlertAction::OpenDeveloperSettings,
                    Action::OpenCertificateSettings => AlertAction::OpenCertificateSettings,
                    Action::OpenPrivacySettings => AlertAction::OpenPrivacySettings,
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
                    Evidence::Indicator(matched) => AlertEvidence::Indicator {
                        indicator: matched.indicator,
                        seen: matched.seen,
                        sighting: match matched.sighting {
                            Sighting::DnsQuery => IndicatorSighting::DnsQuery,
                            Sighting::ServerName => IndicatorSighting::ServerName,
                            Sighting::Address => IndicatorSighting::Address,
                            Sighting::ConnectionName => IndicatorSighting::ConnectionName,
                            Sighting::InstalledPackage => IndicatorSighting::InstalledPackage,
                            Sighting::SigningCertificate => IndicatorSighting::SigningCertificate,
                        },
                        family: matched.family,
                        threat: match matched.threat {
                            Threat::Spyware => IndicatorThreat::Spyware,
                            Threat::Stalkerware => IndicatorThreat::Stalkerware,
                        },
                        source: matched.source,
                        date: matched.date,
                        report: matched.report,
                    },
                    Evidence::PastConnections {
                        first,
                        last,
                        connections,
                    } => AlertEvidence::PastConnections {
                        first_ms: first,
                        last_ms: last,
                        connections,
                    },
                    Evidence::Access { access } => AlertEvidence::Access {
                        access: access.into(),
                    },
                    Evidence::RemoteAccess { service } => AlertEvidence::RemoteAccess {
                        service: match service {
                            RemoteAccess::WirelessDebugging => {
                                RemoteAccessService::WirelessDebugging
                            }
                        },
                    },
                    Evidence::Certificate { sha256, subject } => {
                        AlertEvidence::Certificate { sha256, subject }
                    }
                    Evidence::FlowLimit { limit } => AlertEvidence::FlowLimit { limit },
                    Evidence::Beacon {
                        destination,
                        interval_ms,
                        check_ins,
                        max_bytes,
                    } => AlertEvidence::Beacon {
                        destination,
                        interval_ms,
                        check_ins,
                        max_bytes,
                    },
                    Evidence::DnsNames {
                        domain,
                        names,
                        example,
                    } => AlertEvidence::DnsNames {
                        domain,
                        names,
                        example,
                    },
                    Evidence::DnsTxtLookups { lookups } => AlertEvidence::DnsTxtLookups { lookups },
                    Evidence::EncryptedDns { server } => AlertEvidence::EncryptedDns { server },
                    Evidence::Sensor {
                        sensor,
                        started,
                        guess,
                    } => AlertEvidence::Sensor {
                        sensor: sensor.into(),
                        started_ms: started,
                        guess,
                    },
                })
                .collect(),
            open: stored.state == AlertState::Open,
            notified_ms: stored.notified,
            feedback: stored.feedback.map(Into::into),
        }
    }
}

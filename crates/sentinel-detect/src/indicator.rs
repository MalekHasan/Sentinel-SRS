// SPDX-License-Identifier: GPL-3.0-or-later
//! Known indicators of spyware and stalkerware in the phone's traffic (ID-13): a name an
//! app looked up or connected to, or an address it connected to, that the signed
//! indicator list names (MS-10, ADR-0020). Also in the traffic the history kept from
//! before the list arrived (MS-02, ADR-0021).

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// How the traffic showed an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sighting {
    /// An app looked the name up.
    DnsQuery,
    /// An app named the server when it opened a TLS connection.
    ServerName,
    /// An app connected to the address.
    Address,
    /// The history holds connections by an app to this name, learned from a DNS answer
    /// or a TLS handshake; it does not keep which (MS-02).
    ConnectionName,
}

/// The kind of threat an indicator belongs to, as its report says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Threat {
    /// Mercenary spyware, such as Pegasus or Predator.
    Spyware,
    /// Stalkerware and remote-access tools sold to watch a partner or relative.
    Stalkerware,
}

/// An indicator the traffic matched, with its provenance (MS-10). Kept as an alert's
/// evidence: the field names are part of the stored format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndicatorMatch {
    /// The indicator as the list gives it: a domain or an address.
    pub indicator: String,
    /// What the traffic named: the domain or a name below it, or the address.
    pub seen: String,
    pub sighting: Sighting,
    /// The spyware or stalkerware family, as the report names it.
    pub family: String,
    pub threat: Threat,
    /// The source that lists it, by name.
    pub source: String,
    /// When the report that names it was published: `YYYY-MM-DD`.
    pub date: String,
    /// The report that names it.
    pub report: String,
}

/// ID-13: the traffic of `app`, or of an app not known, showed a known indicator. An
/// indicator match is Critical (SRS §8.3), so it reaches the user through Do Not Disturb
/// and cannot be allowed away (AL-05). Nothing is blocked without the user (SRS §9).
pub fn known_indicator(now: i64, app: Option<&str>, matched: IndicatorMatch) -> Alert {
    let mut evidence = Vec::with_capacity(2);
    if let Some(app) = app {
        evidence.push(Evidence::App {
            package: app.to_owned(),
        });
    }
    evidence.push(Evidence::Indicator(matched));
    Alert {
        rule: Rule::KnownIndicator,
        severity: Severity::Critical,
        created: now,
        evidence,
    }
}

/// MS-02: the history holds `connections` by `app`, or by an app not known, that a list
/// which arrived later matches, made from `first` until `last` (Unix milliseconds). As
/// Critical as a match seen live (SRS §8.3).
pub fn known_indicator_in_history(
    now: i64,
    app: Option<&str>,
    matched: IndicatorMatch,
    first: i64,
    last: i64,
    connections: u64,
) -> Alert {
    let mut alert = known_indicator(now, app, matched);
    alert.evidence.push(Evidence::PastConnections {
        first,
        last,
        connections,
    });
    alert
}

/// Whether `alert` and `other` are known-indicator alerts about the same app and the
/// same indicator, however it was seen: while one is open, the other would tell the
/// user nothing new.
pub fn same_sighting(alert: &Alert, other: &Alert) -> bool {
    alert.rule == Rule::KnownIndicator
        && other.rule == Rule::KnownIndicator
        && alert.app() == other.app()
        && indicators(alert).eq(indicators(other))
}

fn indicators(alert: &Alert) -> impl Iterator<Item = &str> {
    alert.evidence.iter().filter_map(|e| match e {
        Evidence::Indicator(matched) => Some(matched.indicator.as_str()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, evidence_from_json, evidence_to_json};

    fn matched(indicator: &str, seen: &str, sighting: Sighting) -> IndicatorMatch {
        IndicatorMatch {
            indicator: indicator.to_owned(),
            seen: seen.to_owned(),
            sighting,
            family: "Pegasus".to_owned(),
            threat: Threat::Spyware,
            source: "Amnesty International Security Lab".to_owned(),
            date: "2021-07-18".to_owned(),
            report: "https://example.org/report".to_owned(),
        }
    }

    #[test]
    fn a_match_is_critical_names_the_app_and_offers_to_block_it() {
        let alert = known_indicator(
            5_000,
            Some("org.example.chat"),
            matched("bad.example", "cdn.bad.example", Sighting::DnsQuery),
        );
        assert_eq!(alert.rule, Rule::KnownIndicator);
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.created, 5_000);
        assert_eq!(alert.app(), Some("org.example.chat"));
        let package = "org.example.chat".to_owned();
        assert_eq!(
            alert.actions(),
            [
                Action::BlockApp {
                    package: package.clone()
                },
                Action::OpenApp { package }
            ]
        );
    }

    #[test]
    fn a_match_without_an_app_is_still_raised() {
        let alert = known_indicator(
            5_000,
            None,
            matched("198.51.100.7", "198.51.100.7", Sighting::Address),
        );
        assert_eq!(alert.app(), None);
        assert_eq!(alert.actions(), []);
        assert_eq!(alert.evidence.len(), 1);
    }

    /// The stored form is part of the history's format: it must not change by accident.
    #[test]
    fn a_match_is_stored_with_its_provenance() {
        let alert = known_indicator(
            5_000,
            Some("org.example.chat"),
            matched("bad.example", "cdn.bad.example", Sighting::ServerName),
        );
        let json = evidence_to_json(&alert.evidence);
        assert_eq!(
            json,
            r#"[{"type":"app","package":"org.example.chat"},{"type":"indicator","indicator":"bad.example","seen":"cdn.bad.example","sighting":"server_name","family":"Pegasus","threat":"spyware","source":"Amnesty International Security Lab","date":"2021-07-18","report":"https://example.org/report"}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), alert.evidence);
    }

    /// MS-02: a match found in the history says when and how often; it is the same
    /// sighting as a live one about the same app and indicator.
    #[test]
    fn a_match_in_the_history_says_when_and_how_often() {
        let alert = known_indicator_in_history(
            9_000,
            Some("org.example.chat"),
            matched("bad.example", "cdn.bad.example", Sighting::ConnectionName),
            1_000,
            2_000,
            3,
        );
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.created, 9_000);
        let json = evidence_to_json(&alert.evidence[1..]);
        assert_eq!(
            json,
            r#"[{"type":"indicator","indicator":"bad.example","seen":"cdn.bad.example","sighting":"connection_name","family":"Pegasus","threat":"spyware","source":"Amnesty International Security Lab","date":"2021-07-18","report":"https://example.org/report"},{"type":"past_connections","first":1000,"last":2000,"connections":3}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), alert.evidence[1..]);
        let live = known_indicator(
            1,
            Some("org.example.chat"),
            matched("bad.example", "bad.example", Sighting::DnsQuery),
        );
        assert!(same_sighting(&alert, &live));
        assert_eq!(alert.actions(), live.actions());
    }

    #[test]
    fn the_same_indicator_seen_again_by_the_same_app_is_the_same_sighting() {
        let app = Some("org.example.chat");
        let first = known_indicator(
            1,
            app,
            matched("bad.example", "bad.example", Sighting::DnsQuery),
        );
        let again = known_indicator(
            2,
            app,
            matched("bad.example", "x.bad.example", Sighting::ServerName),
        );
        assert!(same_sighting(&first, &again));
        let other_app = known_indicator(
            2,
            Some("org.example.other"),
            matched("bad.example", "bad.example", Sighting::DnsQuery),
        );
        assert!(!same_sighting(&first, &other_app));
        let no_app = known_indicator(
            2,
            None,
            matched("bad.example", "bad.example", Sighting::DnsQuery),
        );
        assert!(!same_sighting(&first, &no_app));
        let other_indicator = known_indicator(
            2,
            app,
            matched("worse.example", "worse.example", Sighting::DnsQuery),
        );
        assert!(!same_sighting(&first, &other_indicator));
        let other_rule = Alert {
            rule: Rule::NewDestination,
            ..first.clone()
        };
        assert!(!same_sighting(&first, &other_rule));
    }
}

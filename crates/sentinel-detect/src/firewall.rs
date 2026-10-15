// SPDX-License-Identifier: GPL-3.0-or-later
//! Firewall rules by app, domain and address (SRS CM-10, the Phase A subset; ADR-0015).
//!
//! A rule names an app, a destination, or both, and allows or blocks what matches. The
//! engine asks [`RuleSet::decide`] at three moments, with what it knows then:
//! - a new connection: its app and address;
//! - the TLS server name of a connection: its app, address and that name;
//! - a DNS lookup through the tunnel: its app and the name looked up.
//!
//! A name learned only from an earlier DNS answer is not matched: several names often
//! share one address, so it may be another site's name.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// What a rule does with what it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Destination {
    /// A domain and every name below it: `example.com` covers `www.example.com` but not
    /// `notexample.com`. Lower case, without a trailing dot.
    Domain { name: String },
    /// One address, or a range of them.
    Network { network: Network },
}

/// An address range: an address and how many of its leading bits must match. A single
/// address has all its bits (32 or 128).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

/// Why a rule was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    #[error("a rule needs an app, a destination, or both")]
    Empty,
    #[error("{0:?} is not an app's package name")]
    BadApp(String),
    #[error("{0:?} is not a domain name")]
    BadDomain(String),
    #[error("{0:?} is not an address or an address range")]
    BadNetwork(String),
}

/// One firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FirewallRule {
    /// The app, by package name; `None` for every app.
    pub app: Option<String>,
    /// Where; `None` for everywhere.
    pub destination: Option<Destination>,
    pub action: RuleAction,
}

/// The rules in force, and how they decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<FirewallRule>,
}

impl Network {
    /// Parse `192.0.2.1`, `192.0.2.0/24`, `2001:db8::1` or `2001:db8::/32`. Bits beyond
    /// the prefix must be zero, so a range is written one way only.
    pub fn parse(text: &str) -> Result<Network, RuleError> {
        let bad = || RuleError::BadNetwork(text.to_owned());
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => {
                let prefix: u8 = prefix.parse().map_err(|_| bad())?;
                (address, Some(prefix))
            }
            None => (text, None),
        };
        let address = normalize(address.parse::<IpAddr>().map_err(|_| bad())?);
        let bits = bits_of(address);
        let prefix = prefix.unwrap_or(bits);
        if prefix > bits || masked(address, prefix) != address {
            return Err(bad());
        }
        Ok(Network { address, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        let address = normalize(address);
        address.is_ipv4() == self.address.is_ipv4() && masked(address, self.prefix) == self.address
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix == bits_of(self.address) {
            write!(f, "{}", self.address)
        } else {
            write!(f, "{}/{}", self.address, self.prefix)
        }
    }
}

impl TryFrom<String> for Network {
    type Error = RuleError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Network::parse(&text)
    }
}

impl From<Network> for String {
    fn from(network: Network) -> String {
        network.to_string()
    }
}

impl Destination {
    /// A domain rule's destination, checked and normalized: lower case, no trailing dot.
    pub fn domain(name: &str) -> Result<Destination, RuleError> {
        let normalized = name.trim_end_matches('.').to_ascii_lowercase();
        if !is_domain(&normalized) {
            return Err(RuleError::BadDomain(name.to_owned()));
        }
        Ok(Destination::Domain { name: normalized })
    }

    pub fn network(text: &str) -> Result<Destination, RuleError> {
        Ok(Destination::Network {
            network: Network::parse(text)?,
        })
    }

    fn matches(&self, address: Option<IpAddr>, name: Option<&str>) -> bool {
        match self {
            Destination::Domain { name: domain } => name.is_some_and(|name| {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                name == *domain || name.ends_with(&format!(".{domain}"))
            }),
            Destination::Network { network } => address.is_some_and(|a| network.contains(a)),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Domain { name } => write!(f, "domain:{name}"),
            Destination::Network { network } => write!(f, "network:{network}"),
        }
    }
}

impl FirewallRule {
    /// A rule, checked: it names an app, a destination or both, and the app is a package
    /// name.
    pub fn new(
        app: Option<&str>,
        destination: Option<Destination>,
        action: RuleAction,
    ) -> Result<FirewallRule, RuleError> {
        if app.is_none() && destination.is_none() {
            return Err(RuleError::Empty);
        }
        if let Some(app) = app
            && (app.is_empty()
                || app.len() > 255
                || app.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(RuleError::BadApp(app.to_owned()));
        }
        Ok(FirewallRule {
            app: app.map(str::to_owned),
            destination,
            action,
        })
    }

    /// What the rule is about, without its action: two rules with the same key replace
    /// each other.
    pub fn key(&self) -> String {
        let app = self.app.as_deref().unwrap_or("*");
        match &self.destination {
            Some(destination) => format!("{app} {destination}"),
            None => format!("{app} *"),
        }
    }

    /// How specific the rule is: an app and a destination, then a destination, then an
    /// app.
    fn specificity(&self) -> u8 {
        match (&self.app, &self.destination) {
            (Some(_), Some(_)) => 3,
            (None, Some(_)) => 2,
            (Some(_), None) => 1,
            (None, None) => 0,
        }
    }

    fn matches(&self, app: Option<&str>, address: Option<IpAddr>, name: Option<&str>) -> bool {
        let app_matches = match &self.app {
            Some(rule_app) => app == Some(rule_app.as_str()),
            None => true,
        };
        let destination_matches = match &self.destination {
            Some(destination) => destination.matches(address, name),
            None => true,
        };
        app_matches && destination_matches
    }

    pub fn to_json(&self) -> String {
        // Serializing this type cannot fail: strings and enums only.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// A stored rule, checked again as [`FirewallRule::new`] would.
    pub fn from_json(json: &str) -> Option<FirewallRule> {
        let rule: FirewallRule = serde_json::from_str(json).ok()?;
        let destination = match rule.destination {
            Some(Destination::Domain { name }) => Some(Destination::domain(&name).ok()?),
            other => other,
        };
        FirewallRule::new(rule.app.as_deref(), destination, rule.action).ok()
    }
}

impl RuleSet {
    pub fn new(rules: Vec<FirewallRule>) -> RuleSet {
        RuleSet { rules }
    }

    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    /// What the rules say about a connection or lookup by `app` to `address` under
    /// `name`, each `None` when not known. The most specific matching rule decides; among
    /// rules equally specific, blocking wins. `None` when no rule matches.
    pub fn decide(
        &self,
        app: Option<&str>,
        address: Option<IpAddr>,
        name: Option<&str>,
    ) -> Option<RuleAction> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(app, address, name))
            .max_by_key(|rule| (rule.specificity(), rule.action == RuleAction::Block))
            .map(|rule| rule.action)
    }
}

fn bits_of(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

/// An IPv4 address written as IPv6 (`::ffff:192.0.2.1`) is the IPv4 address.
fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 => v4,
    }
}

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// A plain domain name: dot-separated labels of letters, digits, `-` and `_`, not
/// starting or ending with `-`, and not an address.
fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: &str = "org.example.chat";
    const MAPS: &str = "org.example.maps";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn rule(
        app: Option<&str>,
        destination: Option<Destination>,
        action: RuleAction,
    ) -> FirewallRule {
        FirewallRule::new(app, destination, action).unwrap()
    }

    fn domain(name: &str) -> Option<Destination> {
        Some(Destination::domain(name).unwrap())
    }

    fn network(text: &str) -> Option<Destination> {
        Some(Destination::network(text).unwrap())
    }

    #[test]
    fn an_app_rule_covers_all_of_that_apps_traffic_only() {
        let rules = RuleSet::new(vec![rule(Some(CHAT), None, RuleAction::Block)]);
        assert_eq!(
            rules.decide(Some(CHAT), Some(ip("192.0.2.1")), None),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(Some(CHAT), None, Some("anything.example")),
            Some(RuleAction::Block)
        );
        assert_eq!(rules.decide(Some(MAPS), Some(ip("192.0.2.1")), None), None);
        assert_eq!(
            rules.decide(None, Some(ip("192.0.2.1")), None),
            None,
            "owner unknown"
        );
    }

    #[test]
    fn a_domain_rule_covers_the_names_below_it_and_no_look_alikes() {
        let rules = RuleSet::new(vec![rule(None, domain("Ads.Example."), RuleAction::Block)]);
        for name in [
            "ads.example",
            "x.ads.example",
            "a.b.ads.example",
            "ADS.EXAMPLE.",
        ] {
            assert_eq!(
                rules.decide(Some(CHAT), None, Some(name)),
                Some(RuleAction::Block),
                "{name}"
            );
        }
        for name in ["notads.example", "ads.example.org", "example"] {
            assert_eq!(rules.decide(Some(CHAT), None, Some(name)), None, "{name}");
        }
        assert_eq!(
            rules.decide(Some(CHAT), Some(ip("192.0.2.1")), None),
            None,
            "no name, no domain match"
        );
    }

    #[test]
    fn an_address_rule_covers_that_address_only() {
        let rules = RuleSet::new(vec![
            rule(None, network("192.0.2.7"), RuleAction::Block),
            rule(None, network("2001:db8::7"), RuleAction::Block),
        ]);
        assert_eq!(
            rules.decide(None, Some(ip("192.0.2.7")), None),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(None, Some(ip("::ffff:192.0.2.7")), None),
            Some(RuleAction::Block),
            "an IPv4 address written as IPv6"
        );
        assert_eq!(
            rules.decide(None, Some(ip("2001:db8::7")), None),
            Some(RuleAction::Block)
        );
        assert_eq!(rules.decide(None, Some(ip("192.0.2.8")), None), None);
        assert_eq!(rules.decide(None, Some(ip("2001:db8::8")), None), None);
        assert_eq!(rules.decide(None, None, Some("192.0.2.7")), None);
    }

    #[test]
    fn a_range_rule_covers_its_range() {
        let rules = RuleSet::new(vec![
            rule(None, network("198.51.100.0/24"), RuleAction::Block),
            rule(None, network("2001:db8:1::/48"), RuleAction::Block),
        ]);
        for inside in ["198.51.100.0", "198.51.100.255", "2001:db8:1:ffff::1"] {
            assert_eq!(
                rules.decide(None, Some(ip(inside)), None),
                Some(RuleAction::Block),
                "{inside}"
            );
        }
        for outside in ["198.51.101.0", "198.51.99.255", "2001:db8:2::1", "::"] {
            assert_eq!(
                rules.decide(None, Some(ip(outside)), None),
                None,
                "{outside}"
            );
        }
        let everything = RuleSet::new(vec![rule(None, network("0.0.0.0/0"), RuleAction::Block)]);
        assert_eq!(
            everything.decide(None, Some(ip("203.0.113.1")), None),
            Some(RuleAction::Block)
        );
        assert_eq!(everything.decide(None, Some(ip("2001:db8::1")), None), None);
    }

    #[test]
    fn an_app_and_destination_rule_needs_both() {
        let rules = RuleSet::new(vec![rule(
            Some(CHAT),
            domain("ads.example"),
            RuleAction::Block,
        )]);
        assert_eq!(
            rules.decide(Some(CHAT), None, Some("x.ads.example")),
            Some(RuleAction::Block)
        );
        assert_eq!(rules.decide(Some(MAPS), None, Some("x.ads.example")), None);
        assert_eq!(rules.decide(Some(CHAT), None, Some("chat.example")), None);
    }

    #[test]
    fn the_most_specific_rule_decides_and_block_wins_a_tie() {
        let rules = RuleSet::new(vec![
            rule(Some(CHAT), None, RuleAction::Block),
            rule(None, domain("chat.example"), RuleAction::Allow),
            rule(Some(CHAT), domain("push.chat.example"), RuleAction::Allow),
            rule(None, domain("ads.example"), RuleAction::Block),
            rule(None, network("192.0.2.0/24"), RuleAction::Allow),
        ]);
        // App and destination beats destination beats app.
        assert_eq!(
            rules.decide(Some(CHAT), None, Some("push.chat.example")),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            rules.decide(Some(CHAT), None, Some("www.chat.example")),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            rules.decide(Some(CHAT), None, Some("other.example")),
            Some(RuleAction::Block)
        );
        // Two destination rules match: blocking wins.
        assert_eq!(
            rules.decide(Some(MAPS), Some(ip("192.0.2.1")), Some("ads.example")),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(Some(MAPS), Some(ip("192.0.2.1")), Some("maps.example")),
            Some(RuleAction::Allow)
        );
        assert_eq!(RuleSet::default().decide(Some(CHAT), None, None), None);
    }

    #[test]
    fn rules_are_checked_when_made() {
        assert_eq!(
            FirewallRule::new(None, None, RuleAction::Block),
            Err(RuleError::Empty)
        );
        for app in ["", "has space", "tab\there"] {
            assert!(matches!(
                FirewallRule::new(Some(app), None, RuleAction::Block),
                Err(RuleError::BadApp(_))
            ));
        }
        for name in [
            "",
            ".",
            "a..b",
            "-a.example",
            "a-.example",
            "a b.example",
            "*.example",
            "192.0.2.1",
            "ü.example",
        ] {
            assert!(
                matches!(Destination::domain(name), Err(RuleError::BadDomain(_))),
                "{name:?}"
            );
        }
        for text in [
            "",
            "192.0.2",
            "192.0.2.1/33",
            "192.0.2.1/24",
            "2001:db8::1/129",
            "10.0.0.0/x",
            "example.com",
        ] {
            assert!(
                matches!(Destination::network(text), Err(RuleError::BadNetwork(_))),
                "{text:?}"
            );
        }
        assert_eq!(
            Destination::network("::ffff:192.0.2.0/120").map(|d| d.to_string()),
            Err(RuleError::BadNetwork("::ffff:192.0.2.0/120".to_owned())),
            "a mapped range is written as IPv4"
        );
        assert_eq!(
            Destination::domain("_dmarc.Example.COM").unwrap(),
            Destination::Domain {
                name: "_dmarc.example.com".to_owned()
            }
        );
    }

    #[test]
    fn keys_name_what_a_rule_is_about() {
        let block = rule(Some(CHAT), domain("ads.example"), RuleAction::Block);
        let allow = rule(Some(CHAT), domain("ads.example"), RuleAction::Allow);
        assert_eq!(block.key(), "org.example.chat domain:ads.example");
        assert_eq!(block.key(), allow.key(), "the action is not part of it");
        assert_eq!(
            rule(None, network("192.0.2.0/24"), RuleAction::Block).key(),
            "* network:192.0.2.0/24"
        );
        assert_eq!(
            rule(Some(CHAT), None, RuleAction::Block).key(),
            "org.example.chat *"
        );
        assert_eq!(
            rule(None, network("2001:db8::1"), RuleAction::Block).key(),
            "* network:2001:db8::1"
        );
    }

    /// The stored form is part of the history's format.
    #[test]
    fn rules_are_stored_as_json() {
        let stored = rule(Some(CHAT), network("192.0.2.0/24"), RuleAction::Block);
        let json = stored.to_json();
        assert_eq!(
            json,
            r#"{"app":"org.example.chat","destination":{"type":"network","network":"192.0.2.0/24"},"action":"block"}"#
        );
        assert_eq!(FirewallRule::from_json(&json), Some(stored));
        let by_name = rule(None, domain("ads.example"), RuleAction::Allow);
        assert_eq!(
            by_name.to_json(),
            r#"{"app":null,"destination":{"type":"domain","name":"ads.example"},"action":"allow"}"#
        );
        assert_eq!(FirewallRule::from_json(&by_name.to_json()), Some(by_name));
        for bad in [
            r#"{"app":null,"destination":null,"action":"block"}"#,
            r#"{"app":null,"destination":{"type":"domain","name":"a b"},"action":"block"}"#,
            r#"{"app":null,"destination":{"type":"network","network":"192.0.2.1/24"},"action":"block"}"#,
            r#"{"app":"x","destination":null,"action":"maybe"}"#,
            "not json",
        ] {
            assert_eq!(FirewallRule::from_json(bad), None, "{bad}");
        }
    }
}

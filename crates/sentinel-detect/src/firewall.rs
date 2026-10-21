// SPDX-License-Identifier: GPL-3.0-or-later
//! Firewall rules by app, domain and address (SRS CM-10, the Phase A subset; ADR-0015).
//!
//! A rule names an app, a destination, or both, and allows or blocks what matches. The
//! engine asks [`RuleSet::verdict`] at three moments, with what it knows then, and asks
//! again about every open connection when the rules or the mode change:
//! - a new connection: its app and address;
//! - the TLS server name of a connection: its app, address and that name;
//! - a DNS lookup through the tunnel: its app and the name looked up.
//!
//! A name learned only from an earlier DNS answer is not matched: several names often
//! share one address, so it may be another site's name.
//!
//! Where no rule matches, the [`FirewallMode`] decides (CM-08, ADR-0016).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
    /// Every name the tracker lists give to this company (DT-06), as they spell it.
    Company { company: String },
}

/// Network isolation (RA-03, ADR-0017): while on, only DNS through the tunnel's own
/// resolver, Sentinel itself and the apps a rule allows as a whole may use the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Isolation {
    /// When it was turned on, Unix milliseconds.
    pub since: i64,
    /// Sentinel's own app, which keeps the network for its updates.
    pub own_app: String,
}

/// What is known for sure about where a connection or lookup goes when the firewall is
/// asked (ADR-0015).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Place<'a> {
    pub address: Option<IpAddr>,
    /// A name the app asked for: a TLS server name or a DNS lookup's.
    pub name: Option<&'a str>,
    /// The company the tracker lists give for `name`.
    pub company: Option<&'a str>,
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
    #[error("{0:?} is not a company's name")]
    BadCompany(String),
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

/// What the firewall does with what no rule matches (CM-08, ADR-0016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallMode {
    /// Only the rules block; everything else is let through and recorded.
    Monitor,
    /// Apps installed at or after `since` (Unix milliseconds), when this mode was turned
    /// on, are blocked until a rule allows them. Apps installed before, and connections
    /// whose app or install time is not known, are let through.
    BlockUnknown { since: i64 },
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

    /// A company, by the name the tracker lists give it: one line of text, without
    /// space around it.
    pub fn company(name: &str) -> Result<Destination, RuleError> {
        let bad = || RuleError::BadCompany(name.to_owned());
        if name.is_empty()
            || name.len() > 200
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(bad());
        }
        Ok(Destination::Company {
            company: name.to_owned(),
        })
    }

    fn matches(&self, place: Place<'_>) -> bool {
        match self {
            Destination::Domain { name: domain } => place.name.is_some_and(|name| {
                let name = name.trim_end_matches('.').to_ascii_lowercase();
                name == *domain || name.ends_with(&format!(".{domain}"))
            }),
            Destination::Network { network } => place.address.is_some_and(|a| network.contains(a)),
            Destination::Company { company } => place.company == Some(company.as_str()),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Domain { name } => write!(f, "domain:{name}"),
            Destination::Network { network } => write!(f, "network:{network}"),
            Destination::Company { company } => write!(f, "company:{company}"),
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

    fn matches(&self, app: Option<&str>, place: Place<'_>) -> bool {
        let app_matches = match &self.app {
            Some(rule_app) => app == Some(rule_app.as_str()),
            None => true,
        };
        let destination_matches = match &self.destination {
            Some(destination) => destination.matches(place),
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
            Some(Destination::Company { company }) => Some(Destination::company(&company).ok()?),
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

    /// What the rules say about a connection or lookup by `app` (`None` when not known)
    /// to `place`. The most specific matching rule decides; among rules equally specific,
    /// blocking wins. `None` when no rule matches.
    pub fn decide(&self, app: Option<&str>, place: Place<'_>) -> Option<RuleAction> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(app, place))
            .max_by_key(|rule| (rule.specificity(), rule.action == RuleAction::Block))
            .map(|rule| rule.action)
    }

    /// Whether to let a connection or lookup through: the rules decide, and where none
    /// matches, `mode` does. `installed` is when `app` was installed, if known.
    pub fn verdict(
        &self,
        mode: FirewallMode,
        app: Option<&str>,
        installed: Option<i64>,
        place: Place<'_>,
    ) -> RuleAction {
        self.decide(app, place)
            .unwrap_or_else(|| mode.decide(installed))
    }
}

impl RuleSet {
    /// Whether a rule that blocks by name, a domain or a company, applies to `app`'s
    /// connections (`None` when the app is not known). A connection whose TLS server name
    /// cannot be read may be going to such a name, and is then blocked rather than let
    /// past the rule unread (audit finding A-03, ADR-0015). Allow rules for some names
    /// are not weighed: without the name, none can be shown to apply.
    pub fn blocks_by_name(&self, app: Option<&str>) -> bool {
        self.rules.iter().any(|rule| {
            rule.action == RuleAction::Block
                && matches!(
                    rule.destination,
                    Some(Destination::Domain { .. } | Destination::Company { .. })
                )
                && rule
                    .app
                    .as_deref()
                    .is_none_or(|rule_app| app == Some(rule_app))
        })
    }

    /// Whether `mode` keeps `app`, installed at `installed`, off the network as a new
    /// app: Block-unknown blocks it and no rule is about the app as a whole. Rules about
    /// some of its destinations may still let it reach those.
    pub fn blocks_new_app(&self, mode: FirewallMode, app: &str, installed: Option<i64>) -> bool {
        mode.decide(installed) == RuleAction::Block
            && self.decide(Some(app), Place::default()).is_none()
    }

    /// Whether `isolation` lets `app`'s connection or lookup sent to `to` through: DNS
    /// to one of the tunnel's own `resolvers` (port 53), Sentinel itself, and apps a rule
    /// allows as a whole. The rules still apply to what it lets through.
    ///
    /// Port 53 elsewhere is not let through: an app may send anything to its own server
    /// there (audit finding A-01). The tunnel's resolver passes only lookups on to the
    /// network's.
    pub fn isolation_lets_through(
        &self,
        isolation: &Isolation,
        app: Option<&str>,
        to: SocketAddr,
        resolvers: &[IpAddr],
    ) -> bool {
        const DNS: u16 = 53;
        let to_resolver = to.port() == DNS
            && resolvers
                .iter()
                .any(|resolver| normalize(*resolver) == normalize(to.ip()));
        to_resolver
            || app == Some(isolation.own_app.as_str())
            || app.is_some_and(|app| {
                self.decide(Some(app), Place::default()) == Some(RuleAction::Allow)
            })
    }
}

impl<'a> Place<'a> {
    /// An address and a name, either unknown; no company.
    pub fn new(address: Option<IpAddr>, name: Option<&'a str>) -> Place<'a> {
        Place {
            address,
            name,
            company: None,
        }
    }
}

impl FirewallMode {
    /// The name stored in the history.
    pub fn id(self) -> &'static str {
        match self {
            FirewallMode::Monitor => "monitor",
            FirewallMode::BlockUnknown { .. } => "block-unknown",
        }
    }

    /// The mode stored as `id`; Block-unknown needs the time it was turned on.
    pub fn from_id(id: &str, since: Option<i64>) -> Option<FirewallMode> {
        match id {
            "monitor" => Some(FirewallMode::Monitor),
            "block-unknown" => Some(FirewallMode::BlockUnknown { since: since? }),
            _ => None,
        }
    }

    /// What the mode does with a connection or lookup that no rule matches, by an app
    /// installed at `installed`.
    pub fn decide(self, installed: Option<i64>) -> RuleAction {
        match (self, installed) {
            (FirewallMode::BlockUnknown { since }, Some(installed)) if installed >= since => {
                RuleAction::Block
            }
            _ => RuleAction::Allow,
        }
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
            rules.decide(Some(CHAT), Place::new(Some(ip("192.0.2.1")), None)),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(None, Some("anything.example"))),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(Some(MAPS), Place::new(Some(ip("192.0.2.1")), None)),
            None
        );
        assert_eq!(
            rules.decide(None, Place::new(Some(ip("192.0.2.1")), None)),
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
                rules.decide(Some(CHAT), Place::new(None, Some(name))),
                Some(RuleAction::Block),
                "{name}"
            );
        }
        for name in ["notads.example", "ads.example.org", "example"] {
            assert_eq!(
                rules.decide(Some(CHAT), Place::new(None, Some(name))),
                None,
                "{name}"
            );
        }
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(Some(ip("192.0.2.1")), None)),
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
            rules.decide(None, Place::new(Some(ip("192.0.2.7")), None)),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(None, Place::new(Some(ip("::ffff:192.0.2.7")), None)),
            Some(RuleAction::Block),
            "an IPv4 address written as IPv6"
        );
        assert_eq!(
            rules.decide(None, Place::new(Some(ip("2001:db8::7")), None)),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(None, Place::new(Some(ip("192.0.2.8")), None)),
            None
        );
        assert_eq!(
            rules.decide(None, Place::new(Some(ip("2001:db8::8")), None)),
            None
        );
        assert_eq!(
            rules.decide(None, Place::new(None, Some("192.0.2.7"))),
            None
        );
    }

    #[test]
    fn a_range_rule_covers_its_range() {
        let rules = RuleSet::new(vec![
            rule(None, network("198.51.100.0/24"), RuleAction::Block),
            rule(None, network("2001:db8:1::/48"), RuleAction::Block),
        ]);
        for inside in ["198.51.100.0", "198.51.100.255", "2001:db8:1:ffff::1"] {
            assert_eq!(
                rules.decide(None, Place::new(Some(ip(inside)), None)),
                Some(RuleAction::Block),
                "{inside}"
            );
        }
        for outside in ["198.51.101.0", "198.51.99.255", "2001:db8:2::1", "::"] {
            assert_eq!(
                rules.decide(None, Place::new(Some(ip(outside)), None)),
                None,
                "{outside}"
            );
        }
        let everything = RuleSet::new(vec![rule(None, network("0.0.0.0/0"), RuleAction::Block)]);
        assert_eq!(
            everything.decide(None, Place::new(Some(ip("203.0.113.1")), None)),
            Some(RuleAction::Block)
        );
        assert_eq!(
            everything.decide(None, Place::new(Some(ip("2001:db8::1")), None)),
            None
        );
    }

    #[test]
    fn an_app_and_destination_rule_needs_both() {
        let rules = RuleSet::new(vec![rule(
            Some(CHAT),
            domain("ads.example"),
            RuleAction::Block,
        )]);
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(None, Some("x.ads.example"))),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(Some(MAPS), Place::new(None, Some("x.ads.example"))),
            None
        );
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(None, Some("chat.example"))),
            None
        );
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
            rules.decide(Some(CHAT), Place::new(None, Some("push.chat.example"))),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(None, Some("www.chat.example"))),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            rules.decide(Some(CHAT), Place::new(None, Some("other.example"))),
            Some(RuleAction::Block)
        );
        // Two destination rules match: blocking wins.
        assert_eq!(
            rules.decide(
                Some(MAPS),
                Place::new(Some(ip("192.0.2.1")), Some("ads.example"))
            ),
            Some(RuleAction::Block)
        );
        assert_eq!(
            rules.decide(
                Some(MAPS),
                Place::new(Some(ip("192.0.2.1")), Some("maps.example"))
            ),
            Some(RuleAction::Allow)
        );
        assert_eq!(
            RuleSet::default().decide(Some(CHAT), Place::default()),
            None
        );
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

    /// RA-01: a company rule covers the names the tracker lists give that company, and
    /// is matched only once a name, and so its company, is known.
    #[test]
    fn a_company_rule_covers_its_names_once_known() {
        let ads = Destination::company("Example Ads Inc").unwrap();
        let rules = RuleSet::new(vec![rule(None, Some(ads.clone()), RuleAction::Block)]);
        let at = |company| Place {
            address: Some(ip("192.0.2.1")),
            name: Some("pixel.example"),
            company,
        };
        assert_eq!(
            rules.decide(Some(CHAT), at(Some("Example Ads Inc"))),
            Some(RuleAction::Block)
        );
        for other in [None, Some("Example Ads"), Some("example ads inc")] {
            assert_eq!(rules.decide(Some(CHAT), at(other)), None, "{other:?}");
        }
        // An app's exception to a company rule needs that app.
        let rules = RuleSet::new(vec![
            rule(None, Some(ads.clone()), RuleAction::Block),
            rule(Some(MAPS), Some(ads), RuleAction::Allow),
        ]);
        let listed = at(Some("Example Ads Inc"));
        assert_eq!(rules.decide(Some(MAPS), listed), Some(RuleAction::Allow));
        assert_eq!(rules.decide(Some(CHAT), listed), Some(RuleAction::Block));
        // Names are checked: one line, without space around it.
        for bad in ["", " Example", "Example ", "Two\nlines", &"x".repeat(201)] {
            assert_eq!(
                Destination::company(bad),
                Err(RuleError::BadCompany(bad.to_owned())),
                "{bad:?}"
            );
        }
        let keyed = rule(
            None,
            Some(Destination::company("Example Ads Inc").unwrap()),
            RuleAction::Block,
        );
        assert_eq!(keyed.key(), "* company:Example Ads Inc");
        assert_eq!(
            keyed.to_json(),
            r#"{"app":null,"destination":{"type":"company","company":"Example Ads Inc"},"action":"block"}"#
        );
        assert_eq!(FirewallRule::from_json(&keyed.to_json()), Some(keyed));
        assert_eq!(
            FirewallRule::from_json(
                r#"{"app":null,"destination":{"type":"company","company":" padded"},"action":"block"}"#
            ),
            None
        );
    }

    #[test]
    fn monitor_mode_lets_through_what_no_rule_blocks() {
        let rules = RuleSet::new(vec![rule(Some(CHAT), None, RuleAction::Block)]);
        let mode = FirewallMode::Monitor;
        assert_eq!(
            rules.verdict(mode, Some(CHAT), Some(5), Place::default()),
            RuleAction::Block
        );
        for installed in [None, Some(0), Some(i64::MAX)] {
            assert_eq!(
                rules.verdict(
                    mode,
                    Some(MAPS),
                    installed,
                    Place::new(Some(ip("192.0.2.1")), None)
                ),
                RuleAction::Allow
            );
        }
        assert_eq!(
            rules.verdict(mode, None, None, Place::default()),
            RuleAction::Allow
        );
    }

    #[test]
    fn block_unknown_blocks_apps_installed_since_it_was_turned_on() {
        let since = 1_000;
        let mode = FirewallMode::BlockUnknown { since };
        let none = RuleSet::default();
        let address = Some(ip("192.0.2.1"));
        // Installed before: let through. At or after: blocked, at every moment it asks.
        assert_eq!(
            none.verdict(mode, Some(MAPS), Some(since - 1), Place::new(address, None)),
            RuleAction::Allow
        );
        for installed in [since, since + 1] {
            assert_eq!(
                none.verdict(mode, Some(MAPS), Some(installed), Place::new(address, None)),
                RuleAction::Block
            );
            assert_eq!(
                none.verdict(
                    mode,
                    Some(MAPS),
                    Some(installed),
                    Place::new(address, Some("maps.example"))
                ),
                RuleAction::Block
            );
            assert_eq!(
                none.verdict(
                    mode,
                    Some(MAPS),
                    Some(installed),
                    Place::new(None, Some("maps.example"))
                ),
                RuleAction::Block
            );
        }
        // Without an app or its install time (Android's shared system identities), the
        // mode cannot tell, so it does not block.
        assert_eq!(
            none.verdict(mode, None, None, Place::new(address, None)),
            RuleAction::Allow
        );
        assert_eq!(
            none.verdict(
                mode,
                Some("android.uid.system:1000"),
                None,
                Place::new(address, None)
            ),
            RuleAction::Allow
        );
    }

    #[test]
    fn rules_come_before_the_mode() {
        let mode = FirewallMode::BlockUnknown { since: 1_000 };
        let new = Some(2_000);
        let old = Some(500);
        let rules = RuleSet::new(vec![
            rule(Some(CHAT), None, RuleAction::Allow),
            rule(Some(MAPS), domain("tiles.example"), RuleAction::Allow),
            rule(None, domain("ads.example"), RuleAction::Block),
        ]);
        let address = Some(ip("192.0.2.1"));
        // Allowing a new app lets it through, except where a rule blocks.
        assert_eq!(
            rules.verdict(mode, Some(CHAT), new, Place::new(address, None)),
            RuleAction::Allow
        );
        assert_eq!(
            rules.verdict(
                mode,
                Some(CHAT),
                new,
                Place::new(address, Some("x.ads.example"))
            ),
            RuleAction::Block
        );
        // A rule for one domain lets a new app reach that domain once its name is known,
        // but its connections are refused when they start, before the name is known.
        assert_eq!(
            rules.verdict(
                mode,
                Some(MAPS),
                new,
                Place::new(None, Some("tiles.example"))
            ),
            RuleAction::Allow
        );
        assert_eq!(
            rules.verdict(mode, Some(MAPS), new, Place::new(address, None)),
            RuleAction::Block
        );
        // Block rules apply to apps the mode lets through.
        assert_eq!(
            rules.verdict(
                mode,
                Some(MAPS),
                old,
                Place::new(address, Some("ads.example"))
            ),
            RuleAction::Block
        );
    }

    #[test]
    fn a_new_app_is_kept_off_only_by_block_unknown_without_a_rule_about_it() {
        let on = FirewallMode::BlockUnknown { since: 1_000 };
        let none = RuleSet::default();
        assert!(none.blocks_new_app(on, CHAT, Some(1_000)));
        assert!(!none.blocks_new_app(on, CHAT, Some(999)));
        assert!(!none.blocks_new_app(on, CHAT, None));
        assert!(!none.blocks_new_app(FirewallMode::Monitor, CHAT, Some(1_000)));
        for action in [RuleAction::Allow, RuleAction::Block] {
            let about_the_app = RuleSet::new(vec![rule(Some(CHAT), None, action)]);
            assert!(
                !about_the_app.blocks_new_app(on, CHAT, Some(1_000)),
                "{action:?}"
            );
        }
        let about_a_place = RuleSet::new(vec![
            rule(Some(CHAT), domain("chat.example"), RuleAction::Allow),
            rule(None, domain("ads.example"), RuleAction::Block),
        ]);
        assert!(about_a_place.blocks_new_app(on, CHAT, Some(1_000)));
    }

    /// RA-03: isolation lets through DNS to the tunnel's resolver, Sentinel itself and the
    /// apps a rule allows as a whole, and nothing else: not other apps, not unknown
    /// owners, not apps allowed only some places, and not port 53 on another server.
    #[test]
    fn isolation_lets_through_dns_sentinel_and_allowed_apps() {
        let isolation = Isolation {
            since: 1_000,
            own_app: "io.github.malekhasan.sentinel".to_owned(),
        };
        let rules = RuleSet::new(vec![
            rule(Some(CHAT), None, RuleAction::Allow),
            rule(Some(MAPS), domain("tiles.example"), RuleAction::Allow),
            rule(Some("org.example.blocked"), None, RuleAction::Block),
        ]);
        let resolvers: [IpAddr; 2] = [
            "10.215.173.53".parse().unwrap(),
            "fd00::53".parse().unwrap(),
        ];
        let through = |app, to: &str| {
            rules.isolation_lets_through(&isolation, app, to.parse().unwrap(), &resolvers)
        };
        assert!(through(Some(CHAT), "203.0.113.5:443"), "allowed as a whole");
        assert!(
            through(Some("io.github.malekhasan.sentinel"), "203.0.113.5:443"),
            "Sentinel itself"
        );
        for app in [
            Some(MAPS),
            Some("org.example.blocked"),
            Some("android.uid.system:1000"),
            None,
        ] {
            assert!(!through(app, "203.0.113.5:443"), "{app:?}");
            assert!(through(app, "10.215.173.53:53"), "DNS for {app:?}");
            assert!(through(app, "[fd00::53]:53"), "DNS over IPv6 for {app:?}");
            assert!(
                through(app, "[::ffff:10.215.173.53]:53"),
                "the resolver written as IPv6, for {app:?}"
            );
            // Audit finding A-01: port 53 on any other server could carry anything.
            assert!(
                !through(app, "203.0.113.5:53"),
                "port 53 elsewhere, {app:?}"
            );
            assert!(
                !through(app, "[2001:db8::5]:53"),
                "port 53 elsewhere, {app:?}"
            );
            // The resolver serves DNS only.
            assert!(
                !through(app, "10.215.173.53:853"),
                "the resolver's port 853, {app:?}"
            );
        }
        // Without a resolver, no DNS is let through.
        assert!(!rules.isolation_lets_through(
            &isolation,
            None,
            "10.215.173.53:53".parse().unwrap(),
            &[]
        ));
    }

    /// Audit finding A-03: a rule blocking a domain or a company, for every app or for
    /// this one, means a connection whose name cannot be read may be going there.
    #[test]
    fn rules_that_block_by_name_are_found_for_their_apps() {
        let company = || {
            Some(Destination::Company {
                company: "Example Ads".into(),
            })
        };
        let network = Some(Destination::Network {
            network: Network::parse("203.0.113.0/24").unwrap(),
        });
        let none = RuleSet::new(vec![
            rule(None, network.clone(), RuleAction::Block),
            rule(Some(CHAT), None, RuleAction::Block),
            rule(None, domain("allowed.example"), RuleAction::Allow),
        ]);
        for app in [Some(CHAT), Some(MAPS), None] {
            assert!(!none.blocks_by_name(app), "no rule blocks a name, {app:?}");
        }

        let everyone = RuleSet::new(vec![rule(None, domain("ads.example"), RuleAction::Block)]);
        for app in [Some(CHAT), Some(MAPS), None] {
            assert!(everyone.blocks_by_name(app), "{app:?}");
        }

        let chat_only = RuleSet::new(vec![rule(Some(CHAT), company(), RuleAction::Block)]);
        assert!(chat_only.blocks_by_name(Some(CHAT)));
        assert!(!chat_only.blocks_by_name(Some(MAPS)));
        assert!(
            !chat_only.blocks_by_name(None),
            "an unknown app is not this one"
        );
    }

    /// The stored names are part of the history's format.
    #[test]
    fn modes_are_stored_by_name() {
        for mode in [
            FirewallMode::Monitor,
            FirewallMode::BlockUnknown { since: 42 },
        ] {
            assert_eq!(FirewallMode::from_id(mode.id(), Some(42)), Some(mode));
        }
        assert_eq!(FirewallMode::Monitor.id(), "monitor");
        assert_eq!(
            FirewallMode::BlockUnknown { since: 0 }.id(),
            "block-unknown"
        );
        assert_eq!(
            FirewallMode::from_id("monitor", None),
            Some(FirewallMode::Monitor)
        );
        assert_eq!(FirewallMode::from_id("block-unknown", None), None);
        assert_eq!(FirewallMode::from_id("lockdown", Some(0)), None);
    }
}

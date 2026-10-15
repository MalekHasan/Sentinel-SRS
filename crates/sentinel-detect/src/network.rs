// SPDX-License-Identifier: GPL-3.0-or-later
//! Changes to where the phone's traffic goes (CM-07): the network's DNS servers, Private
//! DNS and proxies (ADR-0014).

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// What decides where the phone's traffic goes on the network it uses, as last seen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkState {
    /// The network in use, for as long as the phone stays on it: joining a network
    /// again, or restarting the phone, gives another value. `None` if unknown.
    pub network: Option<String>,
    /// The network's DNS servers, in its order.
    pub dns_servers: Vec<String>,
    /// The Private DNS provider the phone is set to use, if one is named.
    pub private_dns: Option<String>,
    /// The proxy set on the network itself, if any.
    pub network_proxy: Option<String>,
    /// The proxy in effect on the network: a proxy set for the whole phone, or the
    /// network's own.
    pub proxy: Option<String>,
}

impl NetworkState {
    /// The state as stored.
    pub fn to_json(&self) -> String {
        // Serializing this type cannot fail: strings and lists only.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Result<NetworkState, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// CM-07: what changed between two states of the network settings, as alerts.
///
/// - DNS servers are compared only on the same network: every network has its own, so
///   joining another one is not a change. A network that lists no servers yet is not
///   compared either.
/// - Private DNS is a setting of the phone, compared on any network.
/// - The proxy in effect is compared on the same network. Across networks it is
///   compared when neither network has its own proxy, since it is then the proxy set
///   for the whole phone.
pub fn network_changes(now: i64, before: &NetworkState, after: &NetworkState) -> Vec<Alert> {
    let same_network = before.network.is_some() && before.network == after.network;
    let mut alerts = Vec::new();
    let sorted = |servers: &[String]| {
        let mut servers = servers.to_vec();
        servers.sort();
        servers
    };
    if same_network
        && !before.dns_servers.is_empty()
        && !after.dns_servers.is_empty()
        && sorted(&before.dns_servers) != sorted(&after.dns_servers)
    {
        alerts.push(changed(
            now,
            Rule::DnsServersChanged,
            Evidence::DnsServers {
                before: before.dns_servers.clone(),
                after: after.dns_servers.clone(),
            },
        ));
    }
    if before.private_dns != after.private_dns {
        alerts.push(changed(
            now,
            Rule::PrivateDnsChanged,
            Evidence::PrivateDns {
                before: before.private_dns.clone(),
                after: after.private_dns.clone(),
            },
        ));
    }
    let whole_phone = before.network_proxy.is_none() && after.network_proxy.is_none();
    if (same_network || whole_phone) && before.proxy != after.proxy {
        alerts.push(changed(
            now,
            Rule::ProxyChanged,
            Evidence::Proxy {
                before: before.proxy.clone(),
                after: after.proxy.clone(),
            },
        ));
    }
    alerts
}

fn changed(now: i64, rule: Rule, evidence: Evidence) -> Alert {
    Alert {
        rule,
        severity: Severity::Warning,
        created: now,
        evidence: vec![evidence],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;

    fn home() -> NetworkState {
        NetworkState {
            network: Some("7:100".to_owned()),
            dns_servers: vec!["192.168.1.1".to_owned(), "fd00::1".to_owned()],
            private_dns: None,
            network_proxy: None,
            proxy: None,
        }
    }

    fn rules(alerts: &[Alert]) -> Vec<Rule> {
        alerts.iter().map(|a| a.rule).collect()
    }

    #[test]
    fn nothing_changed_raises_nothing() {
        assert!(network_changes(1, &home(), &home()).is_empty());
        let mut reordered = home();
        reordered.dns_servers.reverse();
        assert!(network_changes(1, &home(), &reordered).is_empty());
    }

    #[test]
    fn dns_servers_changed_on_the_same_network() {
        let mut after = home();
        after.dns_servers = vec!["203.0.113.53".to_owned()];
        let alerts = network_changes(5, &home(), &after);
        assert_eq!(rules(&alerts), [Rule::DnsServersChanged]);
        let alert = &alerts[0];
        assert_eq!((alert.severity, alert.created), (Severity::Warning, 5));
        assert_eq!(
            alert.evidence,
            [Evidence::DnsServers {
                before: home().dns_servers,
                after: vec!["203.0.113.53".to_owned()],
            }]
        );
        assert_eq!(alert.actions(), [Action::OpenNetworkSettings]);
        assert_eq!(alert.app(), None, "about the phone, not an app");
    }

    #[test]
    fn another_network_or_one_without_servers_yet_is_not_a_dns_change() {
        let mut other = home();
        other.network = Some("7:101".to_owned());
        other.dns_servers = vec!["10.0.0.1".to_owned()];
        assert!(network_changes(1, &home(), &other).is_empty());
        let mut unknown = home();
        unknown.network = None;
        assert!(network_changes(1, &unknown, &unknown).is_empty());
        let mut starting = home();
        starting.dns_servers.clear();
        assert!(network_changes(1, &starting, &home()).is_empty());
        assert!(network_changes(1, &home(), &starting).is_empty());
    }

    #[test]
    fn private_dns_is_compared_on_any_network() {
        let mut after = home();
        after.network = Some("8:100".to_owned());
        after.private_dns = Some("dns.example".to_owned());
        let alerts = network_changes(1, &home(), &after);
        assert_eq!(rules(&alerts), [Rule::PrivateDnsChanged]);
        assert_eq!(
            alerts[0].evidence,
            [Evidence::PrivateDns {
                before: None,
                after: Some("dns.example".to_owned())
            }]
        );
    }

    #[test]
    fn a_proxy_for_the_whole_phone_is_compared_on_any_network() {
        let mut after = home();
        after.network = Some("8:100".to_owned());
        after.proxy = Some("192.0.2.10:3128".to_owned());
        let alerts = network_changes(1, &home(), &after);
        assert_eq!(rules(&alerts), [Rule::ProxyChanged]);
        assert_eq!(
            alerts[0].evidence,
            [Evidence::Proxy {
                before: None,
                after: Some("192.0.2.10:3128".to_owned())
            }]
        );
    }

    #[test]
    fn a_networks_own_proxy_is_compared_on_that_network_only() {
        let mut office = home();
        office.network = Some("7:102".to_owned());
        office.network_proxy = Some("proxy.office.example:8080".to_owned());
        office.proxy = office.network_proxy.clone();
        assert!(
            network_changes(1, &home(), &office).is_empty(),
            "joining a network that has a proxy"
        );
        let mut edited = office.clone();
        edited.network_proxy = Some("192.0.2.66:8080".to_owned());
        edited.proxy = edited.network_proxy.clone();
        assert_eq!(
            rules(&network_changes(1, &office, &edited)),
            [Rule::ProxyChanged]
        );
    }

    #[test]
    fn several_changes_raise_one_alert_each() {
        let mut after = home();
        after.dns_servers = vec!["203.0.113.53".to_owned()];
        after.private_dns = Some("dns.example".to_owned());
        after.proxy = Some("192.0.2.10:3128".to_owned());
        assert_eq!(
            rules(&network_changes(1, &home(), &after)),
            [
                Rule::DnsServersChanged,
                Rule::PrivateDnsChanged,
                Rule::ProxyChanged
            ]
        );
    }

    #[test]
    fn the_stored_state_and_rule_ids_are_stable() {
        let json = home().to_json();
        assert_eq!(
            json,
            r#"{"network":"7:100","dns_servers":["192.168.1.1","fd00::1"],"private_dns":null,"network_proxy":null,"proxy":null}"#
        );
        assert_eq!(NetworkState::from_json(&json).unwrap(), home());
        assert!(NetworkState::from_json("[]").is_err());
        let evidence = [
            Evidence::DnsServers {
                before: vec!["192.168.1.1".to_owned()],
                after: vec![],
            },
            Evidence::PrivateDns {
                before: None,
                after: Some("dns.example".to_owned()),
            },
            Evidence::Proxy {
                before: Some("192.0.2.10:3128".to_owned()),
                after: None,
            },
        ];
        let json = crate::evidence_to_json(&evidence);
        assert_eq!(
            json,
            r#"[{"type":"dns_servers","before":["192.168.1.1"],"after":[]},{"type":"private_dns","before":null,"after":"dns.example"},{"type":"proxy","before":"192.0.2.10:3128","after":null}]"#
        );
        assert_eq!(crate::evidence_from_json(&json).unwrap(), evidence);
        for (rule, id) in [
            (Rule::DnsServersChanged, "dns-servers-changed"),
            (Rule::PrivateDnsChanged, "private-dns-changed"),
            (Rule::ProxyChanged, "proxy-changed"),
        ] {
            assert_eq!(rule.id(), id);
            assert_eq!(Rule::from_id(id), Some(rule));
        }
    }
}

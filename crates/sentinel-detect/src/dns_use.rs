// SPDX-License-Identifier: GPL-3.0-or-later
//! Unusual DNS use (DL-05, ADR-0032):
//! - data hidden in DNS lookups, as DNS tunnels carry it: many long, random-looking
//!   names under one domain, or many TXT lookups;
//! - an app that talks to an encrypted DNS service itself, so that its lookups pass by
//!   the phone's resolver and Sentinel cannot see them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use crate::{Alert, Evidence, Rule, Severity};

/// How far back lookups are counted.
pub const DNS_WINDOW_MS: i64 = 10 * 60 * 1000;
/// Different random-looking names under one domain, within the window, that make a
/// tunnel. Ad and tracking services use a few such names; a tunnel uses one per lookup.
pub const TUNNEL_NAMES: usize = 20;
/// TXT lookups by one app within the window that make a tunnel. Apps hardly ever look
/// up TXT records; tunnels use them to bring data back.
pub const TUNNEL_TXT_LOOKUPS: usize = 20;
/// The TXT record type (RFC 1035).
pub const QTYPE_TXT: u16 = 16;
/// Characters before the domain from which a name may look random.
const RANDOM_MIN_CHARS: usize = 24;
/// Characters before the domain from which a name is long enough on its own.
const LONG_CHARS: usize = 52;
/// Bits per character from which a name looks random: words have less.
const RANDOM_MIN_BITS: f64 = 3.5;
/// Digits a random-looking name has at least: encoded data has them, words seldom do.
const RANDOM_MIN_DIGITS: usize = 3;
/// Apps and domains followed at once; beyond this the one heard from least recently is
/// forgotten.
const FOLLOWED: usize = 1024;

/// Public resolvers that answer encrypted DNS, by name (HTTPS or TLS)...
const ENCRYPTED_DNS_NAMES: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.mullvad.net",
    "doh.mullvad.net",
    "dns.controld.com",
    "freedns.controld.com",
];
/// ...and by address, where HTTPS or QUIC on port 443 is DNS.
const ENCRYPTED_DNS_ADDRESSES: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "1.1.1.2",
    "1.0.0.2",
    "1.1.1.3",
    "1.0.0.3",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "9.9.9.11",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
];
/// DNS over TLS and over QUIC.
const ENCRYPTED_DNS_PORT: u16 = 853;

/// What an app's lookups showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTunnel {
    /// `names` different random-looking names under `domain` within the window, such as
    /// `example`.
    Names {
        domain: String,
        names: u32,
        example: String,
    },
    /// `lookups` TXT lookups within the window.
    TxtLookups { lookups: u32 },
}

/// Follows each app's lookups for signs of a DNS tunnel. One per engine run: each app
/// and domain is reported once.
#[derive(Debug, Default)]
pub struct DnsWatch {
    /// Random-looking names by app and domain: when each was first asked for.
    names: HashMap<(String, String), VecDeque<(i64, String)>>,
    /// TXT lookups by app.
    txt: HashMap<String, VecDeque<i64>>,
    reported: HashSet<(String, Option<String>)>,
}

impl DnsWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// `app` looks up `name` (lower-case, no trailing dot) for records of type `qtype`
    /// at `now` (Unix ms). Returns what makes it look like a tunnel, the first time.
    pub fn lookup(&mut self, now: i64, app: &str, name: &str, qtype: u16) -> Option<DnsTunnel> {
        if qtype == QTYPE_TXT
            && let Some(lookups) = self.txt_lookup(now, app)
        {
            return Some(lookups);
        }
        let (domain, below) = split(name)?;
        if !random_looking(below) {
            return None;
        }
        let key = (app.to_owned(), domain.to_owned());
        if self
            .reported
            .contains(&(key.0.clone(), Some(key.1.clone())))
        {
            return None;
        }
        if !self.names.contains_key(&key) && self.names.len() >= FOLLOWED {
            forget_oldest(&mut self.names, |seen| seen.back().map(|&(at, _)| at));
        }
        let seen = self.names.entry(key.clone()).or_default();
        while seen
            .front()
            .is_some_and(|&(at, _)| at <= now - DNS_WINDOW_MS)
        {
            seen.pop_front();
        }
        if seen.iter().any(|(_, seen)| seen == name) {
            return None;
        }
        seen.push_back((now, name.to_owned()));
        if seen.len() < TUNNEL_NAMES {
            return None;
        }
        let names = u32::try_from(seen.len()).unwrap_or(u32::MAX);
        self.names.remove(&key);
        self.reported.insert((key.0, Some(key.1.clone())));
        Some(DnsTunnel::Names {
            domain: key.1,
            names,
            example: name.to_owned(),
        })
    }

    fn txt_lookup(&mut self, now: i64, app: &str) -> Option<DnsTunnel> {
        if self.reported.contains(&(app.to_owned(), None)) {
            return None;
        }
        if !self.txt.contains_key(app) && self.txt.len() >= FOLLOWED {
            forget_oldest(&mut self.txt, |seen| seen.back().copied());
        }
        let seen = self.txt.entry(app.to_owned()).or_default();
        while seen.front().is_some_and(|&at| at <= now - DNS_WINDOW_MS) {
            seen.pop_front();
        }
        seen.push_back(now);
        if seen.len() < TUNNEL_TXT_LOOKUPS {
            return None;
        }
        let lookups = u32::try_from(seen.len()).unwrap_or(u32::MAX);
        self.txt.remove(app);
        self.reported.insert((app.to_owned(), None));
        Some(DnsTunnel::TxtLookups { lookups })
    }
}

fn forget_oldest<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    last: impl Fn(&V) -> Option<i64>,
) {
    let oldest = map
        .iter()
        .min_by_key(|(_, value)| last(value).unwrap_or(i64::MIN))
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

/// The domain a name is under, and what comes before it: `a1b2.t.example.com` is
/// `example.com` and `a1b2.t`. A domain is the last two labels, or three under a short
/// second level of a country (`example.co.uk`). `None` when nothing comes before it.
fn split(name: &str) -> Option<(&str, &str)> {
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    let country_second_level = n >= 3 && labels[n - 1].len() == 2 && labels[n - 2].len() <= 3;
    let kept = if country_second_level { 3 } else { 2 };
    if n <= kept {
        return None;
    }
    let below: usize = labels[..n - kept].iter().map(|l| l.len() + 1).sum();
    Some((&name[below..], &name[..below - 1]))
}

/// Whether the part of a name before its domain looks like encoded data rather than
/// words: long, with digits, and with as many bits per character as random text.
fn random_looking(below: &str) -> bool {
    let chars: Vec<char> = below.chars().filter(|&c| c != '.').collect();
    if chars.len() >= LONG_CHARS {
        return true;
    }
    if chars.len() < RANDOM_MIN_CHARS
        || chars.iter().filter(|c| c.is_ascii_digit()).count() < RANDOM_MIN_DIGITS
    {
        return false;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for &c in &chars {
        *counts.entry(c).or_default() += 1;
    }
    let total = chars.len() as f64;
    let bits: f64 = counts
        .values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum();
    bits >= RANDOM_MIN_BITS
}

/// The encrypted DNS service a connection reaches, if it is one: anything on port 853
/// (DNS over TLS or QUIC), or a known public resolver by its name or, on port 443, its
/// address. `server_name` is the name the app used, if known.
pub fn encrypted_dns(ip: IpAddr, port: u16, server_name: Option<&str>) -> Option<String> {
    let known_name = server_name.filter(|name| {
        ENCRYPTED_DNS_NAMES.iter().any(|known| {
            name.strip_suffix(known)
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        })
    });
    let known_address = port == 443
        && ENCRYPTED_DNS_ADDRESSES
            .iter()
            .any(|known| known.parse::<IpAddr>().is_ok_and(|known| known == ip));
    if port == ENCRYPTED_DNS_PORT || known_name.is_some() || known_address {
        Some(server_name.map_or_else(|| ip.to_string(), str::to_owned))
    } else {
        None
    }
}

/// DL-05: `app`'s lookups look like data hidden in DNS. A Warning: tunnels hide data
/// this way, though some security apps look things up like this too.
pub fn dns_tunnel(now: i64, app: &str, tunnel: DnsTunnel) -> Alert {
    let evidence = match tunnel {
        DnsTunnel::Names {
            domain,
            names,
            example,
        } => Evidence::DnsNames {
            domain,
            names,
            example,
        },
        DnsTunnel::TxtLookups { lookups } => Evidence::DnsTxtLookups { lookups },
    };
    Alert {
        rule: Rule::DnsTunnel,
        severity: Severity::Warning,
        created: now,
        evidence: vec![
            Evidence::App {
                package: app.to_owned(),
            },
            evidence,
        ],
    }
}

/// DL-05: `app` reached `server`, an encrypted DNS service, itself: its lookups pass by
/// the phone's resolver and by Sentinel. Info: browsers and privacy apps do this too.
pub fn own_encrypted_dns(now: i64, app: &str, server: &str) -> Alert {
    Alert {
        rule: Rule::OwnEncryptedDns,
        severity: Severity::Info,
        created: now,
        evidence: vec![
            Evidence::App {
                package: app.to_owned(),
            },
            Evidence::EncryptedDns {
                server: server.to_owned(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "org.example.app";
    const MINUTE: i64 = 60_000;

    /// Base32 of a counter, as tunnel tools encode their data: 48 characters, mixed
    /// letters and digits.
    fn encoded(i: u64) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut state = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..48)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                ALPHABET[(state % 32) as usize] as char
            })
            .collect()
    }

    #[test]
    fn names_are_split_from_their_domain() {
        assert_eq!(split("a1b2.t.example.com"), Some(("example.com", "a1b2.t")));
        assert_eq!(split("x.example.co.uk"), Some(("example.co.uk", "x")));
        assert_eq!(split("example.com"), None);
        assert_eq!(split("example.co.uk"), None);
    }

    #[test]
    fn encoded_data_looks_random_and_words_do_not() {
        assert!(random_looking(&encoded(1)));
        assert!(random_looking("6f1d0a9c3b2e4d5f8a7b6c5d4e3f2a1b"), "hex");
        assert!(random_looking(&"a".repeat(60)), "very long");
        for words in [
            "www",
            "accounts",
            "r3---sn-4g5e6nzl",
            "this-is-a-very-long-subdomain-name",
            "android-context-data.prod",
            "edge-chat-latest-mobile",
        ] {
            assert!(!random_looking(words), "{words}");
        }
    }

    /// The DNS-tunnel simulation: a different encoded name every few seconds under one
    /// domain is found at the twentieth, once.
    #[test]
    fn a_tunnel_of_encoded_names_is_found() {
        let mut watch = DnsWatch::new();
        let mut found = Vec::new();
        for i in 0..40 {
            let name = format!("{}.t.tunnel.example", encoded(i));
            found.extend(watch.lookup(i as i64 * 3_000, APP, &name, 1));
        }
        assert_eq!(
            found,
            [DnsTunnel::Names {
                domain: "tunnel.example".to_owned(),
                names: 20,
                example: format!("{}.t.tunnel.example", encoded(19)),
            }]
        );
    }

    #[test]
    fn many_txt_lookups_are_found() {
        let mut watch = DnsWatch::new();
        let found: Vec<_> = (0..30)
            .filter_map(|i| watch.lookup(i * 10_000, APP, "cmd.example.net", QTYPE_TXT))
            .collect();
        assert_eq!(found, [DnsTunnel::TxtLookups { lookups: 20 }]);
    }

    #[test]
    fn ordinary_lookups_are_not_a_tunnel() {
        let mut watch = DnsWatch::new();
        let names = [
            "www.google.com",
            "play.googleapis.com",
            "r3---sn-4g5e6nzl.googlevideo.com",
            "i.ytimg.com",
            "edge-chat.facebook.com",
            "graph.instagram.com",
            "1234567890-abcdefghijklmnopqrstuv.apps.googleusercontent.com",
            "d1a2b3c4d5e6f7.cloudfront.net",
            "api.example.co.uk",
        ];
        for i in 0..1_000 {
            let name = names[i % names.len()];
            assert_eq!(watch.lookup(i as i64 * 500, APP, name, 1), None, "{name}");
        }
        // A few TXT lookups now and then.
        for i in 0..50 {
            assert_eq!(
                watch.lookup(i * MINUTE, APP, "example.com", QTYPE_TXT),
                None
            );
        }
    }

    #[test]
    fn slow_or_spread_out_lookups_are_not_a_tunnel() {
        let mut watch = DnsWatch::new();
        // One encoded name a minute: never twenty within ten minutes.
        for i in 0..60 {
            let name = format!("{}.tunnel.example", encoded(i));
            assert_eq!(watch.lookup(i as i64 * MINUTE, APP, &name, 1), None);
        }
        // The same encoded name again and again is one name.
        let same = format!("{}.tunnel.example", encoded(99));
        for i in 0..60 {
            assert_eq!(watch.lookup(i, "org.example.other", &same, 1), None);
        }
    }

    #[test]
    fn apps_are_followed_apart() {
        let mut watch = DnsWatch::new();
        let mut found = 0;
        for i in 0..30u64 {
            let app = if i % 2 == 0 { APP } else { "org.example.other" };
            let name = format!("{}.tunnel.example", encoded(i));
            found += usize::from(watch.lookup(i as i64 * 1_000, app, &name, 1).is_some());
        }
        assert_eq!(found, 0, "fifteen each");
    }

    #[test]
    fn memory_is_bounded() {
        let mut watch = DnsWatch::new();
        for i in 0..(FOLLOWED as u64 + 50) {
            let name = format!("{}.domain{i}.example", encoded(i));
            watch.lookup(i as i64, APP, &name, 1);
        }
        assert_eq!(watch.names.len(), FOLLOWED);
    }

    #[test]
    fn encrypted_dns_services_are_known_by_port_name_or_address() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            encrypted_dns(ip("203.0.113.5"), 853, None).as_deref(),
            Some("203.0.113.5"),
            "DNS over TLS anywhere"
        );
        assert_eq!(
            encrypted_dns(ip("203.0.113.5"), 443, Some("mozilla.cloudflare-dns.com")).as_deref(),
            Some("mozilla.cloudflare-dns.com")
        );
        assert_eq!(
            encrypted_dns(ip("8.8.8.8"), 443, None).as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(
            encrypted_dns(ip("2606:4700:4700::1111"), 443, None).as_deref(),
            Some("2606:4700:4700::1111")
        );
        assert_eq!(
            encrypted_dns(ip("8.8.8.8"), 80, None),
            None,
            "not encrypted"
        );
        assert_eq!(
            encrypted_dns(ip("203.0.113.5"), 443, Some("www.google.com")),
            None
        );
        assert_eq!(
            encrypted_dns(ip("203.0.113.5"), 443, Some("notdns.google")),
            None
        );
    }

    #[test]
    fn the_alerts_name_the_app_and_what_was_seen() {
        let tunnel = dns_tunnel(7, APP, DnsTunnel::TxtLookups { lookups: 20 });
        assert_eq!(tunnel.severity, Severity::Warning);
        assert_eq!(tunnel.app(), Some(APP));
        assert_eq!(
            tunnel.actions(),
            vec![
                crate::Action::BlockApp {
                    package: APP.to_owned()
                },
                crate::Action::OpenApp {
                    package: APP.to_owned()
                },
            ]
        );
        let names = dns_tunnel(
            7,
            APP,
            DnsTunnel::Names {
                domain: "tunnel.example".to_owned(),
                names: 20,
                example: "abc.tunnel.example".to_owned(),
            },
        );
        let own = own_encrypted_dns(7, APP, "dns.google");
        assert_eq!(own.severity, Severity::Info);
        assert_eq!(own.actions(), tunnel.actions());
        assert_eq!(
            crate::evidence_to_json(&[
                tunnel.evidence[1].clone(),
                names.evidence[1].clone(),
                own.evidence[1].clone()
            ]),
            concat!(
                r#"[{"type":"dns_txt_lookups","lookups":20},"#,
                r#"{"type":"dns_names","domain":"tunnel.example","names":20,"example":"abc.tunnel.example"},"#,
                r#"{"type":"encrypted_dns","server":"dns.google"}]"#
            )
        );
    }
}

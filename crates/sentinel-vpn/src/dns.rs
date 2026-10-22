// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS answers seen in the tunnel, used to put a name on later connections (CM-02).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use simple_dns::rdata::RData;
use simple_dns::{Packet, PacketFlag, RCODE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// The name the app asked for, lower-cased, without a trailing dot.
    pub qname: String,
    pub ips: Vec<(IpAddr, u32)>,
}

/// Parse a DNS response. Returns `None` for queries, malformed packets, and responses
/// without A or AAAA answers.
pub fn parse_dns_response(datagram: &[u8]) -> Option<DnsAnswer> {
    let packet = Packet::parse(datagram).ok()?;
    if !packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    let qname = packet.questions.first()?.qname.to_string();
    let qname = qname.trim_end_matches('.').to_ascii_lowercase();
    if qname.is_empty() {
        return None;
    }
    let ips: Vec<(IpAddr, u32)> = packet
        .answers
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::A(a) => Some((IpAddr::V4(Ipv4Addr::from(a.address)), rr.ttl)),
            RData::AAAA(a) => Some((IpAddr::V6(Ipv6Addr::from(a.address)), rr.ttl)),
            _ => None,
        })
        .collect();
    if ips.is_empty() {
        return None;
    }
    Some(DnsAnswer { qname, ips })
}

/// What a DNS query asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Lower-cased, without the trailing dot.
    pub name: String,
    /// The record type asked for, as numbered in the DNS (RFC 1035): 1 for A, 16 for
    /// TXT, 28 for AAAA.
    pub qtype: u16,
}

/// What a DNS query asks, from its first question. `None` for responses, malformed
/// packets and queries without a question.
pub fn parse_dns_query(datagram: &[u8]) -> Option<DnsQuery> {
    let packet = Packet::parse(datagram).ok()?;
    if packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    let question = packet.questions.first()?;
    let name = question.qname.to_string();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then(|| DnsQuery {
        name,
        qtype: u16::from(question.qtype),
    })
}

/// An answer to `query` saying that the name does not exist (NXDOMAIN): what a blocked
/// lookup gets (ADR-0015). It repeats the query's id and questions, so the app's
/// resolver accepts it at once. `None` if `query` cannot be read.
pub fn name_error_reply(query: &[u8]) -> Option<Vec<u8>> {
    let query = Packet::parse(query).ok()?;
    if query.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    let mut reply = Packet::new_reply(query.id());
    reply.questions = query.questions.clone();
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *reply.rcode_mut() = RCODE::NameError;
    reply.build_bytes_vec().ok()
}

/// Maps IP addresses back to the name an app looked up.
///
/// Apps often keep using an address after its DNS TTL, so entries live at least
/// [`DnsCache::MIN_KEEP`]. When several names share an address (CDNs), the most recent
/// answer wins; SNI then gives the precise name for TLS flows. A full cache drops the
/// entries closest to expiring, never all of them (audit A-05).
pub struct DnsCache {
    entries: Mutex<HashMap<IpAddr, (String, Instant)>>,
    capacity: usize,
}

impl DnsCache {
    pub const MIN_KEEP: Duration = Duration::from_secs(10 * 60);
    pub const MAX_KEEP: Duration = Duration::from_secs(24 * 60 * 60);

    pub fn new(capacity: usize) -> Self {
        DnsCache {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    pub fn insert(&self, answer: &DnsAnswer) {
        let now = Instant::now();
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        if map.len() + answer.ips.len() > self.capacity {
            map.retain(|_, (_, expires)| *expires > now);
            if map.len() + answer.ips.len() > self.capacity {
                // Still full of live entries: drop those closest to expiring, an eighth of
                // the cache at a time so that this is rare. Dropping them all would let one
                // large answer wipe every name (audit A-05).
                let drop = (map.len() + answer.ips.len())
                    .saturating_sub(self.capacity)
                    .max(self.capacity / 8);
                let mut by_expiry: Vec<(Instant, IpAddr)> = map
                    .iter()
                    .map(|(ip, (_, expires))| (*expires, *ip))
                    .collect();
                if drop < by_expiry.len() {
                    by_expiry.select_nth_unstable(drop);
                }
                for (_, ip) in by_expiry.into_iter().take(drop) {
                    map.remove(&ip);
                }
            }
        }
        // An answer larger than the whole cache keeps what fits.
        for (ip, ttl) in answer.ips.iter().take(self.capacity) {
            let keep = Duration::from_secs(u64::from(*ttl)).clamp(Self::MIN_KEEP, Self::MAX_KEEP);
            map.insert(*ip, (answer.qname.clone(), now + keep));
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let map = self.entries.lock().ok()?;
        let (name, expires) = map.get(ip)?;
        (*expires > Instant::now()).then(|| name.clone())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use simple_dns::rdata::{A, AAAA};
    use simple_dns::{CLASS, Name, Question, ResourceRecord, TYPE};

    pub(crate) fn response(name: &str, v4: &[Ipv4Addr], v6: &[Ipv6Addr]) -> Vec<u8> {
        let mut p = Packet::new_reply(0x1234);
        p.questions.push(Question::new(
            Name::new_unchecked(name),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
        for ip in v4 {
            p.answers.push(ResourceRecord::new(
                Name::new_unchecked(name),
                CLASS::IN,
                300,
                RData::A(A::from(*ip)),
            ));
        }
        for ip in v6 {
            p.answers.push(ResourceRecord::new(
                Name::new_unchecked(name),
                CLASS::IN,
                300,
                RData::AAAA(AAAA::from(*ip)),
            ));
        }
        p.build_bytes_vec().unwrap()
    }

    pub(crate) fn query(id: u16, name: &str) -> Vec<u8> {
        let mut p = Packet::new_query(id);
        p.set_flags(PacketFlag::RECURSION_DESIRED);
        p.questions.push(Question::new(
            Name::new_unchecked(name),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
        p.build_bytes_vec().unwrap()
    }

    #[test]
    fn reads_the_name_a_query_asks_for() {
        assert_eq!(
            parse_dns_query(&query(1, "Ads.Example.")),
            Some(DnsQuery {
                name: "ads.example".to_owned(),
                qtype: 1,
            }),
            "an A query"
        );
        assert_eq!(
            parse_dns_query(&response("ads.example", &[Ipv4Addr::LOCALHOST], &[])),
            None,
            "an answer is not a query"
        );
        assert_eq!(
            parse_dns_query(&Packet::new_query(2).build_bytes_vec().unwrap()),
            None
        );
        assert_eq!(parse_dns_query(b"not dns"), None);
    }

    /// A blocked lookup gets "no such name" for its own question, with its own id.
    #[test]
    fn a_name_error_reply_answers_the_query() {
        let reply = name_error_reply(&query(0xbeef, "ads.example")).unwrap();
        let packet = Packet::parse(&reply).unwrap();
        assert_eq!(packet.id(), 0xbeef);
        assert!(packet.has_flags(PacketFlag::RESPONSE));
        assert!(packet.has_flags(PacketFlag::RECURSION_DESIRED));
        assert!(packet.has_flags(PacketFlag::RECURSION_AVAILABLE));
        assert_eq!(packet.rcode(), RCODE::NameError);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qname.to_string(), "ads.example");
        assert!(packet.answers.is_empty());
        assert_eq!(parse_dns_response(&reply), None, "it names no address");
        assert_eq!(
            name_error_reply(&response("ads.example", &[Ipv4Addr::LOCALHOST], &[])),
            None
        );
        assert_eq!(name_error_reply(b"\x00"), None);
    }

    #[test]
    fn parses_a_and_aaaa_answers() {
        let bytes = response(
            "Tracker.Example.",
            &[Ipv4Addr::new(203, 0, 113, 7)],
            &[Ipv6Addr::LOCALHOST],
        );
        let answer = parse_dns_response(&bytes).unwrap();
        assert_eq!(answer.qname, "tracker.example");
        assert_eq!(answer.ips.len(), 2);
    }

    #[test]
    fn ignores_queries_and_garbage() {
        let mut query = Packet::new_query(1);
        query.questions.push(Question::new(
            Name::new_unchecked("a.example"),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
        assert!(parse_dns_response(&query.build_bytes_vec().unwrap()).is_none());
        assert!(parse_dns_response(&[]).is_none());
        assert!(parse_dns_response(&[0xFF; 40]).is_none());
        let bytes = response("a.example", &[Ipv4Addr::new(192, 0, 2, 1)], &[]);
        for len in 0..bytes.len() {
            let _ = parse_dns_response(&bytes[..len]);
        }
    }

    #[test]
    fn cache_maps_ip_to_name_and_stays_bounded() {
        let cache = DnsCache::new(3);
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        cache.insert(&DnsAnswer {
            qname: "a.example".into(),
            ips: vec![(ip, 1)],
        });
        assert_eq!(cache.lookup(&ip).as_deref(), Some("a.example"));
        for i in 0..10u8 {
            cache.insert(&DnsAnswer {
                qname: format!("n{i}.example"),
                ips: vec![(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 60)],
            });
            assert!(cache.len() <= 3);
        }
    }

    /// Audit A-05: a full cache drops the names closest to expiring, not every name, so
    /// one large answer cannot wipe the names of everyone else's connections.
    #[test]
    fn a_full_cache_keeps_its_longest_lived_names() {
        let cache = DnsCache::new(8);
        let ip = |i: u8| IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
        // Eight names, each kept ten minutes less than the one before.
        for i in 0..8u8 {
            cache.insert(&DnsAnswer {
                qname: format!("n{i}.example"),
                ips: vec![(ip(i), 86_400 - u32::from(i) * 600)],
            });
        }
        cache.insert(&DnsAnswer {
            qname: "new.example".into(),
            ips: vec![(ip(100), 300)],
        });
        assert_eq!(cache.len(), 8);
        assert_eq!(cache.lookup(&ip(100)).as_deref(), Some("new.example"));
        assert_eq!(cache.lookup(&ip(0)).as_deref(), Some("n0.example"));
        assert_eq!(
            cache.lookup(&ip(7)),
            None,
            "the one closest to expiring goes"
        );

        // An answer larger than the cache keeps what fits.
        cache.insert(&DnsAnswer {
            qname: "big.example".into(),
            ips: (0..20u8).map(|i| (ip(200 + i / 4), 300)).collect(),
        });
        assert!(cache.len() <= 8);
    }
}

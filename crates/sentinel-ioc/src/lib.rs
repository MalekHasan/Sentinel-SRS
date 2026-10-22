// SPDX-License-Identifier: GPL-3.0-or-later
//! Indicator files of the signed feed (SRS MS-10, ID-13; ADR-0019): domains, addresses,
//! app packages and signing certificates that public reports tie to spyware or
//! stalkerware.
//!
//! Each file holds the indicators of one source, so that sources under different
//! licences never mix in one file (LICENCE-REVIEW.md). It is named after its source,
//! `indicators-<source>.json`, and says who the source is, where its data comes from and
//! under which licence. Every indicator carries the rest of its provenance: the date it
//! was published and the report that names it (MS-10).
//!
//! Files are checked when they are loaded, although the feed is signed. A file whose
//! indicators lack provenance, or name something that is not a valid domain, address,
//! package or certificate, is refused as a whole. Kinds and threats this version does not
//! know are skipped and counted, so that a feed made for newer or other editions still
//! installs.
//!
//! A [`Matcher`] holds the domain and address indicators of the list in force, to match
//! the phone's traffic against.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

mod matcher;

pub use matcher::{Hit, Matcher};

/// The indicator file format this version reads.
pub const SCHEMA: u32 = 1;

/// Most indicators one file may hold, so that a damaged file cannot exhaust memory.
pub const MAX_INDICATORS: usize = 1_000_000;

const FILE_PREFIX: &str = "indicators-";
const FILE_SUFFIX: &str = ".json";

/// What an indicator names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A domain: it and every name below it. Lower case, without a trailing dot.
    Domain,
    /// One IP address, as Rust writes it.
    Address,
    /// An Android app's package name.
    Package,
    /// The SHA-256 of an app's signing certificate, in lower-case hex.
    Certificate,
}

/// What kind of threat the report describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Threat {
    /// Mercenary spyware, such as Pegasus or Predator (SRS §8A).
    Spyware,
    /// Stalkerware and remote-access tools sold to watch a partner or relative (ID-13).
    Stalkerware,
}

/// Who published the indicators of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Short name, used in the file name: lower-case letters, digits and `-`.
    pub id: String,
    /// The publisher, as the app shows it.
    pub name: String,
    /// Where the data comes from: an `https` link.
    pub url: String,
    /// The licence the data is under.
    pub licence: String,
}

/// One indicator, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: Kind,
    pub value: String,
    /// The spyware or stalkerware family, as the report names it.
    pub family: String,
    pub threat: Threat,
    /// When the report was published: `YYYY-MM-DD`.
    pub date: String,
    /// The report that names this indicator: an `https` link.
    pub report: String,
}

/// An indicator file, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorFile {
    pub source: Source,
    pub indicators: Vec<Indicator>,
    /// Indicators of a kind or threat this version does not know, left out.
    pub skipped: usize,
}

/// Why an indicator file was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IocError {
    #[error("not an indicator file: {0}")]
    Format(String),
    #[error("indicator file schema {0} is not supported")]
    Schema(u32),
    #[error("the source's {0} is not valid")]
    Source(&'static str),
    #[error("indicator {index}: {problem}")]
    Indicator { index: usize, problem: &'static str },
    #[error("more than {MAX_INDICATORS} indicators")]
    TooMany,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    /// Checked before the rest of the file is read.
    #[serde(rename = "schema")]
    _schema: u32,
    source: RawSource,
    indicators: Vec<RawIndicator>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    id: String,
    name: String,
    url: String,
    licence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIndicator {
    kind: String,
    value: String,
    family: String,
    threat: String,
    date: String,
    report: String,
}

impl IndicatorFile {
    /// Read and check an indicator file.
    pub fn parse(bytes: &[u8]) -> Result<IndicatorFile, IocError> {
        // The schema comes first, so a newer format is reported as such rather than as
        // a field this version does not know.
        #[derive(Deserialize)]
        struct Schema {
            schema: u32,
        }
        let Schema { schema } =
            serde_json::from_slice(bytes).map_err(|e| IocError::Format(e.to_string()))?;
        if schema != SCHEMA {
            return Err(IocError::Schema(schema));
        }
        let raw: RawFile =
            serde_json::from_slice(bytes).map_err(|e| IocError::Format(e.to_string()))?;
        if raw.indicators.len() > MAX_INDICATORS {
            return Err(IocError::TooMany);
        }
        let source = check_source(raw.source)?;
        let mut indicators = Vec::with_capacity(raw.indicators.len());
        let mut skipped = 0;
        for (index, raw) in raw.indicators.into_iter().enumerate() {
            let problem = |problem| IocError::Indicator { index, problem };
            let (Some(kind), Some(threat)) = (kind(&raw.kind), threat(&raw.threat)) else {
                skipped += 1;
                continue;
            };
            if !valid_value(kind, &raw.value) {
                return Err(problem(match kind {
                    Kind::Domain => "not a lower-case domain name",
                    Kind::Address => "not a public IP address",
                    Kind::Package => "not a package name",
                    Kind::Certificate => "not a lower-case SHA-256",
                }));
            }
            if !is_text(&raw.family, 100) {
                return Err(problem("no family"));
            }
            if !is_date(&raw.date) {
                return Err(problem("no date, or not YYYY-MM-DD"));
            }
            if !is_https(&raw.report) {
                return Err(problem("no report link, or not https"));
            }
            indicators.push(Indicator {
                kind,
                value: raw.value,
                family: raw.family,
                threat,
                date: raw.date,
                report: raw.report,
            });
        }
        Ok(IndicatorFile {
            source,
            indicators,
            skipped,
        })
    }

    /// The name this file must have in the feed: `indicators-<source>.json`.
    pub fn file_name(&self) -> String {
        format!("{FILE_PREFIX}{}{FILE_SUFFIX}", self.source.id)
    }
}

/// Whether a feed file at `path` is an indicator file.
pub fn is_indicator_file(path: &str) -> bool {
    path.strip_prefix(FILE_PREFIX)
        .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
        .is_some_and(is_source_id)
}

fn check_source(raw: RawSource) -> Result<Source, IocError> {
    if !is_source_id(&raw.id) {
        return Err(IocError::Source("id"));
    }
    if !is_text(&raw.name, 100) {
        return Err(IocError::Source("name"));
    }
    if !is_https(&raw.url) {
        return Err(IocError::Source("link"));
    }
    if !is_text(&raw.licence, 100) {
        return Err(IocError::Source("licence"));
    }
    Ok(Source {
        id: raw.id,
        name: raw.name,
        url: raw.url,
        licence: raw.licence,
    })
}

fn kind(name: &str) -> Option<Kind> {
    match name {
        "domain" => Some(Kind::Domain),
        "address" => Some(Kind::Address),
        "package" => Some(Kind::Package),
        "certificate" => Some(Kind::Certificate),
        _ => None,
    }
}

fn threat(name: &str) -> Option<Threat> {
    match name {
        "spyware" => Some(Threat::Spyware),
        "stalkerware" => Some(Threat::Stalkerware),
        _ => None,
    }
}

fn valid_value(kind: Kind, value: &str) -> bool {
    match kind {
        Kind::Domain => is_domain(value),
        Kind::Address => is_public_address(value),
        Kind::Package => is_package(value),
        Kind::Certificate => {
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
    }
}

fn is_source_id(id: &str) -> bool {
    (1..=40).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// One line of text, not empty, at most `max` characters.
fn is_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.chars().count() <= max && !text.chars().any(char::is_control)
}

/// An `https` link with a host, without spaces or control characters.
fn is_https(link: &str) -> bool {
    link.len() <= 2048
        && link
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && !link.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `YYYY-MM-DD`, a day that exists.
fn is_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if !date.is_ascii() || bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = &date[range];
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// A lower-case domain of at least two labels, without a trailing dot, and not an
/// address: a whole top-level domain is never an indicator.
fn is_domain(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
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

/// An address a server on the internet could have, written as Rust writes it. Local,
/// private and special addresses are refused: an indicator naming one would match a
/// home network's own traffic, or a phone's (audit A-52). The documentation ranges
/// (RFC 5737, RFC 3849) are kept: nothing is reached there, and tests use them.
fn is_public_address(text: &str) -> bool {
    let Ok(address) = text.parse::<IpAddr>() else {
        return false;
    };
    if address.to_string() != text {
        return false;
    }
    match address {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                // 100.64.0.0/10, shared address space (carrier-grade NAT).
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
                // 0.0.0.0/8, "this network".
                || v4.octets()[0] == 0
                // 192.0.0.0/24, protocol assignments: Android's 464XLAT (192.0.0.4)
                // and `ipv4only.arpa`, by which NAT64 is found (192.0.0.170).
                || v4.octets()[..3] == [192, 0, 0]
                // 198.18.0.0/15, for benchmarks; proxies hand these out as stand-ins.
                || (v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18)
                // 240.0.0.0/4, reserved.
                || v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.to_ipv4_mapped().is_some()
                // An IPv4 address through NAT64 is matched as IPv4 (audit A-23).
                || nat64(v6).is_some()
                // 64:ff9b:1::/48, NAT64 prefixes a network chooses (RFC 8215).
                || v6.segments()[..3] == [0x64, 0xff9b, 1]
                // 100::/64, discarded (RFC 6666).
                || v6.segments()[..4] == [0x100, 0, 0, 0]
                // fc00::/7 unique local, fe80::/10 link-local.
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}

/// The IPv4 address an address of NAT64's well-known prefix stands for: `64:ff9b::/96`
/// (RFC 6052), as on a network that reaches IPv4 only through NAT64 (audit A-23).
pub(crate) fn nat64(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let [a, b, c, d] = v6.octets()[12..] else {
        return None;
    };
    (v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]).then(|| Ipv4Addr::new(a, b, c, d))
}

/// An Android package name: at least two dot-separated parts, each starting with a
/// letter, made of letters, digits and `_`.
fn is_package(name: &str) -> bool {
    name.len() <= 255
        && name.contains('.')
        && name.split('.').all(|part| {
            part.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

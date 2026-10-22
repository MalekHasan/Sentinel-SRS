// SPDX-License-Identifier: GPL-3.0-or-later
//! Matching traffic against indicators (ID-13): which names and addresses match, and
//! that every match keeps its provenance.

#![allow(clippy::unwrap_used)]

use std::net::IpAddr;

use sentinel_ioc::{IndicatorFile, Matcher, Threat};
use serde_json::{Value, json};

fn file(source: &str, indicators: &[(&str, &str, &str)]) -> IndicatorFile {
    let indicators: Vec<Value> = indicators
        .iter()
        .map(|(kind, value, family)| {
            json!({
                "kind": kind,
                "value": value,
                "family": family,
                "threat": "spyware",
                "date": "2023-09-22",
                "report": format!("https://example.org/{source}/report"),
            })
        })
        .collect();
    let json = json!({
        "schema": 1,
        "source": {
            "id": source,
            "name": format!("Source {source}"),
            "url": "https://example.org/data",
            "licence": "CC BY 4.0",
        },
        "indicators": indicators,
    });
    IndicatorFile::parse(&serde_json::to_vec(&json).unwrap()).unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn a_domain_matches_itself_and_every_name_below_it() {
    let matcher = Matcher::new([file("lab", &[("domain", "bad.example.org", "Predator")])]);
    for name in [
        "bad.example.org",
        "cdn.bad.example.org",
        "a.b.c.bad.example.org",
        "BAD.Example.ORG",
        "bad.example.org.",
    ] {
        let hit = matcher.name(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(hit.indicator.value, "bad.example.org");
    }
    for name in [
        "example.org",
        "org",
        "notbad.example.org",
        "bad.example.org.evil",
        "bad.example.com",
        "bad-example.org",
        "",
        ".",
    ] {
        assert_eq!(matcher.name(name), None, "{name}");
    }
}

#[test]
fn a_hit_carries_its_provenance() {
    let matcher = Matcher::new([
        file("first", &[("domain", "shared.example", "Pegasus")]),
        file(
            "second",
            &[
                ("domain", "shared.example", "Other"),
                ("address", "198.51.100.7", "Graphite"),
            ],
        ),
    ]);
    let hit = matcher.name("x.shared.example").unwrap();
    assert_eq!(
        hit.indicator.family, "Pegasus",
        "the first source's entry is kept"
    );
    assert_eq!(hit.indicator.threat, Threat::Spyware);
    assert_eq!(hit.indicator.date, "2023-09-22");
    assert_eq!(hit.indicator.report, "https://example.org/first/report");
    assert_eq!(hit.source.name, "Source first");

    let hit = matcher.address(ip("198.51.100.7")).unwrap();
    assert_eq!(hit.indicator.family, "Graphite");
    assert_eq!(hit.source.id, "second");
    assert_eq!(matcher.len(), 2);
}

#[test]
fn an_address_matches_exactly() {
    let matcher = Matcher::new([file(
        "lab",
        &[
            ("address", "198.51.100.7", "Pegasus"),
            ("address", "2001:db8::7", "Pegasus"),
        ],
    )]);
    assert!(matcher.address(ip("198.51.100.7")).is_some());
    assert!(
        matcher.address(ip("::ffff:198.51.100.7")).is_some(),
        "an IPv4 address written as IPv6"
    );
    assert!(
        matcher.address(ip("64:ff9b::198.51.100.7")).is_some(),
        "an IPv4 address through NAT64 (audit A-23)"
    );
    assert!(matcher.address(ip("2001:db8::7")).is_some());
    assert!(matcher.address(ip("2001:0db8:0:0::7")).is_some());
    for other in [
        "198.51.100.8",
        "198.51.100.70",
        "2001:db8::8",
        "::198.51.100.7",
    ] {
        assert_eq!(matcher.address(ip(other)), None, "{other}");
    }
}

#[test]
fn kinds_do_not_cross() {
    let certificate = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    let matcher = Matcher::new([file(
        "lab",
        &[
            ("domain", "bad.example", "Hermit"),
            ("address", "203.0.113.9", "Hermit"),
            ("package", "com.example.watch", "Hermit"),
            ("certificate", certificate, "Hermit"),
        ],
    )]);
    assert_eq!(matcher.len(), 4);
    assert_eq!(matcher.name("203.0.113.9"), None);
    assert_eq!(
        matcher.name("com.example.watch"),
        None,
        "a package is not a name"
    );
    assert_eq!(matcher.package("bad.example"), None);
    assert_eq!(matcher.certificate("bad.example"), None);
}

/// ID-13: installed apps are matched by their exact package name, and by the SHA-256 of
/// any certificate they are signed with, whatever its case.
#[test]
fn an_app_matches_by_package_or_certificate() {
    let certificate = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    let matcher = Matcher::new([file(
        "lab",
        &[
            ("package", "com.example.watch", "Hermit"),
            ("certificate", certificate, "Hermit"),
        ],
    )]);
    let hit = matcher.package("com.example.watch").unwrap();
    assert_eq!(hit.indicator.value, "com.example.watch");
    assert_eq!(hit.source.id, "lab");
    for other in [
        "com.example.watch2",
        "com.example",
        "Com.Example.Watch",
        "watch",
    ] {
        assert_eq!(matcher.package(other), None, "{other}");
    }
    assert_eq!(
        matcher.certificate(certificate).unwrap().indicator.value,
        certificate
    );
    assert!(
        matcher
            .certificate(&certificate.to_ascii_uppercase())
            .is_some()
    );
    assert_eq!(matcher.certificate(&certificate[1..]), None);
    assert_eq!(matcher.certificate(&"5e".repeat(31)), None);
}

#[test]
fn an_empty_list_matches_nothing() {
    let matcher = Matcher::new([]);
    assert!(matcher.is_empty());
    assert_eq!(matcher.name("bad.example"), None);
    assert_eq!(matcher.address(ip("198.51.100.7")), None);
    let matcher = Matcher::new([file("lab", &[])]);
    assert!(matcher.is_empty());
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Indicator files: what is accepted, and that every indicator's provenance is checked
//! on load (SRS MS-10).

#![allow(clippy::unwrap_used)]

use sentinel_ioc::{
    Indicator, IndicatorFile, IocError, Kind, MAX_INDICATORS, Source, Threat, is_indicator_file,
};
use serde_json::{Value, json};

fn indicator(kind: &str, value: &str) -> Value {
    json!({
        "kind": kind,
        "value": value,
        "family": "Pegasus",
        "threat": "spyware",
        "date": "2021-07-18",
        "report": "https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/",
    })
}

fn file(indicators: Vec<Value>) -> Value {
    json!({
        "schema": 1,
        "source": {
            "id": "amnesty",
            "name": "Amnesty International Security Lab",
            "url": "https://github.com/AmnestyTech/investigations",
            "licence": "CC BY 4.0",
        },
        "indicators": indicators,
    })
}

fn parse(value: &Value) -> Result<IndicatorFile, IocError> {
    IndicatorFile::parse(&serde_json::to_vec(value).unwrap())
}

/// The format is fixed here: a source and, for each indicator, what it names and its
/// provenance.
#[test]
fn a_file_gives_its_source_and_each_indicator_with_its_provenance() {
    let parsed = parse(&file(vec![
        indicator("domain", "free247downloads.com"),
        indicator("address", "203.0.113.7"),
        indicator("address", "2001:db8::7"),
        json!({
            "kind": "package",
            "value": "com.example.spy_app",
            "family": "ExampleSpy",
            "threat": "stalkerware",
            "date": "2024-02-29",
            "report": "https://stopstalkerware.org/example",
        }),
        indicator("certificate", &"ab".repeat(32)),
    ]))
    .unwrap();
    assert_eq!(
        parsed.source,
        Source {
            id: "amnesty".into(),
            name: "Amnesty International Security Lab".into(),
            url: "https://github.com/AmnestyTech/investigations".into(),
            licence: "CC BY 4.0".into(),
        }
    );
    assert_eq!(parsed.file_name(), "indicators-amnesty.json");
    assert_eq!(parsed.skipped, 0);
    let kinds: Vec<_> = parsed.indicators.iter().map(|i| i.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::Domain,
            Kind::Address,
            Kind::Address,
            Kind::Package,
            Kind::Certificate
        ]
    );
    assert_eq!(
        parsed.indicators[3],
        Indicator {
            kind: Kind::Package,
            value: "com.example.spy_app".into(),
            family: "ExampleSpy".into(),
            threat: Threat::Stalkerware,
            date: "2024-02-29".into(),
            report: "https://stopstalkerware.org/example".into(),
        }
    );
}

/// MS-10: provenance on every indicator. A file with one indicator lacking any part of
/// it is refused as a whole.
#[test]
fn an_indicator_without_its_provenance_refuses_the_file() {
    for (field, bad) in [
        ("family", json!("")),
        ("family", json!("   ")),
        ("date", json!("")),
        ("date", json!("18/07/2021")),
        ("date", json!("2021-02-29")),
        ("date", json!("2021-13-01")),
        ("date", json!("2021-07-32")),
        ("date", json!("2021-07-1é")),
        ("report", json!("")),
        ("report", json!("http://www.amnesty.org/report")),
        ("report", json!("https://")),
        ("report", json!("https:///path")),
        ("report", json!("https://example.org/a report")),
        ("report", json!("www.amnesty.org/report")),
    ] {
        let mut second = indicator("domain", "second.example");
        second[field] = bad.clone();
        let refused = parse(&file(vec![indicator("domain", "first.example"), second]));
        assert!(
            matches!(refused, Err(IocError::Indicator { index: 1, .. })),
            "{field} = {bad}: {refused:?}"
        );
    }
    for field in ["family", "date", "report", "threat", "value"] {
        let mut missing = indicator("domain", "second.example");
        missing.as_object_mut().unwrap().remove(field);
        let refused = parse(&file(vec![missing]));
        assert!(
            matches!(refused, Err(IocError::Format(_))),
            "without {field}: {refused:?}"
        );
    }
}

#[test]
fn a_source_without_its_details_refuses_the_file() {
    for (field, bad, problem) in [
        ("id", "", "id"),
        ("id", "Amnesty", "id"),
        ("id", "amnesty/../x", "id"),
        ("name", "", "name"),
        ("url", "http://github.com/AmnestyTech", "link"),
        ("licence", "", "licence"),
    ] {
        let mut bad_file = file(vec![]);
        bad_file["source"][field] = json!(bad);
        assert_eq!(
            parse(&bad_file),
            Err(IocError::Source(problem)),
            "{field} = {bad}"
        );
    }
}

/// Each kind names what it says, written one way only, so that matching is exact.
#[test]
fn values_must_be_what_their_kind_says() {
    for (kind, bad) in [
        ("domain", "Example.com"),
        ("domain", "example.com."),
        ("domain", "com"),
        ("domain", "-bad.example"),
        ("domain", "bad..example"),
        ("domain", "203.0.113.7"),
        ("domain", "spaced name.example"),
        // Written another way than Rust writes it.
        ("address", "2001:DB8::7"),
        ("address", "203.000.113.7"),
        ("address", "203.0.113.0/24"),
        // Addresses that a home network's own traffic would match.
        ("address", "10.0.0.1"),
        ("address", "192.168.1.1"),
        ("address", "172.16.0.1"),
        ("address", "127.0.0.1"),
        ("address", "0.0.0.0"),
        ("address", "169.254.0.1"),
        ("address", "100.64.0.1"),
        ("address", "224.0.0.1"),
        ("address", "255.255.255.255"),
        ("address", "::1"),
        ("address", "::"),
        ("address", "fe80::1"),
        ("address", "fd00::1"),
        ("address", "::ffff:203.0.113.7"),
        ("address", "64:ff9b::cb00:7107"),
        ("address", "ff02::1"),
        ("package", "spyapp"),
        ("package", "com.1example.app"),
        ("package", "com..app"),
        ("package", "com.example-app.x"),
        ("certificate", &"AB".repeat(32)),
        ("certificate", &"ab".repeat(31)),
        ("certificate", &"zz".repeat(32)),
    ] {
        let refused = parse(&file(vec![indicator(kind, bad)]));
        assert!(
            matches!(refused, Err(IocError::Indicator { index: 0, .. })),
            "{kind} {bad}: {refused:?}"
        );
    }
}

/// A feed also serves other editions: kinds and threats this version does not know are
/// left out and counted, and the rest of the file is used.
#[test]
fn unknown_kinds_and_threats_are_skipped() {
    let mut other_threat = indicator("domain", "adware.example");
    other_threat["threat"] = json!("adware");
    let parsed = parse(&file(vec![
        indicator("file-hash", "d41d8cd98f00b204e9800998ecf8427e"),
        other_threat,
        indicator("domain", "known.example"),
    ]))
    .unwrap();
    assert_eq!(parsed.skipped, 2);
    assert_eq!(parsed.indicators.len(), 1);
    assert_eq!(parsed.indicators[0].value, "known.example");
}

#[test]
fn other_formats_are_refused() {
    let mut newer = file(vec![]);
    newer["schema"] = json!(2);
    assert_eq!(parse(&newer), Err(IocError::Schema(2)));
    let mut extra = file(vec![]);
    extra["comment"] = json!("not part of the format");
    assert!(matches!(parse(&extra), Err(IocError::Format(_))));
    let mut extra_field = indicator("domain", "known.example");
    extra_field["severity"] = json!("high");
    assert!(matches!(
        parse(&file(vec![extra_field])),
        Err(IocError::Format(_))
    ));
    for bad in [&b"not json"[..], b"[]", b"{}", b""] {
        assert!(matches!(
            IndicatorFile::parse(bad),
            Err(IocError::Format(_))
        ));
    }
}

#[test]
fn a_file_holds_at_most_the_maximum() {
    let many = format!(
        r#"{{"schema":1,"source":{{"id":"x","name":"X","url":"https://x.example","licence":"CC0"}},"indicators":[{}]}}"#,
        vec![
            r#"{"kind":"x","value":"","family":"","threat":"","date":"","report":""}"#;
            MAX_INDICATORS + 1
        ]
        .join(",")
    );
    assert_eq!(
        IndicatorFile::parse(many.as_bytes()),
        Err(IocError::TooMany)
    );
}

#[test]
fn indicator_files_are_known_by_name() {
    for name in ["indicators-amnesty.json", "indicators-echap-2.json"] {
        assert!(is_indicator_file(name), "{name}");
    }
    for name in [
        "indicators-.json",
        "indicators-Amnesty.json",
        "indicators-a/b.json",
        "ip.db",
        "trackers.db",
        "indicators-amnesty.json.sig",
    ] {
        assert!(!is_indicator_file(name), "{name}");
    }
}

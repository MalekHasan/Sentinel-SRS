// SPDX-License-Identifier: GPL-3.0-or-later
//! The tracker list (DT-06): building it from the published lists, matching hostnames,
//! damaged files, and lookup speed at the size of the real lists.

#![allow(clippy::unwrap_used)]

use std::time::Instant;

use sentinel_enrich::upstream_trackers::{
    TrackerListError, read_ddg_app_trackers, read_tracker_radar_domain,
};
use sentinel_enrich::{
    Listed, TrackerBuildError, TrackerDb, TrackerDbBuilder, TrackerInfo, TrackerLoadError,
};

const RADAR: &str = "Tracker Radar test";
const APP_LIST: &str = "App tracker list test";

/// One Tracker Radar domain file, with the fields the reader ignores.
const RADAR_ADS: &str = r#"{
  "domain": "ads.example",
  "owner": {"name": "Example Ads LLC", "displayName": "Example Ads",
            "privacyPolicy": "https://ads.example/privacy", "url": "http://ads.example"},
  "source": ["DuckDuckGo"],
  "prevalence": 0.1,
  "sites": 1000,
  "subdomains": ["pixel", "eu"],
  "cnames": [],
  "fingerprinting": 2,
  "resources": [{"rule": "ads\\.example\\/p\\.js", "type": "Script"}],
  "categories": ["Advertising", "Analytics"],
  "performance": {"time": 1, "size": 2, "cpu": 3, "cache": 4},
  "cookies": 0.05,
  "nameservers": ["ns1.example"]
}"#;
/// A nearer domain below `ads.example`, owned by someone else.
const RADAR_EU: &str = r#"{"domain": "eu.ads.example",
  "owner": {"name": "Example EU Ltd"}, "categories": ["Audience Measurement"]}"#;
/// Owner unknown.
const RADAR_NO_OWNER: &str = r#"{"domain": "cdn.example", "owner": {}, "categories": ["CDN"]}"#;
/// Neither owner nor category: says nothing, so left out.
const RADAR_NOTHING_KNOWN: &str = r#"{"domain": "static.example", "owner": {}, "categories": []}"#;
/// As in the real list.
const RADAR_NOT_A_DOMAIN: &str =
    r#"{"domain": "%2a.ads.example", "owner": {"name": "Example Ads LLC"}, "categories": []}"#;
/// DuckDuckGo's app tracker list: owners, no categories.
const APP_TRACKERS: &str = r#"{
  "trackers": {
    "ads.example": {"owner": {"name": "Example Ads LLC", "displayName": "Example Ads (app)"},
                    "default": "block", "rules": []},
    "g.ads.example": {"owner": {"name": "Example Ads LLC", "displayName": "Example Ads (app)"},
                      "default": "block"},
    "metrics.example": {"owner": {"name": "Metrics Co", "displayName": "Metrics"},
                        "default": "block"},
    "nobody.example": {"default": "block"}
  },
  "entities": {"Example Ads LLC": {"domains": ["ads.example"], "displayName": "Example Ads"}},
  "domains": {"ads.example": "Example Ads LLC"},
  "cnames": {}
}"#;

fn sample_bytes() -> Vec<u8> {
    let mut builder = TrackerDbBuilder::new();
    let radar = builder.add_source(RADAR).unwrap();
    let apps = builder.add_source(APP_LIST).unwrap();
    for file in [RADAR_ADS, RADAR_EU, RADAR_NO_OWNER] {
        assert!(read_tracker_radar_domain(file, radar, &mut builder).unwrap());
    }
    for file in [RADAR_NOTHING_KNOWN, RADAR_NOT_A_DOMAIN] {
        assert!(!read_tracker_radar_domain(file, radar, &mut builder).unwrap());
    }
    assert_eq!(
        read_ddg_app_trackers(APP_TRACKERS, apps, &mut builder).unwrap(),
        3,
        "the domain without an owner says nothing"
    );
    builder.build().unwrap()
}

fn sample() -> TrackerDb {
    TrackerDb::from_bytes(&sample_bytes()).unwrap()
}

fn listed<'a, T>(value: T, domain: &'a str, sources: &[&'a str]) -> Listed<'a, T> {
    Listed {
        value,
        domain,
        sources: sources.to_vec(),
    }
}

#[test]
fn matches_a_listed_domain_and_every_name_below_it() {
    let db = sample();
    let ads = TrackerInfo {
        // Both lists name an owner; the first list's name is kept.
        company: Some(listed("Example Ads", "ads.example", &[RADAR, APP_LIST])),
        categories: Some(listed(
            vec!["Advertising", "Analytics"],
            "ads.example",
            &[RADAR],
        )),
    };
    assert_eq!(db.lookup("ads.example"), Some(ads.clone()));
    assert_eq!(db.lookup("pixel.ads.example"), Some(ads.clone()));
    assert_eq!(db.lookup("a.b.c.pixel.ads.example"), Some(ads.clone()));
    // Case and the final dot of a fully qualified name do not matter.
    assert_eq!(db.lookup("Pixel.ADS.Example."), Some(ads));
}

#[test]
fn the_nearest_listed_domain_wins() {
    let db = sample();
    assert_eq!(
        db.lookup("x.eu.ads.example"),
        Some(TrackerInfo {
            // The name is used when there is no display name.
            company: Some(listed("Example EU Ltd", "eu.ads.example", &[RADAR])),
            categories: Some(listed(
                vec!["Audience Measurement"],
                "eu.ads.example",
                &[RADAR]
            )),
        })
    );
    let next_door = db.lookup("eu2.ads.example").unwrap();
    assert_eq!(next_door.company.unwrap().domain, "ads.example");
}

/// As with `googleads.g.doubleclick.net` in the real lists: the app list names
/// `g.doubleclick.net` and its owner, and Tracker Radar gives `doubleclick.net` its
/// categories. Each answer keeps where it comes from.
#[test]
fn company_and_categories_come_from_the_nearest_domain_that_has_them() {
    let db = sample();
    assert_eq!(
        db.lookup("x.g.ads.example"),
        Some(TrackerInfo {
            company: Some(listed("Example Ads (app)", "g.ads.example", &[APP_LIST])),
            categories: Some(listed(
                vec!["Advertising", "Analytics"],
                "ads.example",
                &[RADAR]
            )),
        })
    );
    // Only in the app list, with nothing above it: a company and no categories.
    let metrics = db.lookup("sdk.metrics.example").unwrap();
    assert_eq!(
        metrics.company,
        Some(listed("Metrics", "metrics.example", &[APP_LIST]))
    );
    assert_eq!(metrics.categories, None);
    // Owner unknown.
    let cdn = db.lookup("cdn.example").unwrap();
    assert_eq!(cdn.company, None);
    assert_eq!(cdn.categories.unwrap().value, ["CDN"]);
}

#[test]
fn names_that_only_look_alike_do_not_match() {
    let db = sample();
    for host in [
        "static.example",
        "nobody.example",
        "notads.example",
        "ads.example.org",
        "ads-example",
        "example",
        "s.example",
        "",
        ".",
    ] {
        assert_eq!(db.lookup(host), None, "{host}");
    }
}

#[test]
fn keeps_the_lists_it_was_built_from() {
    let db = sample();
    assert_eq!(db.sources(), [RADAR, APP_LIST]);
    // ads, eu.ads, g.ads, cdn, metrics.
    assert_eq!(db.len(), 5);
}

#[test]
fn addresses_never_match_domains() {
    let mut builder = TrackerDbBuilder::new();
    let source = builder.add_source("test").unwrap();
    for domain in ["2.7", "1"] {
        assert!(
            builder
                .add_domain(source, domain, Some("Digits"), &[])
                .unwrap()
        );
    }
    let db = TrackerDb::from_bytes(&builder.build().unwrap()).unwrap();
    assert_eq!(db.lookup("x.2.7").unwrap().company.unwrap().value, "Digits");
    for address in ["192.0.2.7", "10.0.0.1", "::1", "2001:db8::1"] {
        assert_eq!(db.lookup(address), None, "{address}");
    }
}

#[test]
fn rejects_bad_input_while_building() {
    let mut builder = TrackerDbBuilder::new();
    let source = builder.add_source("test").unwrap();
    for domain in [
        "",
        ".",
        "a..example",
        ".example",
        "ex ample.com",
        "bücher.example",
        "a/b.example",
        &format!("{}.example", "a".repeat(64)),
        &format!("{}.example", ["a"; 127].join(".")),
    ] {
        assert!(
            matches!(
                builder.add_domain(source, domain, Some("Co"), &[]),
                Err(TrackerBuildError::BadDomain(_))
            ),
            "{domain:?}"
        );
    }
    // Upper case and a final dot are fine; nothing to say is left out.
    assert!(
        builder
            .add_domain(source, "Ads.Example.", Some("Co"), &[])
            .unwrap()
    );
    assert!(
        !builder
            .add_domain(source, "b.example", Some("  "), &[" ", ""])
            .unwrap()
    );

    let long = "x".repeat(1025);
    assert_eq!(
        builder.add_domain(source, "a.example", Some(&long), &[]),
        Err(TrackerBuildError::TextTooLong(long.clone()))
    );
    for text in ["Ads\nfake line", "Ads\u{202e}sdA"] {
        assert_eq!(
            builder.add_domain(source, "a.example", None, &[text]),
            Err(TrackerBuildError::ControlCharacter(text.to_owned()))
        );
    }
    assert_eq!(
        builder.add_source(&long),
        Err(TrackerBuildError::TextTooLong(long))
    );

    let mut categories = TrackerDbBuilder::new();
    let source = categories.add_source("test").unwrap();
    let names: Vec<String> = (0..64).map(|n| format!("category {n}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    categories
        .add_domain(source, "a.example", None, &names)
        .unwrap();
    assert_eq!(
        categories.add_domain(source, "b.example", None, &["one too many"]),
        Err(TrackerBuildError::TooManyCategories)
    );
    // All 64 survive the file.
    let db = TrackerDb::from_bytes(&categories.build().unwrap()).unwrap();
    assert_eq!(
        db.lookup("a.example").unwrap().categories.unwrap().value,
        names
    );

    let mut sources = TrackerDbBuilder::new();
    for n in 0..8 {
        sources.add_source(&format!("list {n}")).unwrap();
    }
    assert_eq!(
        sources.add_source("list 8"),
        Err(TrackerBuildError::TooManySources)
    );
}

#[test]
fn the_list_readers_refuse_what_they_cannot_read() {
    let mut builder = TrackerDbBuilder::new();
    let source = builder.add_source("test").unwrap();
    for json in [
        "",
        "[]",
        "{}",
        r#"{"domain": 7}"#,
        r#"{"domain": "a.example", "categories": "Ads"}"#,
    ] {
        assert!(
            matches!(
                read_tracker_radar_domain(json, source, &mut builder),
                Err(TrackerListError::Json(_))
            ),
            "{json}"
        );
    }
    let long = format!(
        r#"{{"domain": "a.example", "owner": {{"name": "{}"}}}}"#,
        "x".repeat(1025)
    );
    assert!(matches!(
        read_tracker_radar_domain(&long, source, &mut builder),
        Err(TrackerListError::Build(TrackerBuildError::TextTooLong(_)))
    ));
    assert!(matches!(
        read_ddg_app_trackers(r#"{"entities": {}}"#, source, &mut builder),
        Err(TrackerListError::Json(_))
    ));
    assert!(matches!(
        read_ddg_app_trackers(
            r#"{"trackers": {"a b": {"owner": {"name": "Co"}}}}"#,
            source,
            &mut builder
        ),
        Err(TrackerListError::Build(TrackerBuildError::BadDomain(_)))
    ));
}

/// One domain of a hand-written file: name, company, categories, company sources,
/// category sources.
type Row<'a> = (&'a str, u32, u64, u8, u8);

/// A file written by hand, following the layout in the module's documentation, with one
/// source and one category.
fn file(companies: &[&str], domains: &[Row<'_>]) -> Vec<u8> {
    let mut out = b"SNTLTRKR".to_vec();
    out.extend_from_slice(&1u32.to_le_bytes());
    let text = |out: &mut Vec<u8>, text: &str| {
        out.extend_from_slice(&(text.len() as u32).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
    };
    for list in [&["list"][..], companies, &["Ads"][..]] {
        out.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for name in list {
            text(&mut out, name);
        }
    }
    out.extend_from_slice(&(domains.len() as u32).to_le_bytes());
    for (domain, company, categories, company_sources, category_sources) in domains {
        text(&mut out, domain);
        out.extend_from_slice(&company.to_le_bytes());
        out.extend_from_slice(&categories.to_le_bytes());
        out.push(*company_sources);
        out.push(*category_sources);
    }
    out
}

#[test]
fn rejects_files_that_are_not_whole_and_valid() {
    let good = sample_bytes();
    assert_eq!(
        TrackerDb::from_bytes(b"not a tracker list").unwrap_err(),
        TrackerLoadError::NotATrackerList
    );
    for len in 0..good.len() {
        assert!(
            TrackerDb::from_bytes(&good[..len]).is_err(),
            "cut at {len} of {}",
            good.len()
        );
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(
        TrackerDb::from_bytes(&longer).unwrap_err(),
        TrackerLoadError::TrailingBytes
    );
    let mut newer = good.clone();
    newer[8] = 2;
    assert_eq!(
        TrackerDb::from_bytes(&newer).unwrap_err(),
        TrackerLoadError::UnsupportedVersion(2)
    );
    let mut huge = good;
    huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        TrackerDb::from_bytes(&huge).unwrap_err(),
        TrackerLoadError::TooLarge
    );

    // The hand-written file loads, so each change below is what makes it fail.
    const NONE: u32 = u32::MAX;
    let valid = file(
        &["Co"],
        &[
            ("a.example", 0, 1, 1, 1),
            ("b.example", NONE, 1, 0, 1),
            ("c.example", 0, 0, 1, 0),
        ],
    );
    assert_eq!(TrackerDb::from_bytes(&valid).unwrap().len(), 3);
    for (what, domains, error) in [
        (
            "out of order",
            [("b.example", 0, 1, 1, 1), ("a.example", 0, 1, 1, 1)],
            TrackerLoadError::NotSorted,
        ),
        (
            "twice",
            [("a.example", 0, 1, 1, 1), ("a.example", 0, 1, 1, 1)],
            TrackerLoadError::NotSorted,
        ),
        (
            "upper case",
            [("A.example", 0, 1, 1, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadDomain,
        ),
        (
            "unknown company",
            [("a.example", 1, 1, 1, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "unknown category",
            [("a.example", 0, 2, 1, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "unknown source",
            [("a.example", 0, 1, 2, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "a company without a source",
            [("a.example", 0, 1, 0, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "a source without a company",
            [("a.example", NONE, 1, 1, 1), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "categories without a source",
            [("a.example", 0, 1, 1, 0), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
        (
            "nothing to say",
            [("a.example", NONE, 0, 0, 0), ("b.example", 0, 1, 1, 1)],
            TrackerLoadError::BadReference,
        ),
    ] {
        assert_eq!(
            TrackerDb::from_bytes(&file(&["Co"], &domains)).unwrap_err(),
            error,
            "{what}"
        );
    }
    assert_eq!(
        TrackerDb::from_bytes(&file(&["Co\u{202e}"], &[("a.example", 0, 1, 1, 1)])).unwrap_err(),
        TrackerLoadError::BadText,
        "a text direction mark"
    );
}

#[test]
fn damaged_files_never_panic() {
    let good = sample_bytes();
    let probes = [
        "ads.example",
        "x.eu.ads.example",
        "x.g.ads.example",
        "metrics.example",
        "none.example",
    ];
    for at in 0..good.len() {
        for flip in [0x01, 0x80, 0xff] {
            let mut damaged = good.clone();
            damaged[at] ^= flip;
            // Either refused, or a list whose lookups still work.
            if let Ok(db) = TrackerDb::from_bytes(&damaged) {
                for probe in probes {
                    db.lookup(probe);
                }
            }
        }
    }
}

/// DT-01: under 1 ms per flow. Tracker Radar's US region and the app list come to about
/// 9,300 domains; this uses thirty times that, with names several labels deep, half of
/// them not listed (the slowest case: every domain above them is searched).
#[test]
fn lookups_take_well_under_a_millisecond_at_full_size() {
    const DOMAINS: u32 = 300_000;
    let mut builder = TrackerDbBuilder::new();
    let source = builder.add_source("synthetic").unwrap();
    for n in 0..DOMAINS {
        builder
            .add_domain(
                source,
                &format!("tracker{n}.example{}.com", n % 1_000),
                Some(&format!("Company {}", n % 20_000)),
                &[["Advertising", "Analytics", "CDN"][(n % 3) as usize]],
            )
            .unwrap();
    }
    let bytes = builder.build().unwrap();
    let loading = Instant::now();
    let db = TrackerDb::from_bytes(&bytes).unwrap();
    let load_time = loading.elapsed();

    const LOOKUPS: u32 = 100_000;
    let mut found = 0;
    let started = Instant::now();
    for i in 0..LOOKUPS {
        let n = i.wrapping_mul(2_654_435_761) % (2 * DOMAINS);
        let host = format!("a.b.tracker{n}.example{}.com", n % 1_000);
        found += usize::from(db.lookup(&host).is_some());
    }
    let per_lookup = started.elapsed() / LOOKUPS;
    println!(
        "{} bytes, loaded in {load_time:?}; {per_lookup:?} per lookup ({found} of {LOOKUPS} found)",
        bytes.len()
    );
    assert!(found > 0 && found < LOOKUPS as usize);
    assert!(
        per_lookup.as_micros() < 1_000,
        "a lookup took {per_lookup:?}, the budget per flow is 1 ms"
    );
}

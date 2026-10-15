// SPDX-License-Identifier: GPL-3.0-or-later
//! The store against a real SQLCipher database in a temporary directory.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use sentinel_store::{
    AppSummary, AwayTotal, CompanyTotal, DailyTotal, DestinationFacts, DestinationTotal, FlowEvent,
    FlowRow, Gap, HostnameSource, Listed, Proto, Store, StoreError, wipe,
};

const KEY: [u8; 32] = [7; 32];
const DAY: i64 = 24 * 60 * 60 * 1000;
/// 2026-10-14 12:00 UTC, in Unix milliseconds.
const NOW: i64 = 1_791_979_200_000;

fn db(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("history.db")
}

fn flow(app: &str, host: &str, started: i64) -> FlowRow {
    FlowRow {
        app: Some(app.to_owned()),
        proto: Proto::Tcp,
        local_ip: "10.215.173.1".to_owned(),
        local_port: 40_000,
        remote_ip: "93.184.215.14".to_owned(),
        remote_port: 443,
        hostname: Some(host.to_owned()),
        hostname_src: Some(HostnameSource::Dns),
        started,
        ended: None,
        bytes_up: 0,
        bytes_down: 0,
        bytes_up_away: 0,
        bytes_down_away: 0,
        blocked: false,
    }
}

fn event(engine_id: u64, flow: FlowRow) -> FlowEvent {
    FlowEvent {
        engine_id,
        flow,
        destination: None,
    }
}

/// True if `needle` appears in the database file or its write-ahead log.
fn file_contains(path: &Path, needle: &[u8]) -> bool {
    let mut bytes = std::fs::read(path).unwrap();
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    if let Ok(more) = std::fs::read(&wal) {
        bytes.extend(more);
    }
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn history_is_encrypted_on_disk_and_needs_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    {
        let store = Store::open(&path, &KEY).unwrap();
        store
            .record_flows(
                1,
                &[event(
                    1,
                    flow("org.example.tracker", "secret-host.example", NOW),
                )],
            )
            .unwrap();
    }
    assert!(!file_contains(&path, b"secret-host.example"));
    assert!(!file_contains(&path, b"org.example.tracker"));
    assert!(!file_contains(&path, b"SQLite format 3"));

    assert!(matches!(
        Store::open(&path, &[8; 32]),
        Err(StoreError::WrongKey)
    ));
    let store = Store::open(&path, &KEY).unwrap();
    let flows = store.recent_flows(10).unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].flow.hostname.as_deref(),
        Some("secret-host.example")
    );
}

#[test]
fn a_flow_start_and_end_become_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();

    let started = flow("org.example.app", "api.example", NOW);
    store.record_flows(1, &[event(5, started.clone())]).unwrap();
    // The same engine id in another session is another flow.
    store
        .record_flows(
            2,
            &[event(5, flow("org.example.app", "cdn.example", NOW + 1))],
        )
        .unwrap();

    let mut ended = started.clone();
    ended.ended = Some(NOW + 2_000);
    ended.bytes_up = 1_200;
    ended.bytes_down = 64_000;
    ended.hostname = Some("www.example".to_owned());
    ended.hostname_src = Some(HostnameSource::Sni);
    store.record_flows(1, &[event(5, ended.clone())]).unwrap();

    let flows = store.recent_flows(10).unwrap();
    assert_eq!(flows.len(), 2);
    let api = flows.iter().find(|f| f.flow.started == NOW).unwrap();
    assert_eq!(api.flow, ended);
    let cdn = flows.iter().find(|f| f.flow.started == NOW + 1).unwrap();
    assert_eq!(
        cdn.flow.ended, None,
        "the other session's flow is still open"
    );
    assert_eq!(flows[0].flow.started, NOW + 1, "newest first");
}

#[test]
fn an_end_without_a_seen_start_is_stored_whole() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let mut row = flow("org.example.app", "api.example", NOW);
    row.ended = Some(NOW + 10);
    row.blocked = true;
    row.app = None;
    store.record_flows(1, &[event(9, row.clone())]).unwrap();
    let flows = store.recent_flows(10).unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].flow, row);
}

#[test]
fn old_flows_are_rolled_up_into_daily_totals() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let old_day = NOW - 40 * DAY;
    let mut events = Vec::new();
    for (i, (app, host, at, up, down)) in [
        ("org.example.a", "x.example", old_day, 10, 100),
        ("org.example.a", "x.example", old_day + 60_000, 5, 50),
        ("org.example.b", "y.example", old_day, 1, 1),
        ("org.example.a", "x.example", NOW - DAY, 7, 7), // within 30 days: kept
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = flow(app, host, at);
        row.ended = Some(at + 1_000);
        row.bytes_up = up;
        row.bytes_down = down;
        events.push(event(i as u64, row));
    }
    store.record_flows(1, &events).unwrap();

    assert_eq!(store.apply_retention(NOW, 30).unwrap(), 3);
    assert_eq!(
        store.apply_retention(NOW, 30).unwrap(),
        0,
        "nothing left to roll up"
    );
    assert_eq!(store.recent_flows(10).unwrap().len(), 1);

    let mut totals = store.daily_totals(10).unwrap();
    totals.sort_by(|a, b| a.destination.cmp(&b.destination));
    let day = old_day / DAY;
    assert_eq!(
        totals,
        vec![
            DailyTotal {
                day,
                app: Some("org.example.a".to_owned()),
                destination: "x.example".to_owned(),
                proto: Proto::Tcp,
                flows: 2,
                bytes_up: 15,
                bytes_down: 150,
                bytes_up_away: 0,
                bytes_down_away: 0,
            },
            DailyTotal {
                day,
                app: Some("org.example.b".to_owned()),
                destination: "y.example".to_owned(),
                proto: Proto::Tcp,
                flows: 1,
                bytes_up: 1,
                bytes_down: 1,
                bytes_up_away: 0,
                bytes_down_away: 0,
            },
        ]
    );

    // A later flow on the same old day (for example from a clock change) adds to the
    // existing total instead of replacing it.
    let mut late = flow("org.example.a", "x.example", old_day + 120_000);
    late.ended = Some(old_day + 121_000);
    late.bytes_up = 100;
    store.record_flows(2, &[event(1, late)]).unwrap();
    store.apply_retention(NOW, 30).unwrap();
    let x = store
        .daily_totals(10)
        .unwrap()
        .into_iter()
        .find(|t| t.destination == "x.example")
        .unwrap();
    assert_eq!((x.flows, x.bytes_up), (3, 115));
}

#[test]
fn app_summary_totals_each_destination_across_flows_and_daily_totals() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let app = "org.example.a";
    let old_day = NOW - 40 * DAY;
    let mut events = Vec::new();
    for (i, (owner, host, at, up, down)) in [
        (app, "x.example", old_day, 10, 100), // rolled up below
        (app, "x.example", NOW - DAY, 5, 50), // same destination, still detailed
        (app, "y.example", NOW - 2 * DAY, 1_000, 1),
        ("org.example.b", "y.example", NOW, 9, 9), // another app
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = flow(owner, host, at);
        row.ended = Some(at + 1_000);
        row.bytes_up = up;
        row.bytes_down = down;
        events.push(event(i as u64, row));
    }
    // Still open, with no name: listed by address, with what was stored at its start.
    let mut open = flow(app, "z.example", NOW);
    open.hostname = None;
    open.hostname_src = None;
    events.push(event(9, open));
    store.record_flows(1, &events).unwrap();
    store.apply_retention(NOW, 30).unwrap();

    let summary = store.app_summary(app, 10).unwrap().unwrap();
    assert_eq!(
        summary,
        AppSummary {
            app: app.to_owned(),
            first_seen: old_day,
            flows: 4,
            bytes_up: 1_015,
            bytes_down: 151,
            bytes_up_away: 0,
            bytes_down_away: 0,
            destination_count: 3,
            destinations: vec![
                DestinationTotal {
                    destination: "y.example".to_owned(),
                    flows: 1,
                    bytes_up: 1_000,
                    bytes_down: 1,
                    bytes_up_away: 0,
                    bytes_down_away: 0,
                    name_source: Some(HostnameSource::Dns),
                    facts: DestinationFacts::default(),
                    first_seen: NOW - 2 * DAY,
                    last_seen: NOW - 2 * DAY + 1_000,
                },
                DestinationTotal {
                    destination: "x.example".to_owned(),
                    flows: 2,
                    bytes_up: 15,
                    bytes_down: 150,
                    bytes_up_away: 0,
                    bytes_down_away: 0,
                    name_source: Some(HostnameSource::Dns),
                    facts: DestinationFacts::default(),
                    // The rolled-up flow keeps only its day.
                    first_seen: old_day / DAY * DAY,
                    last_seen: NOW - DAY + 1_000,
                },
                DestinationTotal {
                    destination: "93.184.215.14".to_owned(),
                    flows: 1,
                    bytes_up: 0,
                    bytes_down: 0,
                    bytes_up_away: 0,
                    bytes_down_away: 0,
                    name_source: None,
                    facts: DestinationFacts::default(),
                    first_seen: NOW,
                    last_seen: NOW,
                },
            ],
            companies: vec![],
        }
    );

    let top = store.app_summary(app, 1).unwrap().unwrap();
    assert_eq!(
        top.destination_count, 3,
        "the count covers every destination"
    );
    assert_eq!(top.destinations.len(), 1);
    assert_eq!(top.bytes_up, 1_015, "the totals too");
    assert_eq!(store.app_summary("org.example.never", 10).unwrap(), None);
}

#[test]
fn traffic_while_away_is_totalled_per_app_and_survives_roll_up() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let mut events = Vec::new();
    for (i, (app, at, up, down, up_away, down_away)) in [
        ("org.example.a", NOW - 40 * DAY, 100, 100, 10, 20), // rolled up below
        ("org.example.a", NOW - 2 * DAY, 100, 100, 30, 0),   // before `since`
        ("org.example.a", NOW - 60_000, 500, 50, 400, 40),
        ("org.example.a", NOW - 50_000, 9, 9, 0, 0), // nothing while away
        ("org.example.b", NOW - 40_000, 900, 9, 5, 5),
        ("org.example.c", NOW - 30_000, 7, 7, 7, 7),
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = flow(app, "x.example", at);
        row.ended = Some(at + 1_000);
        (row.bytes_up, row.bytes_down) = (up, down);
        (row.bytes_up_away, row.bytes_down_away) = (up_away, down_away);
        events.push(event(i as u64, row));
    }
    // Still open: its start was stored with nothing while away; its end adds some.
    let mut open = flow("org.example.c", "y.example", NOW - 20_000);
    store.record_flows(1, &[event(99, open.clone())]).unwrap();
    open.ended = Some(NOW);
    open.bytes_up_away = 3;
    events.push(event(99, open));
    store.record_flows(1, &events).unwrap();
    store.apply_retention(NOW, 30).unwrap();

    // The last day: most data sent while away first; flows that carried none do not
    // count.
    let since = NOW - DAY;
    assert_eq!(
        store.away_totals(since, 10).unwrap(),
        vec![
            AwayTotal {
                app: Some("org.example.a".to_owned()),
                flows: 1,
                bytes_up_away: 400,
                bytes_down_away: 40,
            },
            AwayTotal {
                app: Some("org.example.c".to_owned()),
                flows: 2,
                bytes_up_away: 10,
                bytes_down_away: 7,
            },
            AwayTotal {
                app: Some("org.example.b".to_owned()),
                flows: 1,
                bytes_up_away: 5,
                bytes_down_away: 5,
            },
        ]
    );
    assert_eq!(store.away_totals(since, 1).unwrap().len(), 1);

    // The app's whole history, rolled-up days included.
    let a = store.app_summary("org.example.a", 10).unwrap().unwrap();
    assert_eq!((a.bytes_up_away, a.bytes_down_away), (440, 60));
    let old = store.daily_totals(10).unwrap();
    assert_eq!(
        old.iter()
            .map(|d| (d.bytes_up_away, d.bytes_down_away))
            .collect::<Vec<_>>(),
        vec![(10, 20)]
    );
}

#[test]
fn destination_facts_are_kept_per_destination_with_their_sources() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let facts = |asn: u32, country: &str, date: &str| DestinationFacts {
        asn: Some(asn),
        network_owner: Some(format!("NET-{asn}")),
        network_source: Some(format!("IPtoASN {date}")),
        country: Some(country.to_owned()),
        country_source: Some(format!("DB-IP Lite {date}")),
        ..DestinationFacts::default()
    };
    let app = "org.example.a";
    let with = |id: u64, row: FlowRow, facts: Option<DestinationFacts>| FlowEvent {
        engine_id: id,
        flow: row,
        destination: facts,
    };
    let mut by_sni = flow(app, "cdn.example", NOW - 60_000);
    by_sni.hostname_src = Some(HostnameSource::Sni);
    let mut bare = flow(app, "unused", NOW - 50_000);
    bare.hostname = None;
    bare.hostname_src = None;
    bare.remote_ip = "192.0.2.7".to_owned();
    store
        .record_flows(
            1,
            &[
                with(
                    1,
                    flow(app, "cdn.example", NOW - 120_000),
                    Some(facts(64_500, "DE", "old")),
                ),
                with(2, by_sni, Some(facts(64_501, "JO", "new"))),
                with(3, bare, Some(facts(64_502, "US", "new"))),
                // A late report of an older flow does not replace newer facts.
                with(
                    4,
                    flow(app, "cdn.example", NOW - 180_000),
                    Some(facts(64_999, "FR", "older")),
                ),
                // Nothing known: nothing recorded.
                with(
                    5,
                    flow(app, "plain.example", NOW),
                    Some(DestinationFacts::default()),
                ),
            ],
        )
        .unwrap();

    let summary = store.app_summary(app, 10).unwrap().unwrap();
    let get = |name: &str| {
        summary
            .destinations
            .iter()
            .find(|d| d.destination == name)
            .unwrap()
            .clone()
    };
    let cdn = get("cdn.example");
    assert_eq!(
        cdn.facts,
        facts(64_501, "JO", "new"),
        "the latest facts win"
    );
    assert_eq!(
        cdn.name_source,
        Some(HostnameSource::Sni),
        "the TLS name outranks DNS"
    );
    let bare = get("192.0.2.7");
    assert_eq!(bare.facts.asn, Some(64_502));
    assert_eq!(bare.name_source, None, "an address has no name source");
    let plain = get("plain.example");
    assert_eq!(plain.facts, DestinationFacts::default());
    assert_eq!(plain.name_source, Some(HostnameSource::Dns));
}

/// DT-06: each destination keeps its company and categories with where they come from,
/// and the app summary adds up the companies.
#[test]
fn companies_and_categories_are_kept_with_their_sources() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    const RADAR: &str = "Tracker Radar 2026-10-09";
    const APPS: &str = "App tracker list 2023-07-06";
    let listed = |value: &str, domain: &str, sources: &[&str]| Listed {
        value: value.to_owned(),
        domain: domain.to_owned(),
        sources: sources.iter().map(|s| (*s).to_owned()).collect(),
    };
    let kinds = |value: &[&str], domain: &str| Listed {
        value: value.iter().map(|s| (*s).to_owned()).collect(),
        domain: domain.to_owned(),
        sources: vec![RADAR.to_owned()],
    };
    let ads_pixel = DestinationFacts {
        company: Some(listed("Example Ads", "ads.example", &[RADAR, APPS])),
        categories: Some(kinds(&["Advertising", "Analytics"], "ads.example")),
        ..DestinationFacts::default()
    };
    let ads_g = DestinationFacts {
        company: Some(listed("Example Ads", "g.ads.example", &[APPS])),
        categories: Some(kinds(
            &["Advertising", "Audience Measurement"],
            "ads.example",
        )),
        ..DestinationFacts::default()
    };
    let cdn = DestinationFacts {
        categories: Some(kinds(&["CDN"], "cdn.example")),
        ..DestinationFacts::default()
    };
    let metrics = DestinationFacts {
        company: Some(listed("Metrics", "metrics.example", &[APPS])),
        ..DestinationFacts::default()
    };
    let app = "org.example.a";
    let sent = |id: u64, app: &str, host: &str, up: i64, facts: Option<DestinationFacts>| {
        let mut row = flow(app, host, NOW - 60_000 + id as i64);
        row.bytes_up = up;
        row.bytes_down = 1;
        FlowEvent {
            engine_id: id,
            flow: row,
            destination: facts,
        }
    };
    store
        .record_flows(
            1,
            &[
                sent(1, app, "pixel.ads.example", 100, Some(ads_pixel.clone())),
                sent(2, app, "x.g.ads.example", 50, Some(ads_g.clone())),
                sent(3, app, "cdn.example", 500, Some(cdn.clone())),
                sent(4, app, "metrics.example", 200, Some(metrics.clone())),
                sent(5, app, "plain.example", 900, None),
                // Another app's companies are its own.
                sent(
                    6,
                    "org.example.b",
                    "other.example",
                    5,
                    Some(metrics.clone()),
                ),
            ],
        )
        .unwrap();

    let summary = store.app_summary(app, 2).unwrap().unwrap();
    let all = store.app_summary(app, 10).unwrap().unwrap();
    for (host, facts) in [
        ("pixel.ads.example", &ads_pixel),
        ("x.g.ads.example", &ads_g),
        ("cdn.example", &cdn),
        ("metrics.example", &metrics),
    ] {
        let found = all
            .destinations
            .iter()
            .find(|d| d.destination == host)
            .unwrap();
        assert_eq!(&found.facts, facts, "{host}");
    }
    assert_eq!(
        summary.companies,
        vec![
            CompanyTotal {
                company: "Metrics".to_owned(),
                categories: vec![],
                destinations: 1,
                bytes_up: 200,
                bytes_down: 1,
            },
            CompanyTotal {
                company: "Example Ads".to_owned(),
                categories: vec![
                    "Advertising".to_owned(),
                    "Analytics".to_owned(),
                    "Audience Measurement".to_owned(),
                ],
                destinations: 2,
                bytes_up: 150,
                bytes_down: 2,
            },
        ],
        "every destination counts, not only the two listed"
    );
}

#[test]
fn one_gap_is_open_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    store.open_gap(Some(NOW), "engine stopped").unwrap();
    store.open_gap(Some(NOW + 1), "revoked").unwrap();
    store.close_gap(NOW + 5_000).unwrap();
    store.close_gap(NOW + 9_000).unwrap();
    store.open_gap(None, "closed without warning").unwrap();
    assert_eq!(
        store.recent_gaps(10).unwrap(),
        vec![
            Gap {
                started: None,
                ended: None,
                reason: "closed without warning".to_owned()
            },
            Gap {
                started: Some(NOW),
                ended: Some(NOW + 5_000),
                reason: "engine stopped".to_owned()
            },
        ]
    );
}

#[test]
fn wipe_deletes_the_database_and_its_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    store
        .record_flows(1, &[event(1, flow("org.example.app", "a.example", NOW))])
        .unwrap();
    drop(store);
    wipe(&path).unwrap();
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(left.is_empty(), "files left after wipe: {left:?}");
    wipe(&path).unwrap(); // nothing to delete is fine

    // A new store starts empty.
    let store = Store::open(&path, &KEY).unwrap();
    assert!(store.recent_flows(10).unwrap().is_empty());
}

#[test]
fn reopening_keeps_the_schema_and_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    Store::open(&path, &KEY)
        .unwrap()
        .open_gap(Some(NOW), "test")
        .unwrap();
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.recent_gaps(10).unwrap().len(), 1);
}

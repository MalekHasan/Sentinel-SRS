// SPDX-License-Identifier: GPL-3.0-or-later
//! The store against a real SQLCipher database in a temporary directory.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use sentinel_detect::AlertState;
use sentinel_store::{
    AppSummary, AwayTotal, CompanyTotal, DailyTotal, DestinationFacts, DestinationTotal, FirstSeen,
    FlowEvent, FlowRow, Gap, HostnameSource, Listed, Proto, Store, StoreError, StoredAlert, wipe,
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

/// Connections from `app` to `name` and `address`: first, last and how many.
fn destination(
    app: Option<&str>,
    name: Option<&str>,
    address: Option<&str>,
    (first, last, connections): (i64, i64, u64),
) -> sentinel_store::PastDestination {
    sentinel_store::PastDestination {
        app: app.map(str::to_owned),
        name: name.map(str::to_owned),
        address: address.map(str::to_owned),
        first,
        last,
        connections,
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

/// AL-01, AL-02: alerts keep their rule, severity and evidence, newest first, and can be
/// put away.
#[test]
fn alerts_are_kept_with_their_evidence_and_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    assert!(store.alerts(false, 10).unwrap().is_empty());

    let older = sentinel_detect::monitoring_interrupted(NOW - 60_000, None, "killed");
    let mut newer = sentinel_detect::monitoring_interrupted(NOW, Some(NOW - 5_000), "revoked");
    newer.severity = sentinel_detect::Severity::High;
    newer.evidence.push(sentinel_detect::Evidence::App {
        package: "org.example.vpn".to_owned(),
    });
    let older_id = store.record_alert(&older).unwrap();
    let newer_id = store.record_alert(&newer).unwrap();

    let open = store.alerts(true, 10).unwrap();
    assert_eq!(
        open,
        vec![
            StoredAlert {
                id: newer_id,
                alert: newer.clone(),
                state: AlertState::Open,
                notified: None,
                feedback: None,
            },
            StoredAlert {
                id: older_id,
                alert: older.clone(),
                state: AlertState::Open,
                notified: None,
                feedback: None,
            },
        ]
    );
    assert_eq!(store.alerts(true, 1).unwrap().len(), 1, "the limit holds");

    assert!(
        store
            .set_alert_state(newer_id, AlertState::Dismissed)
            .unwrap()
    );
    assert!(!store.set_alert_state(9_999, AlertState::Dismissed).unwrap());
    let open = store.alerts(true, 10).unwrap();
    assert_eq!(open.iter().map(|a| a.id).collect::<Vec<_>>(), [older_id]);
    let all = store.alerts(false, 10).unwrap();
    assert_eq!(all.len(), 2, "dismissed alerts stay in the history");
    assert_eq!(
        store.alert(newer_id).unwrap().unwrap().state,
        AlertState::Dismissed
    );
    assert_eq!(store.alert(9_999).unwrap(), None);

    // They survive closing and reopening, encrypted like the rest.
    drop(store);
    let store = Store::open(&db(&dir), &KEY).unwrap();
    assert_eq!(store.alert(older_id).unwrap().unwrap().alert, older);
}

/// AL-03, AL-04: claiming a notification applies the delivery rules to what was
/// already notified, and records it in the same step.
#[test]
fn notifications_are_claimed_once_and_rate_limited() {
    use sentinel_detect::{Delivery, Evidence, Severity};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let about = |app: &str, severity: Severity| {
        let mut alert = sentinel_detect::monitoring_interrupted(NOW, None, "r");
        alert.severity = severity;
        alert.evidence.push(Evidence::App {
            package: app.to_owned(),
        });
        store.record_alert(&alert).unwrap()
    };
    assert_eq!(store.claim_notification(9_999, NOW, false).unwrap(), None);

    // Do Not Disturb keeps a Warning in the app, and records nothing.
    let held = about("org.example.chat", Severity::Warning);
    assert_eq!(
        store.claim_notification(held, NOW, true).unwrap(),
        Some(Delivery::HoldForDoNotDisturb)
    );
    assert_eq!(store.alert(held).unwrap().unwrap().notified, None);

    // Three notifications for the app within the hour, then the fourth is held.
    let ids: Vec<i64> = (0..4)
        .map(|_| about("org.example.chat", Severity::Warning))
        .collect();
    for (i, id) in ids.iter().enumerate() {
        let expected = if i < 3 {
            Delivery::Notify
        } else {
            Delivery::HoldForRateLimit
        };
        let at = NOW + i as i64;
        assert_eq!(
            store.claim_notification(*id, at, false).unwrap(),
            Some(expected)
        );
    }
    assert_eq!(store.alert(ids[0]).unwrap().unwrap().notified, Some(NOW));
    assert_eq!(store.alert(ids[3]).unwrap().unwrap().notified, None);
    // Claiming again changes nothing, and does not count twice.
    assert_eq!(
        store.claim_notification(ids[0], NOW + 10, false).unwrap(),
        Some(Delivery::Notify)
    );
    assert_eq!(store.alert(ids[0]).unwrap().unwrap().notified, Some(NOW));
    // Another app has its own allowance; Critical is never held.
    let other = about("org.example.mail", Severity::Warning);
    assert_eq!(
        store.claim_notification(other, NOW, false).unwrap(),
        Some(Delivery::Notify)
    );
    let critical = about("org.example.chat", Severity::Critical);
    assert_eq!(
        store.claim_notification(critical, NOW, true).unwrap(),
        Some(Delivery::Notify)
    );
    // An hour after the first three, the held one can be notified.
    let later = NOW + sentinel_detect::RATE_WINDOW_MS + 3;
    assert_eq!(
        store.claim_notification(ids[3], later, false).unwrap(),
        Some(Delivery::Notify)
    );
}

/// AL-05: feedback stays in the history, dismisses the alert, and changes only how this
/// user is alerted: "not useful" holds later alerts like it, "allowed" adds to the
/// allow-list. Both can be taken back; a Critical alert cannot be allowed.
#[test]
fn feedback_is_kept_and_tunes_only_later_alerts_like_it() {
    use sentinel_detect::{Delivery, Evidence, Feedback, Rule, Severity};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let raise = |app: Option<&str>, severity: Severity| {
        let mut alert = sentinel_detect::monitoring_interrupted(NOW, None, "r");
        alert.severity = severity;
        if let Some(app) = app {
            alert.evidence.push(Evidence::App {
                package: app.to_owned(),
            });
        }
        store.record_alert(&alert).unwrap()
    };
    let chat = Some("org.example.chat");
    assert!(
        !store
            .set_feedback(9_999, Some(Feedback::NotUseful), NOW)
            .unwrap()
    );

    // Not useful: dismissed, kept, and later alerts like it wait in the app.
    let first = raise(chat, Severity::Warning);
    assert!(
        store
            .set_feedback(first, Some(Feedback::NotUseful), NOW)
            .unwrap()
    );
    let stored = store.alert(first).unwrap().unwrap();
    assert_eq!(stored.feedback, Some(Feedback::NotUseful));
    assert_eq!(stored.state, AlertState::Dismissed);
    let like_it = raise(chat, Severity::High);
    assert_eq!(
        store.claim_notification(like_it, NOW, false).unwrap(),
        Some(Delivery::HoldForFeedback)
    );
    let other_app = raise(Some("org.example.mail"), Severity::Warning);
    assert_eq!(
        store.claim_notification(other_app, NOW, false).unwrap(),
        Some(Delivery::Notify),
        "only the same app"
    );
    let critical = raise(chat, Severity::Critical);
    assert_eq!(
        store.claim_notification(critical, NOW, false).unwrap(),
        Some(Delivery::Notify),
        "Critical always notifies"
    );
    // Taken back: alerts like it notify again.
    store.set_feedback(first, None, NOW).unwrap();
    assert_eq!(store.alert(first).unwrap().unwrap().feedback, None);
    let after_undo = raise(chat, Severity::Warning);
    assert_eq!(
        store.claim_notification(after_undo, NOW, false).unwrap(),
        Some(Delivery::Notify)
    );

    // Allowed: on the allow-list, for this rule and app only.
    assert!(!store.is_allowed(Rule::MonitoringInterrupted, chat).unwrap());
    let allow = raise(chat, Severity::Warning);
    store
        .set_feedback(allow, Some(Feedback::Allowed), NOW + 1)
        .unwrap();
    assert!(store.is_allowed(Rule::MonitoringInterrupted, chat).unwrap());
    assert!(!store.is_allowed(Rule::MonitoringInterrupted, None).unwrap());
    let own = raise(None, Severity::Warning);
    store
        .set_feedback(own, Some(Feedback::Allowed), NOW + 2)
        .unwrap();
    assert_eq!(
        store.allowed().unwrap(),
        vec![
            sentinel_store::AllowedEntry {
                rule: Rule::MonitoringInterrupted,
                app: None,
                created: NOW + 2,
            },
            sentinel_store::AllowedEntry {
                rule: Rule::MonitoringInterrupted,
                app: chat.map(str::to_owned),
                created: NOW + 1,
            },
        ]
    );
    // Changing the feedback from allowed takes the app off the list.
    store
        .set_feedback(allow, Some(Feedback::NotUseful), NOW)
        .unwrap();
    assert!(!store.is_allowed(Rule::MonitoringInterrupted, chat).unwrap());
    assert!(store.is_allowed(Rule::MonitoringInterrupted, None).unwrap());

    // A Critical alert cannot be allowed; it can be marked not useful.
    assert!(matches!(
        store.set_feedback(critical, Some(Feedback::Allowed), NOW),
        Err(StoreError::FeedbackNotAllowed(id)) if id == critical
    ));
    assert!(
        store
            .set_feedback(critical, Some(Feedback::NotUseful), NOW)
            .unwrap()
    );

    // It all stays in the encrypted history.
    drop(store);
    let store = Store::open(&db(&dir), &KEY).unwrap();
    assert!(store.is_allowed(Rule::MonitoringInterrupted, None).unwrap());
    assert_eq!(
        store.alert(first).unwrap().unwrap().state,
        AlertState::Dismissed
    );
}

#[test]
fn one_gap_is_open_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    assert!(store.open_gap(Some(NOW), "engine stopped").unwrap());
    assert!(
        !store.open_gap(Some(NOW + 1), "revoked").unwrap(),
        "one is already open"
    );
    store.close_gap(NOW + 5_000).unwrap();
    store.close_gap(NOW + 9_000).unwrap();
    assert!(store.open_gap(None, "closed without warning").unwrap());
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

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// CM-04: the history knows when it began; reopening keeps that, and a wipe starts a
/// new history.
#[test]
fn the_history_knows_when_it_began() {
    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let before = now_ms();
    let began = Store::open(&path, &KEY).unwrap().began();
    assert!((before - 1_000..=now_ms() + 1_000).contains(&began));
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(Store::open(&path, &KEY).unwrap().began(), began, "kept");
    wipe(&path).unwrap();
    assert!(
        Store::open(&path, &KEY).unwrap().began() > began,
        "a new history"
    );
}

/// CM-04: each app's first connection is reported when it starts, and each name an app
/// connects to for the first time when the connection ends, once, across reopening and
/// the roll-up of old flows.
#[test]
fn first_connections_and_first_names_are_reported_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let ended = |mut row: FlowRow, at: i64| {
        row.ended = Some(at);
        row
    };

    // A new app's first connection, its name known from DNS.
    let first = flow("org.example.chat", "chat.example", NOW);
    assert_eq!(
        store.record_flows(1, &[event(1, first.clone())]).unwrap(),
        [FirstSeen::App {
            app: "org.example.chat".to_owned(),
            destination: "chat.example".to_owned(),
            blocked: false,
        }]
    );
    // Its name counts when the connection ends.
    assert_eq!(
        store
            .record_flows(1, &[event(1, ended(first.clone(), NOW + 10))])
            .unwrap(),
        [FirstSeen::Destination {
            app: "org.example.chat".to_owned(),
            app_first_seen: NOW,
            destination: "chat.example".to_owned()
        }]
    );
    // The same name again, and a connection with no name, are not new.
    let again = flow("org.example.chat", "chat.example", NOW + 20);
    let mut bare = flow("org.example.chat", "unused", NOW + 30);
    bare.hostname = None;
    bare.hostname_src = None;
    assert!(
        store
            .record_flows(
                1,
                &[
                    event(2, again.clone()),
                    event(2, ended(again, NOW + 25)),
                    event(3, ended(bare, NOW + 35)),
                ]
            )
            .unwrap()
            .is_empty()
    );

    // Another app: its first connection has no name yet, so its address is reported;
    // the name it ends with (from the TLS handshake) is its first destination.
    let mut late = flow("org.example.maps", "unused", NOW + 40);
    late.hostname = None;
    late.hostname_src = None;
    let mut named = late.clone();
    named.hostname = Some("tiles.example".to_owned());
    named.hostname_src = Some(HostnameSource::Sni);
    assert_eq!(
        store
            .record_flows(1, &[event(4, late), event(4, ended(named, NOW + 50))])
            .unwrap(),
        [
            FirstSeen::App {
                app: "org.example.maps".to_owned(),
                destination: "93.184.215.14".to_owned(),
                blocked: false,
            },
            FirstSeen::Destination {
                app: "org.example.maps".to_owned(),
                app_first_seen: NOW + 40,
                destination: "tiles.example".to_owned()
            },
        ]
    );
    // A name is new per app: the chat app's first visit to tiles.example is news.
    let shared = flow("org.example.chat", "tiles.example", NOW + 60);
    assert_eq!(
        store
            .record_flows(2, &[event(1, ended(shared, NOW + 70))])
            .unwrap(),
        [FirstSeen::Destination {
            app: "org.example.chat".to_owned(),
            app_first_seen: NOW,
            destination: "tiles.example".to_owned()
        }]
    );
    // A connection with no owner is nobody's news.
    let mut unowned = flow("unused", "x.example", NOW + 80);
    unowned.app = None;
    assert!(
        store
            .record_flows(2, &[event(2, ended(unowned, NOW + 90))])
            .unwrap()
            .is_empty()
    );

    // Rolled up and reopened, the history still knows both apps and their names.
    assert_eq!(store.apply_retention(NOW + 40 * DAY, 30).unwrap(), 6);
    drop(store);
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let back = flow("org.example.chat", "chat.example", NOW + 41 * DAY);
    assert!(
        store
            .record_flows(3, &[event(1, ended(back, NOW + 41 * DAY))])
            .unwrap()
            .is_empty()
    );
}

/// CM-04: newer destinations join the app's open alert of the same rule raised since a
/// given time, instead of making another; other apps, dismissed alerts and older ones
/// do not take them.
#[test]
fn newer_destinations_join_an_open_alert() {
    use sentinel_detect::{Evidence, LEARNING_MS, new_destinations};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let names = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let at = NOW + LEARNING_MS;
    let alert = |app: &str, hosts: &[&str], created: i64| {
        new_destinations(created, app, NOW, &names(hosts)).unwrap()
    };

    let first = alert("org.example.chat", &["a.example"], at);
    assert_eq!(store.join_open_alert(&first, at - DAY).unwrap(), None);
    let id = store.record_alert(&first).unwrap();

    let later = alert("org.example.chat", &["a.example", "b.example"], at + 1_000);
    assert_eq!(store.join_open_alert(&later, at - DAY).unwrap(), Some(id));
    assert_eq!(
        store.alert(id).unwrap().unwrap().alert.evidence[1],
        Evidence::Destinations {
            destinations: names(&["a.example", "b.example"]),
            more: 0
        }
    );
    assert_eq!(store.alerts(false, 10).unwrap().len(), 1);

    let other_app = alert("org.example.maps", &["c.example"], at + 2_000);
    assert_eq!(store.join_open_alert(&other_app, at - DAY).unwrap(), None);
    assert_eq!(
        store.join_open_alert(&later, at + 1).unwrap(),
        None,
        "raised before the window"
    );
    store.set_alert_state(id, AlertState::Dismissed).unwrap();
    assert_eq!(
        store.join_open_alert(&later, at - DAY).unwrap(),
        None,
        "dismissed"
    );
}

/// MS-02: every app, name and address the history holds connections to, with when and
/// how many: flows still kept give the name and the address, rolled-up days the name, or
/// the address of connections that had none. The list version last checked is kept.
#[test]
fn past_destinations_cover_kept_flows_and_rolled_up_days() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let old = NOW - 40 * DAY;
    let mut named = flow("org.example.a", "spy.example", old);
    named.ended = Some(old + 1_000);
    let mut again = flow("org.example.a", "spy.example", old + 60_000);
    again.ended = Some(old + 61_000);
    let mut unnamed = flow("org.example.b", "unused", old);
    unnamed.hostname = None;
    unnamed.hostname_src = None;
    unnamed.remote_ip = "198.51.100.7".to_owned();
    let mut kept = flow("org.example.a", "spy.example", NOW - DAY);
    kept.ended = Some(NOW - DAY + 5_000);
    let mut unowned = flow("unused", "cdn.example", NOW - 2 * DAY);
    unowned.app = None;
    let events: Vec<_> = [named, again, unnamed, kept, unowned]
        .into_iter()
        .enumerate()
        .map(|(i, row)| event(i as u64, row))
        .collect();
    store.record_flows(1, &events).unwrap();
    assert_eq!(store.apply_retention(NOW, 30).unwrap(), 3);

    let mut past = store.past_destinations().unwrap();
    past.sort_by(|a, b| (a.first, &a.app).cmp(&(b.first, &b.app)));
    let day = old / DAY * DAY;
    let a = Some("org.example.a");
    let spy = Some("spy.example");
    let address = Some("93.184.215.14");
    assert_eq!(
        past,
        [
            destination(a, spy, None, (day, day, 2)),
            destination(
                Some("org.example.b"),
                None,
                Some("198.51.100.7"),
                (day, day, 1)
            ),
            destination(
                None,
                Some("cdn.example"),
                address,
                (NOW - 2 * DAY, NOW - 2 * DAY, 1)
            ),
            destination(a, spy, address, (NOW - DAY, NOW - DAY + 5_000, 1)),
        ]
    );

    assert_eq!(store.hunted().unwrap(), None);
    store.set_hunted(3).unwrap();
    store.set_hunted(2).unwrap();
    assert_eq!(store.hunted().unwrap(), Some(2), "replaced, not kept apart");
    drop(store);
    let store = Store::open(&db(&dir), &KEY).unwrap();
    assert_eq!(store.hunted().unwrap(), Some(2));
}

/// ID-13, MS-02: a known-indicator alert is found among the alerts of its rule, open or
/// all, so that the same sighting is not raised twice.
#[test]
fn alerts_are_found_by_rule() {
    use sentinel_detect::{IndicatorMatch, Rule, Sighting, Threat, known_indicator};

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let matched = IndicatorMatch {
        indicator: "bad.example".to_owned(),
        seen: "cdn.bad.example".to_owned(),
        sighting: Sighting::DnsQuery,
        family: "Hermit".to_owned(),
        threat: Threat::Spyware,
        source: "Example lab".to_owned(),
        date: "2022-06-23".to_owned(),
        report: "https://example.org/report".to_owned(),
    };
    let first = known_indicator(NOW, Some("org.example.chat"), matched.clone());
    let second = known_indicator(NOW + 1, None, matched);
    let first_id = store.record_alert(&first).unwrap();
    let second_id = store.record_alert(&second).unwrap();
    store
        .record_alert(&sentinel_detect::monitoring_interrupted(
            NOW, None, "killed",
        ))
        .unwrap();

    let open = store.alerts_of(Rule::KnownIndicator, true).unwrap();
    assert_eq!(
        open.iter().map(|a| a.id).collect::<Vec<_>>(),
        [second_id, first_id],
        "newest first, only this rule's"
    );
    assert_eq!(open[1].alert, first, "kept with its provenance");
    store
        .set_alert_state(second_id, AlertState::Dismissed)
        .unwrap();
    let ids = |open_only| {
        store
            .alerts_of(Rule::KnownIndicator, open_only)
            .unwrap()
            .iter()
            .map(|a| a.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(true), [first_id]);
    assert_eq!(ids(false), [second_id, first_id], "dismissed ones too");
    assert_eq!(store.count_alerts(Rule::KnownIndicator).unwrap(), 2);
    assert_eq!(store.count_alerts(Rule::MonitoringInterrupted).unwrap(), 1);
    assert_eq!(store.count_alerts(Rule::ProxyChanged).unwrap(), 0);
    assert!(
        store
            .alerts_of(Rule::ProxyChanged, false)
            .unwrap()
            .is_empty()
    );
}

/// CM-07: the network settings last seen are kept across reopening, so that a change
/// made while Sentinel was not running is found; a wipe forgets them.
#[test]
fn the_network_settings_last_seen_are_kept() {
    use sentinel_detect::NetworkState;

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    let home = NetworkState {
        network: Some("7:100".to_owned()),
        dns_servers: vec!["192.168.1.1".to_owned()],
        ..Default::default()
    };
    assert_eq!(store.network_state().unwrap(), None);
    assert_eq!(store.swap_network_state(&home, NOW).unwrap(), None);
    assert_eq!(store.network_state().unwrap(), Some(home.clone()));
    let mut proxied = home.clone();
    proxied.proxy = Some("192.0.2.10:3128".to_owned());
    assert_eq!(
        store.swap_network_state(&proxied, NOW + 1).unwrap(),
        Some(home)
    );
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.swap_network_state(&proxied, NOW + 2).unwrap(),
        Some(proxied.clone())
    );
    drop(store);
    wipe(&path).unwrap();
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.swap_network_state(&proxied, NOW + 3).unwrap(), None);
}

/// CM-10: firewall rules are kept, encrypted, keyed by what they are about: a second
/// rule about the same app and destination replaces the first. They survive reopening,
/// can be removed, and a wipe removes them.
#[test]
fn firewall_rules_are_kept_and_replaced_by_key() {
    use sentinel_detect::{Destination, FirewallRule, RuleAction};

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    assert!(store.firewall_rules().unwrap().is_empty());
    let ads = Destination::domain("ads.example").unwrap();
    let block = FirewallRule::new(
        Some("org.example.chat"),
        Some(ads.clone()),
        RuleAction::Block,
    )
    .unwrap();
    let range = FirewallRule::new(
        None,
        Some(Destination::network("192.0.2.0/24").unwrap()),
        RuleAction::Block,
    )
    .unwrap();
    let key = store.set_firewall_rule(&block, NOW, None).unwrap();
    assert_eq!(key, "org.example.chat domain:ads.example");
    store.set_firewall_rule(&range, NOW + 1, None).unwrap();
    let allow = FirewallRule::new(Some("org.example.chat"), Some(ads), RuleAction::Allow).unwrap();
    assert_eq!(store.set_firewall_rule(&allow, NOW + 2, None).unwrap(), key);

    let kept: Vec<_> = store
        .firewall_rules()
        .unwrap()
        .into_iter()
        .map(|r| (r.key, r.rule, r.created))
        .collect();
    assert_eq!(
        kept,
        [
            (key.clone(), allow.clone(), NOW + 2),
            ("* network:192.0.2.0/24".to_owned(), range.clone(), NOW + 1),
        ]
    );
    assert!(!file_contains(&path, b"ads.example"), "encrypted on disk");

    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.firewall_rules().unwrap().len(), 2);
    assert!(store.remove_firewall_rule(&key, NOW).unwrap());
    assert!(!store.remove_firewall_rule(&key, NOW).unwrap());
    assert_eq!(store.firewall_rules().unwrap()[0].rule, range);
    drop(store);
    wipe(&path).unwrap();
    assert!(
        Store::open(&path, &KEY)
            .unwrap()
            .firewall_rules()
            .unwrap()
            .is_empty()
    );
}

/// CM-08: the firewall mode is Monitor until set, survives reopening, and a wipe forgets
/// it. Setting the mode already in force keeps when Block-unknown was turned on.
#[test]
fn the_firewall_mode_is_kept() {
    use sentinel_detect::FirewallMode;

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.firewall_mode().unwrap(), FirewallMode::Monitor);
    let on = FirewallMode::BlockUnknown { since: NOW };
    assert_eq!(store.set_firewall_mode(on, NOW).unwrap(), on);
    assert_eq!(
        store
            .set_firewall_mode(FirewallMode::BlockUnknown { since: NOW + 5 }, NOW)
            .unwrap(),
        on,
        "still on since it was turned on"
    );
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.firewall_mode().unwrap(), on);
    assert_eq!(
        store.set_firewall_mode(FirewallMode::Monitor, NOW).unwrap(),
        FirewallMode::Monitor
    );
    let again = FirewallMode::BlockUnknown { since: NOW + 10 };
    assert_eq!(
        store.set_firewall_mode(again, NOW).unwrap(),
        again,
        "a new start"
    );
    drop(store);
    wipe(&path).unwrap();
    assert_eq!(
        Store::open(&path, &KEY).unwrap().firewall_mode().unwrap(),
        FirewallMode::Monitor
    );
}

/// CM-08: an app's first connection says whether the firewall refused it, so that the
/// alert can say so.
#[test]
fn a_blocked_first_connection_is_reported_as_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&db(&dir), &KEY).unwrap();
    let mut refused = flow("org.example.new", "new.example", NOW);
    refused.blocked = true;
    assert_eq!(
        store.record_flows(1, &[event(1, refused)]).unwrap(),
        [FirstSeen::App {
            app: "org.example.new".to_owned(),
            destination: "new.example".to_owned(),
            blocked: true,
        }]
    );
}

/// RA-03: isolation is kept while on, keeps when it was turned on, survives reopening,
/// and is gone when turned off or wiped.
#[test]
fn isolation_is_kept_until_turned_off() {
    use sentinel_detect::Isolation;

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.isolation().unwrap(), None);
    let on = Isolation {
        since: NOW,
        own_app: "io.github.malekhasan.sentinel".to_owned(),
    };
    store.set_isolation(Some(&on), NOW).unwrap();
    store
        .set_isolation(
            Some(&Isolation {
                since: NOW + 5,
                ..on.clone()
            }),
            NOW,
        )
        .unwrap();
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(
        store.isolation().unwrap(),
        Some(on.clone()),
        "since it was first turned on"
    );
    store.set_isolation(None, NOW).unwrap();
    assert_eq!(store.isolation().unwrap(), None);
    store.set_isolation(Some(&on), NOW).unwrap();
    drop(store);
    wipe(&path).unwrap();
    assert_eq!(Store::open(&path, &KEY).unwrap().isolation().unwrap(), None);
}

/// SRS §9: every change to the firewall rules, the mode and isolation is journalled,
/// encrypted, with who made it, when, from which alert, and the setting before and
/// after. A change that changes nothing is not journalled.
#[test]
fn every_firewall_change_is_journalled() {
    use sentinel_detect::{
        Destination, FirewallMode, FirewallRule, Isolation, RuleAction, Setting,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    assert!(store.journal(10).unwrap().is_empty());
    let alert = store
        .record_alert(&sentinel_detect::monitoring_interrupted(
            NOW, None, "killed",
        ))
        .unwrap();

    let block = FirewallRule::new(Some("org.example.chat"), None, RuleAction::Block).unwrap();
    let allow = FirewallRule {
        action: RuleAction::Allow,
        ..block.clone()
    };
    let key = store.set_firewall_rule(&block, NOW, Some(alert)).unwrap();
    store.set_firewall_rule(&block, NOW + 1, None).unwrap();
    store
        .set_firewall_rule(&allow, NOW + 2, Some(alert + 100))
        .unwrap();
    assert!(store.remove_firewall_rule(&key, NOW + 3).unwrap());
    assert!(!store.remove_firewall_rule(&key, NOW + 4).unwrap());
    let on = FirewallMode::BlockUnknown { since: NOW + 5 };
    store.set_firewall_mode(on, NOW + 5).unwrap();
    store
        .set_firewall_mode(FirewallMode::BlockUnknown { since: NOW + 6 }, NOW + 6)
        .unwrap();
    store
        .set_firewall_mode(FirewallMode::Monitor, NOW + 7)
        .unwrap();
    let isolation = Isolation {
        since: NOW + 8,
        own_app: "io.github.malekhasan.sentinel".to_owned(),
    };
    store.set_isolation(Some(&isolation), NOW + 8).unwrap();
    store
        .set_isolation(
            Some(&Isolation {
                since: NOW + 9,
                ..isolation.clone()
            }),
            NOW + 9,
        )
        .unwrap();
    store.set_isolation(None, NOW + 10).unwrap();
    store.set_isolation(None, NOW + 11).unwrap();
    // A domain rule is about a destination, under its own key.
    let ads = FirewallRule::new(
        None,
        Some(Destination::domain("ads.example").unwrap()),
        RuleAction::Block,
    )
    .unwrap();
    store.set_firewall_rule(&ads, NOW + 12, None).unwrap();

    let rule = |rule: Option<&FirewallRule>| Setting::Rule {
        key: key.clone(),
        rule: rule.cloned(),
    };
    let journal = store.journal(20).unwrap();
    let seen: Vec<_> = journal
        .iter()
        .map(|e| {
            (
                e.change.before().clone(),
                e.change.after().clone(),
                e.alert,
                e.at,
                e.can_undo,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (
                Setting::Rule {
                    key: ads.key(),
                    rule: None
                },
                Setting::Rule {
                    key: ads.key(),
                    rule: Some(ads.clone())
                },
                None,
                NOW + 12,
                true,
            ),
            (
                Setting::Isolation(Some(isolation.clone())),
                Setting::Isolation(None),
                None,
                NOW + 10,
                true,
            ),
            (
                Setting::Isolation(None),
                Setting::Isolation(Some(isolation)),
                None,
                NOW + 8,
                false,
            ),
            (
                Setting::Mode(on),
                Setting::Mode(FirewallMode::Monitor),
                None,
                NOW + 7,
                true,
            ),
            (
                Setting::Mode(FirewallMode::Monitor),
                Setting::Mode(on),
                None,
                NOW + 5,
                false,
            ),
            (rule(Some(&allow)), rule(None), None, NOW + 3, true),
            // An alert that does not exist is not kept.
            (rule(Some(&block)), rule(Some(&allow)), None, NOW + 2, false),
            (rule(None), rule(Some(&block)), Some(alert), NOW, false),
        ]
    );
    assert!(
        journal
            .iter()
            .all(|e| e.actor == "user" && e.undone_at.is_none())
    );
    let actions: Vec<_> = journal.iter().map(|e| e.change.action()).collect();
    assert_eq!(
        actions,
        [
            "keep_rule",
            "end_isolation",
            "isolate",
            "set_mode",
            "set_mode",
            "remove_rule",
            "keep_rule",
            "keep_rule"
        ]
    );
    assert_eq!(
        store.journal(2).unwrap().len(),
        2,
        "newest first, as many as asked"
    );
    assert!(!file_contains(&path, b"keep_rule"), "encrypted on disk");

    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.journal(20).unwrap(), journal, "kept across reopening");
    drop(store);
    wipe(&path).unwrap();
    assert!(
        Store::open(&path, &KEY)
            .unwrap()
            .journal(20)
            .unwrap()
            .is_empty()
    );
}

/// SRS §9: undoing an action puts its setting back as it was before, Block-unknown's
/// and isolation's start times included, only while the setting is still as the action
/// left it, and only once.
#[test]
fn undo_puts_back_what_was_there_before() {
    use sentinel_detect::{FirewallMode, FirewallRule, Isolation, RuleAction};
    use sentinel_store::Undo;

    let dir = tempfile::tempdir().unwrap();
    let path = db(&dir);
    let store = Store::open(&path, &KEY).unwrap();
    let newest = |store: &Store| store.journal(1).unwrap()[0].id;
    let rules = |store: &Store| -> Vec<FirewallRule> {
        store
            .firewall_rules()
            .unwrap()
            .into_iter()
            .map(|r| r.rule)
            .collect()
    };

    // A new rule: undoing removes it.
    let block = FirewallRule::new(Some("org.example.chat"), None, RuleAction::Block).unwrap();
    let key = store.set_firewall_rule(&block, NOW, None).unwrap();
    let kept = newest(&store);
    assert_eq!(store.undo(kept, NOW + 1).unwrap(), Undo::Undone);
    assert!(rules(&store).is_empty());
    assert_eq!(store.undo(kept, NOW + 2).unwrap(), Undo::AlreadyUndone);
    let entry = store.journal(1).unwrap().remove(0);
    assert_eq!((entry.undone_at, entry.can_undo), (Some(NOW + 1), false));

    // A replaced rule: undoing puts the earlier one back; a removed one comes back.
    store.set_firewall_rule(&block, NOW + 3, None).unwrap();
    let allow = FirewallRule {
        action: RuleAction::Allow,
        ..block.clone()
    };
    store.set_firewall_rule(&allow, NOW + 4, None).unwrap();
    assert_eq!(store.undo(newest(&store), NOW + 5).unwrap(), Undo::Undone);
    assert_eq!(rules(&store), std::slice::from_ref(&block));
    store.remove_firewall_rule(&key, NOW + 6).unwrap();
    assert_eq!(store.undo(newest(&store), NOW + 7).unwrap(), Undo::Undone);
    assert_eq!(rules(&store), std::slice::from_ref(&block));

    // Changed since: the later change stays.
    store.remove_firewall_rule(&key, NOW + 8).unwrap();
    let removed = newest(&store);
    store.set_firewall_rule(&allow, NOW + 9, None).unwrap();
    assert!(!store.journal(2).unwrap()[1].can_undo);
    assert_eq!(store.undo(removed, NOW + 10).unwrap(), Undo::ChangedSince);
    assert_eq!(rules(&store), [allow]);

    // The mode comes back with when Block-unknown was turned on.
    let on = FirewallMode::BlockUnknown { since: NOW + 11 };
    store.set_firewall_mode(on, NOW + 11).unwrap();
    let switched_on = newest(&store);
    store
        .set_firewall_mode(FirewallMode::Monitor, NOW + 12)
        .unwrap();
    assert_eq!(store.undo(newest(&store), NOW + 13).unwrap(), Undo::Undone);
    assert_eq!(store.firewall_mode().unwrap(), on);
    // Back as the first switch left it, so that switch can be undone too.
    assert!(store.journal(2).unwrap()[1].can_undo);
    assert_eq!(store.undo(switched_on, NOW + 14).unwrap(), Undo::Undone);
    assert_eq!(store.firewall_mode().unwrap(), FirewallMode::Monitor);

    // Isolation comes back with when it began.
    let isolation = Isolation {
        since: NOW + 15,
        own_app: "io.github.malekhasan.sentinel".to_owned(),
    };
    store.set_isolation(Some(&isolation), NOW + 15).unwrap();
    let isolated = newest(&store);
    store.set_isolation(None, NOW + 16).unwrap();
    let ended = newest(&store);
    assert_eq!(store.undo(isolated, NOW + 17).unwrap(), Undo::ChangedSince);
    assert_eq!(store.undo(ended, NOW + 17).unwrap(), Undo::Undone);
    drop(store);
    let store = Store::open(&path, &KEY).unwrap();
    assert_eq!(store.isolation().unwrap(), Some(isolation));
    assert_eq!(store.undo(isolated, NOW + 18).unwrap(), Undo::Undone);
    assert_eq!(store.isolation().unwrap(), None);

    // Undoing is not itself journalled: the entry says when it was undone.
    assert_eq!(store.journal(100).unwrap().len(), 10);
    assert_eq!(store.undo(9_999, NOW + 19).unwrap(), Undo::NotFound);
}

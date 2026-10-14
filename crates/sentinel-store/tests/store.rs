// SPDX-License-Identifier: GPL-3.0-or-later
//! The store against a real SQLCipher database in a temporary directory.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use sentinel_store::{
    AppSummary, DailyTotal, DestinationTotal, FlowEvent, FlowRow, Gap, HostnameSource, Proto,
    Store, StoreError, wipe,
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
        blocked: false,
    }
}

fn event(engine_id: u64, flow: FlowRow) -> FlowEvent {
    FlowEvent { engine_id, flow }
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
            },
            DailyTotal {
                day,
                app: Some("org.example.b".to_owned()),
                destination: "y.example".to_owned(),
                proto: Proto::Tcp,
                flows: 1,
                bytes_up: 1,
                bytes_down: 1,
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
            destination_count: 3,
            destinations: vec![
                DestinationTotal {
                    destination: "y.example".to_owned(),
                    flows: 1,
                    bytes_up: 1_000,
                    bytes_down: 1,
                    first_seen: NOW - 2 * DAY,
                    last_seen: NOW - 2 * DAY + 1_000,
                },
                DestinationTotal {
                    destination: "x.example".to_owned(),
                    flows: 2,
                    bytes_up: 15,
                    bytes_down: 150,
                    // The rolled-up flow keeps only its day.
                    first_seen: old_day / DAY * DAY,
                    last_seen: NOW - DAY + 1_000,
                },
                DestinationTotal {
                    destination: "93.184.215.14".to_owned(),
                    flows: 1,
                    bytes_up: 0,
                    bytes_down: 0,
                    first_seen: NOW,
                    last_seen: NOW,
                },
            ],
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

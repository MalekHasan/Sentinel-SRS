// SPDX-License-Identifier: GPL-3.0-or-later
//! Beacon-like traffic (DL-04, ADR-0031): an app that connects to the same place again
//! and again at a fixed interval, with little jitter and little data each time, as
//! spyware checking in with its server does. Many ordinary apps poll a server too, so
//! the alert is Info, and its text says both.

use std::collections::{HashMap, VecDeque};

use crate::{Alert, Evidence, Rule, Severity};

/// Check-ins in a row that make a pattern: seven intervals.
pub const BEACON_CHECK_INS: usize = 8;
/// The shortest interval counted. More often than this is a busy app, not a check-in.
pub const BEACON_MIN_INTERVAL_MS: i64 = 10_000;
/// The longest interval counted: one check-in an hour.
pub const BEACON_MAX_INTERVAL_MS: i64 = 60 * 60 * 1000;
/// The most data one check-in may carry, both ways together. A larger transfer breaks
/// the pattern.
pub const BEACON_MAX_BYTES: u64 = 16 * 1024;
/// Every interval must be within a tenth of the typical one.
const JITTER_DIVISOR: i64 = 10;
/// Connections that begin this close together are one check-in.
const CHECK_IN_MS: i64 = 2_000;
/// App and destination pairs followed at once. Beyond this, the pair seen least
/// recently is forgotten, which bounds memory however many places apps reach.
const FOLLOWED: usize = 4096;

/// A pattern of check-ins: one app to one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// A name, or an address when no name is known.
    pub destination: String,
    /// The typical (median) time between check-ins, in milliseconds.
    pub interval_ms: i64,
    /// Check-ins in the pattern.
    pub check_ins: u32,
    /// The most data one check-in carried, both ways together, in bytes.
    pub max_bytes: u64,
}

/// Follows each app's connections to each destination, and finds check-ins at a fixed
/// interval. One per engine run: each pattern is reported once.
#[derive(Debug, Default)]
pub struct Beacons {
    series: HashMap<(String, String), Series>,
}

#[derive(Debug, Default)]
struct Series {
    /// The latest check-ins, in order of start: when each began (Unix ms), and the data
    /// it carried.
    check_ins: VecDeque<(i64, u64)>,
    reported: bool,
}

impl Beacons {
    pub fn new() -> Self {
        Self::default()
    }

    /// A connection of `app` to `destination` (a name, or an address when no name is
    /// known), begun at `started` (Unix ms), has ended having carried `bytes` both ways.
    /// Returns the pattern the first time this app's latest check-ins there make one.
    pub fn connection(
        &mut self,
        app: &str,
        destination: &str,
        started: i64,
        bytes: u64,
    ) -> Option<Beacon> {
        let key = (app.to_owned(), destination.to_owned());
        if !self.series.contains_key(&key) && self.series.len() >= FOLLOWED {
            self.forget_oldest();
        }
        let series = self.series.entry(key).or_default();
        if series.reported {
            return None;
        }
        let check_ins = &mut series.check_ins;
        // Connections end out of order: keep them in order of start.
        let at = check_ins.partition_point(|&(start, _)| start <= started);
        let joins = [at.checked_sub(1), Some(at)]
            .into_iter()
            .flatten()
            .find(|&i| {
                check_ins
                    .get(i)
                    .is_some_and(|&(start, _)| (start - started).abs() < CHECK_IN_MS)
            });
        let size = match joins {
            Some(i) => {
                check_ins[i].1 = check_ins[i].1.saturating_add(bytes);
                check_ins[i].1
            }
            None => {
                check_ins.insert(at, (started, bytes));
                bytes
            }
        };
        if size > BEACON_MAX_BYTES {
            check_ins.clear();
            return None;
        }
        while check_ins.len() > BEACON_CHECK_INS {
            check_ins.pop_front();
        }
        let (interval_ms, max_bytes) = pattern(check_ins)?;
        series.reported = true;
        Some(Beacon {
            destination: destination.to_owned(),
            interval_ms,
            check_ins: BEACON_CHECK_INS as u32,
            max_bytes,
        })
    }

    /// App and destination pairs followed now.
    pub fn followed(&self) -> usize {
        self.series.len()
    }

    fn forget_oldest(&mut self) {
        let oldest = self
            .series
            .iter()
            .min_by_key(|(_, series)| {
                series
                    .check_ins
                    .back()
                    .map_or(i64::MIN, |&(start, _)| start)
            })
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.series.remove(&key);
        }
    }
}

/// The typical interval and the largest check-in, if `check_ins` are evenly spaced.
fn pattern(check_ins: &VecDeque<(i64, u64)>) -> Option<(i64, u64)> {
    if check_ins.len() < BEACON_CHECK_INS {
        return None;
    }
    let starts: Vec<i64> = check_ins.iter().map(|&(start, _)| start).collect();
    let mut intervals: Vec<i64> = starts.windows(2).map(|pair| pair[1] - pair[0]).collect();
    intervals.sort_unstable();
    let typical = intervals[intervals.len() / 2];
    if !(BEACON_MIN_INTERVAL_MS..=BEACON_MAX_INTERVAL_MS).contains(&typical) {
        return None;
    }
    let jitter = intervals
        .iter()
        .map(|interval| (interval - typical).abs())
        .max()?;
    if jitter * JITTER_DIVISOR > typical {
        return None;
    }
    Some((typical, check_ins.iter().map(|&(_, bytes)| bytes).max()?))
}

/// DL-04: `app` connects to the beacon's destination at a fixed interval with little
/// data each time. Info: spyware checks in like this, and so do many ordinary apps.
pub fn beacon_like(now: i64, app: &str, beacon: Beacon) -> Alert {
    Alert {
        rule: Rule::BeaconLike,
        severity: Severity::Info,
        created: now,
        evidence: vec![
            Evidence::App {
                package: app.to_owned(),
            },
            Evidence::Beacon {
                destination: beacon.destination,
                interval_ms: beacon.interval_ms,
                check_ins: beacon.check_ins,
                max_bytes: beacon.max_bytes,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "org.example.app";
    const HOST: &str = "c2.example.net";
    const MINUTE: i64 = 60_000;

    /// Feeds connections begun at `starts`, each carrying `bytes`, in the order given.
    fn feed(beacons: &mut Beacons, starts: &[i64], bytes: u64) -> Vec<Beacon> {
        starts
            .iter()
            .filter_map(|&start| beacons.connection(APP, HOST, start, bytes))
            .collect()
    }

    /// Every `interval`, shifted by `jitter[i % len]`.
    fn every(interval: i64, count: usize, jitter: &[i64]) -> Vec<i64> {
        (0..count)
            .map(|i| 1_000_000 + i as i64 * interval + jitter[i % jitter.len()])
            .collect()
    }

    /// The beacon simulation: a check-in every minute, give or take two seconds, with
    /// half a kilobyte each time, is found once, at the eighth.
    #[test]
    fn regular_small_check_ins_are_a_beacon() {
        let mut beacons = Beacons::new();
        let starts = every(MINUTE, 12, &[0, 1_500, -2_000, 800, -400]);
        let found = feed(&mut beacons, &starts[..7], 500);
        assert!(found.is_empty(), "seven are not enough");
        assert_eq!(
            beacons.connection(APP, HOST, starts[7], 500),
            Some(Beacon {
                destination: HOST.to_owned(),
                interval_ms: 60_400,
                check_ins: 8,
                max_bytes: 500,
            })
        );
        assert!(feed(&mut beacons, &starts[8..], 500).is_empty(), "once");
    }

    #[test]
    fn check_ins_that_end_out_of_order_are_put_in_order() {
        let mut beacons = Beacons::new();
        let mut starts = every(5 * MINUTE, 8, &[0]);
        starts.swap(2, 5);
        starts.swap(0, 7);
        assert_eq!(feed(&mut beacons, &starts, 900).len(), 1);
    }

    #[test]
    fn several_connections_at_once_are_one_check_in() {
        let mut beacons = Beacons::new();
        let mut found = Vec::new();
        for start in every(MINUTE, 8, &[0]) {
            found.extend(beacons.connection(APP, HOST, start, 300));
            found.extend(beacons.connection(APP, HOST, start + 150, 200));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].max_bytes, 500);
        assert_eq!(found[0].interval_ms, MINUTE);
    }

    #[test]
    fn irregular_or_jittery_traffic_is_not_a_beacon() {
        let mut beacons = Beacons::new();
        // A tenth of a minute off is the most allowed; this is a fifth.
        assert!(
            feed(
                &mut beacons,
                &every(MINUTE, 20, &[0, 12_000, -12_000, 3_000]),
                500
            )
            .is_empty()
        );
        // Someone browsing: gaps of seconds to minutes.
        let browsing = [
            0, 4_000, 31_000, 95_000, 101_000, 260_000, 262_000, 400_000, 615_000, 640_000,
        ];
        let mut other = Beacons::new();
        assert!(feed(&mut other, &browsing, 500).is_empty());
    }

    #[test]
    fn too_often_too_rarely_or_too_much_data_is_not_a_beacon() {
        let mut beacons = Beacons::new();
        assert!(
            feed(&mut beacons, &every(5_000, 20, &[0]), 500).is_empty(),
            "too often"
        );
        let mut beacons = Beacons::new();
        assert!(
            feed(&mut beacons, &every(2 * 60 * MINUTE, 20, &[0]), 500).is_empty(),
            "too rarely"
        );
        let mut beacons = Beacons::new();
        assert!(
            feed(&mut beacons, &every(MINUTE, 20, &[0]), 64 * 1024).is_empty(),
            "too much data"
        );
    }

    #[test]
    fn a_large_transfer_starts_the_count_again() {
        let mut beacons = Beacons::new();
        let starts = every(MINUTE, 16, &[0]);
        assert!(feed(&mut beacons, &starts[..7], 500).is_empty());
        assert_eq!(beacons.connection(APP, HOST, starts[7], 1_000_000), None);
        assert!(
            feed(&mut beacons, &starts[8..15], 500).is_empty(),
            "seven since"
        );
        assert!(beacons.connection(APP, HOST, starts[15], 500).is_some());
    }

    #[test]
    fn apps_and_destinations_are_followed_apart() {
        let mut beacons = Beacons::new();
        let mut found = Vec::new();
        for (i, start) in every(MINUTE, 8, &[0]).into_iter().enumerate() {
            // Alternating between two places, each every two minutes.
            let host = if i % 2 == 0 { "a.example" } else { "b.example" };
            found.extend(beacons.connection(APP, host, start, 100));
            found.extend(beacons.connection("org.example.other", HOST, start, 100));
        }
        assert_eq!(found.len(), 1, "only the other app has eight");
        assert_eq!(found[0].destination, HOST);
    }

    #[test]
    fn memory_is_bounded() {
        let mut beacons = Beacons::new();
        for i in 0..(FOLLOWED as i64 + 100) {
            beacons.connection(APP, &format!("host{i}.example"), i * 1_000, 100);
        }
        assert_eq!(beacons.followed(), FOLLOWED);
    }

    #[test]
    fn the_alert_is_info_about_the_app() {
        let alert = beacon_like(
            7,
            APP,
            Beacon {
                destination: HOST.to_owned(),
                interval_ms: MINUTE,
                check_ins: 8,
                max_bytes: 500,
            },
        );
        assert_eq!(alert.severity, Severity::Info);
        assert_eq!(alert.app(), Some(APP));
        assert_eq!(
            alert.actions(),
            vec![
                crate::Action::BlockApp {
                    package: APP.to_owned()
                },
                crate::Action::OpenApp {
                    package: APP.to_owned()
                },
            ]
        );
        assert_eq!(
            crate::evidence_to_json(&alert.evidence[1..]),
            r#"[{"type":"beacon","destination":"c2.example.net","interval_ms":60000,"check_ins":8,"max_bytes":500}]"#
        );
    }
}

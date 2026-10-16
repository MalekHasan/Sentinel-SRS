// SPDX-License-Identifier: GPL-3.0-or-later
//! The retro-hunt (SRS MS-02, ADR-0021): when a new indicator list comes into force, the
//! history is checked against it. Connections the phone made before the list arrived
//! that it names are reported, with the app, when they were made and how many.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError};

use sentinel_detect::{IndicatorMatch, Rule, Sighting, known_indicator_in_history, same_sighting};
use sentinel_ioc::{Hit, Matcher};
use sentinel_store::PastDestination;

use crate::feed::Feed;
use crate::history::{HistoryError, HistoryStore, now_ms};

/// What checking the history against an indicator list found.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HuntReport {
    /// The version of the list the history was checked against.
    pub version: u64,
    /// How many apps and indicators the history holds connections between.
    pub matches: u32,
    /// Of those, the ones not reported before: each raised a Critical alert.
    pub raised: u32,
}

#[uniffi::export]
impl HistoryStore {
    /// Check the history against the indicator list `feed` has in force (MS-02): every
    /// app, name and address it holds connections to, kept flows and rolled-up days.
    /// Each app and indicator found raises one Critical alert with when the connections
    /// were made and how many, unless an alert already reported them, open or dismissed.
    /// Runs once per list version; `None` when there is no list in force or the history
    /// was already checked against it.
    pub fn hunt(&self, feed: Arc<Feed>) -> Result<Option<HuntReport>, HistoryError> {
        let _one_at_a_time = self.hunting.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((version, matcher)) = feed.in_force() else {
            return Ok(None);
        };
        if self.store.hunted()? == Some(version) {
            return Ok(None);
        }
        let found = matches(&matcher, &self.store.past_destinations()?);
        let reported = self.store.alerts_of(Rule::KnownIndicator, false)?;
        let now = now_ms();
        let mut raised = 0u32;
        for past in &found {
            let alert = known_indicator_in_history(
                now,
                past.app.as_deref(),
                past.matched.clone(),
                past.first,
                past.last,
                past.connections,
            );
            if reported
                .iter()
                .any(|earlier| same_sighting(&alert, &earlier.alert))
            {
                continue;
            }
            self.raise(&alert)?;
            raised += 1;
        }
        // Only now: a check cut short is run again, and what it raised is not repeated.
        self.store.set_hunted(version)?;
        Ok(Some(HuntReport {
            version,
            matches: u32::try_from(found.len()).unwrap_or(u32::MAX),
            raised,
        }))
    }
}

/// What a match says about an indicator: which, how it was seen, and its provenance
/// (MS-10).
pub(crate) fn indicator_match(hit: &Hit, seen: &str, sighting: Sighting) -> IndicatorMatch {
    let indicator = &hit.indicator;
    IndicatorMatch {
        indicator: indicator.value.clone(),
        seen: seen.to_owned(),
        sighting,
        family: indicator.family.clone(),
        threat: match indicator.threat {
            sentinel_ioc::Threat::Spyware => sentinel_detect::Threat::Spyware,
            sentinel_ioc::Threat::Stalkerware => sentinel_detect::Threat::Stalkerware,
        },
        source: hit.source.name.clone(),
        date: indicator.date.clone(),
        report: indicator.report.clone(),
    }
}

/// Connections the history holds between one app and one indicator.
struct Found {
    app: Option<String>,
    /// As first seen.
    matched: IndicatorMatch,
    first: i64,
    last: i64,
    connections: u64,
}

/// The apps and indicators `past` holds connections between, oldest first. A name and
/// an address are matched each on their own.
fn matches(matcher: &Matcher, past: &[PastDestination]) -> Vec<Found> {
    let mut found: Vec<Found> = Vec::new();
    let mut index: HashMap<(Option<String>, String), usize> = HashMap::new();
    for destination in past {
        let by_name = destination.name.as_deref().and_then(|name| {
            matcher
                .name(name)
                .map(|hit| (hit, name, Sighting::ConnectionName))
        });
        let by_address = destination.address.as_deref().and_then(|address| {
            let hit = matcher.address(address.parse().ok()?)?;
            Some((hit, address, Sighting::Address))
        });
        for (hit, seen, sighting) in [by_name, by_address].into_iter().flatten() {
            let key = (destination.app.clone(), hit.indicator.value.clone());
            match index.get(&key) {
                Some(&i) => {
                    let earlier = &mut found[i];
                    earlier.first = earlier.first.min(destination.first);
                    earlier.last = earlier.last.max(destination.last);
                    earlier.connections =
                        earlier.connections.saturating_add(destination.connections);
                }
                None => {
                    index.insert(key, found.len());
                    found.push(Found {
                        app: destination.app.clone(),
                        matched: indicator_match(hit, seen, sighting),
                        first: destination.first,
                        last: destination.last,
                        connections: destination.connections,
                    });
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity, IndicatorSighting};
    use crate::feed::tests::{indicators, open, path, stage};
    use sentinel_store::{FlowEvent, FlowRow, HostnameSource, Proto};

    const DAY: i64 = 24 * 60 * 60 * 1000;

    fn history(dir: &std::path::Path) -> Arc<HistoryStore> {
        let path = dir.join("history.db").to_string_lossy().into_owned();
        HistoryStore::open(path, vec![7; 32]).unwrap()
    }

    /// A finished flow from `app` to `address`, by `name` if given, from `started` for a
    /// second.
    fn flow(app: &str, name: Option<&str>, address: &str, started: i64) -> FlowRow {
        FlowRow {
            app: Some(app.to_owned()),
            proto: Proto::Tcp,
            local_ip: "10.215.173.1".to_owned(),
            local_port: 40_000,
            remote_ip: address.to_owned(),
            remote_port: 443,
            hostname: name.map(str::to_owned),
            hostname_src: name.map(|_| HostnameSource::Sni),
            started,
            ended: Some(started + 1_000),
            bytes_up: 1,
            bytes_down: 1,
            bytes_up_away: 0,
            bytes_down_away: 0,
            blocked: false,
        }
    }

    /// The evidence of the open known-indicator alerts, oldest first.
    fn reported(history: &HistoryStore) -> Vec<Vec<AlertEvidence>> {
        let mut alerts = history.alerts(true, 100).unwrap();
        alerts.reverse();
        assert!(
            alerts
                .iter()
                .all(|alert| alert.rule == AlertRule::KnownIndicator
                    && alert.severity == AlertSeverity::Critical)
        );
        alerts.into_iter().map(|alert| alert.evidence).collect()
    }

    /// MS-02: when a list comes into force, the history is checked against it once. Kept
    /// flows and rolled-up days that it names raise one alert per app and indicator, with
    /// when and how often, and the indicator's provenance. A newer list raises only what
    /// was not reported before, even if that was dismissed.
    #[test]
    fn the_history_is_checked_once_per_list_and_reports_each_match_once() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let feed = open(&dir.path().join("feed"));
        assert_eq!(history.hunt(Arc::clone(&feed)).unwrap(), None, "no list");

        let now = now_ms();
        let (t1, t2, t3) = (now - 3 * DAY, now - 2 * DAY, now - DAY);
        let old = now - 40 * DAY;
        let rows = [
            flow("org.example.old", Some("spy.example"), "203.0.113.1", old),
            flow(
                "org.example.chat",
                Some("cdn.spy.example"),
                "203.0.113.5",
                t1,
            ),
            flow(
                "org.example.chat",
                Some("cdn.spy.example"),
                "203.0.113.6",
                t2,
            ),
            flow("org.example.maps", None, "198.51.100.7", t3),
            flow("org.example.news", Some("news.example"), "203.0.113.9", t3),
        ];
        let events: Vec<_> = rows
            .into_iter()
            .enumerate()
            .map(|(i, flow)| FlowEvent {
                engine_id: i as u64,
                flow,
                destination: None,
            })
            .collect();
        history.store.record_flows(1, &events).unwrap();
        history.store.apply_retention(now, 30).unwrap();

        let first = stage(
            dir.path(),
            1,
            &[(
                "indicators-lab.json",
                indicators(
                    "lab",
                    &[("domain", "spy.example"), ("address", "198.51.100.7")],
                ),
            )],
        );
        feed.install(path(&first)).unwrap();
        assert_eq!(
            history.hunt(Arc::clone(&feed)).unwrap(),
            Some(HuntReport {
                version: 1,
                matches: 3,
                raised: 3
            })
        );
        let provenance = |indicator: &str, seen: &str, sighting| AlertEvidence::Indicator {
            indicator: indicator.into(),
            seen: seen.into(),
            sighting,
            family: "Example".into(),
            threat: crate::alerts::IndicatorThreat::Stalkerware,
            source: "Source lab".into(),
            date: "2025-01-31".into(),
            report: "https://example.org/report".into(),
        };
        let app = |app: &str| AlertEvidence::App { app: app.into() };
        let day = old / DAY * DAY;
        assert_eq!(
            reported(&history),
            [
                vec![
                    app("org.example.old"),
                    provenance(
                        "spy.example",
                        "spy.example",
                        IndicatorSighting::ConnectionName
                    ),
                    AlertEvidence::PastConnections {
                        first_ms: day,
                        last_ms: day,
                        connections: 1
                    },
                ],
                vec![
                    app("org.example.chat"),
                    provenance(
                        "spy.example",
                        "cdn.spy.example",
                        IndicatorSighting::ConnectionName
                    ),
                    AlertEvidence::PastConnections {
                        first_ms: t1,
                        last_ms: t2 + 1_000,
                        connections: 2
                    },
                ],
                vec![
                    app("org.example.maps"),
                    provenance("198.51.100.7", "198.51.100.7", IndicatorSighting::Address),
                    AlertEvidence::PastConnections {
                        first_ms: t3,
                        last_ms: t3 + 1_000,
                        connections: 1
                    },
                ],
            ]
        );
        assert_eq!(
            history.hunt(Arc::clone(&feed)).unwrap(),
            None,
            "once per list"
        );

        // A newer list that adds an indicator: only the new match is raised, although the
        // chat app's alert was dismissed.
        let chat = history.alerts(true, 100).unwrap()[1].id;
        history.dismiss_alert(chat).unwrap();
        let second = stage(
            dir.path(),
            2,
            &[(
                "indicators-lab.json",
                indicators(
                    "lab",
                    &[
                        ("domain", "spy.example"),
                        ("address", "198.51.100.7"),
                        ("domain", "news.example"),
                    ],
                ),
            )],
        );
        feed.install(path(&second)).unwrap();
        assert_eq!(
            history.hunt(Arc::clone(&feed)).unwrap(),
            Some(HuntReport {
                version: 2,
                matches: 4,
                raised: 1
            })
        );
        let open = reported(&history);
        assert_eq!(open.len(), 3, "{open:?}");
        assert_eq!(open[2][0], app("org.example.news"));
    }

    /// A match already reported live (ID-13) is not reported again from the history.
    #[test]
    fn a_match_already_seen_live_is_not_reported_again() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let feed = open(&dir.path().join("feed"));
        let staged = stage(
            dir.path(),
            1,
            &[(
                "indicators-lab.json",
                indicators("lab", &[("domain", "spy.example")]),
            )],
        );
        feed.install(path(&staged)).unwrap();
        let row = flow(
            "org.example.chat",
            Some("spy.example"),
            "203.0.113.5",
            now_ms(),
        );
        history
            .store
            .record_flows(
                1,
                &[FlowEvent {
                    engine_id: 1,
                    flow: row,
                    destination: None,
                }],
            )
            .unwrap();
        let (_, matcher) = feed.in_force().unwrap();
        let hit = matcher.name("spy.example").unwrap();
        let live = sentinel_detect::known_indicator(
            now_ms(),
            Some("org.example.chat"),
            indicator_match(hit, "spy.example", Sighting::ServerName),
        );
        history.raise(&live).unwrap();
        assert_eq!(
            history.hunt(feed).unwrap(),
            Some(HuntReport {
                version: 1,
                matches: 1,
                raised: 0
            })
        );
        assert_eq!(history.alerts(false, 10).unwrap().len(), 1);
    }
}

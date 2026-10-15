// SPDX-License-Identifier: GPL-3.0-or-later
//! New behaviour (CM-04): an app's first use of the network, and the names an app
//! connects to for the first time (ADR-0013).

use crate::{Alert, Evidence, Rule, Severity};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// How long the history learns an app's destinations before new ones are flagged:
/// a week, so that apps used only on some days settle too.
pub const LEARNING_MS: i64 = 7 * DAY_MS;

/// New destinations of one app join its open alert of the same rule raised within this
/// time, rather than raising another.
pub const GROUP_WINDOW_MS: i64 = DAY_MS;

/// Destinations listed in one alert's evidence. Further ones are counted.
pub const MAX_LISTED: usize = 20;

/// CM-04: `package` used the network for the first time the history knows of, at
/// `now`, connecting to `destination` (a name, or an address if no name is known).
///
/// Only an app installed since the history began (`installed` at or after
/// `history_began`, Unix milliseconds) is new: an app that was there before may have
/// used the network before Sentinel watched. `None` when the install time is unknown,
/// as for Android's shared system identities.
pub fn first_network_use(
    now: i64,
    package: &str,
    installed: Option<i64>,
    history_began: i64,
    destination: &str,
) -> Option<Alert> {
    if installed? < history_began {
        return None;
    }
    Some(Alert {
        rule: Rule::FirstNetworkUse,
        severity: Severity::Info,
        created: now,
        evidence: vec![
            Evidence::App {
                package: package.to_owned(),
            },
            Evidence::Destinations {
                destinations: vec![destination.to_owned()],
                more: 0,
            },
        ],
    })
}

/// CM-04: `package`, first seen by the history at `app_first_seen`, connected to
/// `destinations` (names) for the first time. Nothing while the history is still
/// learning the app ([`LEARNING_MS`]): every destination of a new app is new.
pub fn new_destinations(
    now: i64,
    package: &str,
    app_first_seen: i64,
    destinations: &[String],
) -> Option<Alert> {
    if destinations.is_empty() || now.saturating_sub(app_first_seen) < LEARNING_MS {
        return None;
    }
    let mut evidence = vec![Evidence::App {
        package: package.to_owned(),
    }];
    add_destinations(&mut evidence, destinations);
    Some(Alert {
        rule: Rule::NewDestination,
        severity: Severity::Info,
        created: now,
        evidence,
    })
}

/// Add `destinations` to an alert's evidence: listed while fewer than [`MAX_LISTED`]
/// are, counted after that. Destinations already listed are not added again.
pub fn add_destinations(evidence: &mut Vec<Evidence>, destinations: &[String]) {
    let (listed, more) = destinations_of(evidence);
    for destination in destinations {
        if listed.contains(destination) {
            continue;
        }
        if listed.len() < MAX_LISTED {
            listed.push(destination.clone());
        } else {
            *more = more.saturating_add(1);
        }
    }
}

/// Join a newer alert's destinations, listed and counted, into an open alert's evidence
/// (see [`GROUP_WINDOW_MS`]).
pub fn join_destinations(evidence: &mut Vec<Evidence>, newer: &[Evidence]) {
    for item in newer {
        if let Evidence::Destinations { destinations, more } = item {
            add_destinations(evidence, destinations);
            let (_, counted) = destinations_of(evidence);
            *counted = counted.saturating_add(*more);
        }
    }
}

/// The evidence's destinations, added empty if it has none.
fn destinations_of(evidence: &mut Vec<Evidence>) -> (&mut Vec<String>, &mut u32) {
    let index = match evidence
        .iter()
        .position(|e| matches!(e, Evidence::Destinations { .. }))
    {
        Some(index) => index,
        None => {
            evidence.push(Evidence::Destinations {
                destinations: Vec::new(),
                more: 0,
            });
            evidence.len() - 1
        }
    };
    match &mut evidence[index] {
        Evidence::Destinations { destinations, more } => (destinations, more),
        _ => unreachable!("the index points at the destinations"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;

    const BEGAN: i64 = 1_000_000;

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("host{i}.example")).collect()
    }

    #[test]
    fn an_app_installed_since_the_history_began_is_new() {
        let alert = first_network_use(
            BEGAN + 60_000,
            "org.example.new",
            Some(BEGAN),
            BEGAN,
            "api.example",
        )
        .unwrap();
        assert_eq!(alert.rule, Rule::FirstNetworkUse);
        assert_eq!(alert.severity, Severity::Info);
        assert_eq!(alert.created, BEGAN + 60_000);
        assert_eq!(alert.app(), Some("org.example.new"));
        assert_eq!(
            alert.evidence[1],
            Evidence::Destinations {
                destinations: vec!["api.example".to_owned()],
                more: 0
            }
        );
        assert_eq!(
            alert.actions(),
            [Action::OpenApp {
                package: "org.example.new".to_owned()
            }]
        );
    }

    #[test]
    fn an_app_installed_before_or_at_an_unknown_time_is_not() {
        assert_eq!(
            first_network_use(
                BEGAN,
                "org.example.old",
                Some(BEGAN - 1),
                BEGAN,
                "a.example"
            ),
            None
        );
        assert_eq!(
            first_network_use(BEGAN, "android.uid.system:1000", None, BEGAN, "a.example"),
            None
        );
    }

    #[test]
    fn new_destinations_wait_for_the_learning_period() {
        let first_seen = BEGAN;
        let hosts = names(2);
        assert_eq!(
            new_destinations(
                first_seen + LEARNING_MS - 1,
                "org.example.chat",
                first_seen,
                &hosts
            ),
            None
        );
        let alert = new_destinations(
            first_seen + LEARNING_MS,
            "org.example.chat",
            first_seen,
            &hosts,
        )
        .unwrap();
        assert_eq!(alert.rule, Rule::NewDestination);
        assert_eq!(alert.severity, Severity::Info);
        assert_eq!(alert.app(), Some("org.example.chat"));
        assert_eq!(
            alert.evidence[1],
            Evidence::Destinations {
                destinations: hosts,
                more: 0
            }
        );
        assert_eq!(
            new_destinations(
                first_seen + LEARNING_MS,
                "org.example.chat",
                first_seen,
                &[]
            ),
            None
        );
    }

    #[test]
    fn destinations_are_listed_up_to_the_limit_then_counted() {
        let mut evidence = vec![Evidence::App {
            package: "org.example.browser".to_owned(),
        }];
        let all = names(MAX_LISTED + 5);
        add_destinations(&mut evidence, &all[..3]);
        add_destinations(&mut evidence, &all[..3]);
        add_destinations(&mut evidence, &all[3..]);
        assert_eq!(evidence.len(), 2);
        assert_eq!(
            evidence[1],
            Evidence::Destinations {
                destinations: all[..MAX_LISTED].to_vec(),
                more: 5
            }
        );
    }

    #[test]
    fn a_newer_alert_joins_an_open_one() {
        let first_seen = BEGAN;
        let now = first_seen + LEARNING_MS;
        let all = names(MAX_LISTED + 3);
        let mut open = new_destinations(now, "org.example.chat", first_seen, &all[..2]).unwrap();
        let newer = new_destinations(now + 1, "org.example.chat", first_seen, &all[1..]).unwrap();
        join_destinations(&mut open.evidence, &newer.evidence);
        assert_eq!(open.evidence.len(), 2, "one app, one list");
        // 23 destinations: the first 20 listed, the other 3 counted, the one both
        // alerts had only once.
        assert_eq!(
            open.evidence[1],
            Evidence::Destinations {
                destinations: all[..MAX_LISTED].to_vec(),
                more: 3,
            }
        );
    }

    #[test]
    fn rule_ids_are_stable() {
        assert_eq!(Rule::FirstNetworkUse.id(), "first-network-use");
        assert_eq!(Rule::NewDestination.id(), "new-destination");
        for rule in [Rule::FirstNetworkUse, Rule::NewDestination] {
            assert_eq!(Rule::from_id(rule.id()), Some(rule));
        }
    }
}

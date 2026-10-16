// SPDX-License-Identifier: GPL-3.0-or-later
//! Installed apps against the indicators in force (ID-13, ADR-0023): an app installed
//! under a package name, or signed with a certificate, that the list ties to stalkerware
//! or spyware.

use std::collections::HashSet;
use std::sync::{Arc, PoisonError};

use sentinel_detect::{Rule, Sighting, known_indicator, same_sighting};

use crate::feed::Feed;
use crate::history::{HistoryError, HistoryStore, now_ms};
use crate::hunt::indicator_match;

/// An app installed on the phone, as Android describes it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InstalledApp {
    pub package: String,
    /// The SHA-256 of each certificate it is signed with, now or before a key rotation,
    /// in hex.
    pub certificates: Vec<String>,
    /// When it was installed or last updated, Unix milliseconds.
    pub installed_ms: i64,
}

/// What checking the installed apps found.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppCheck {
    /// The version of the list the apps were checked against.
    pub version: u64,
    /// How many apps and indicators match.
    pub matches: u32,
    /// Of those, the ones not reported since the app was installed or last updated: each
    /// raised a Critical alert.
    pub raised: u32,
}

#[uniffi::export]
impl HistoryStore {
    /// Check `apps` against the package and certificate indicators `feed` has in force
    /// (ID-13). Each app and indicator found raises one Critical alert, unless an alert
    /// already reported them since the app was installed or last updated, open or
    /// dismissed: an app that stays installed is reported once, and again if it is
    /// installed anew. `None` when there is no list in force.
    pub fn check_apps(
        &self,
        feed: Arc<Feed>,
        apps: Vec<InstalledApp>,
    ) -> Result<Option<AppCheck>, HistoryError> {
        let _one_at_a_time = self.hunting.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((version, matcher)) = feed.in_force() else {
            return Ok(None);
        };
        let reported = self.store.alerts_of(Rule::KnownIndicator, false)?;
        let now = now_ms();
        let (mut matches, mut raised) = (0u32, 0u32);
        for app in &apps {
            let by_package = matcher
                .package(&app.package)
                .map(|hit| (hit, app.package.as_str(), Sighting::InstalledPackage));
            let by_certificate = app.certificates.iter().filter_map(|certificate| {
                matcher
                    .certificate(certificate)
                    .map(|hit| (hit, certificate.as_str(), Sighting::SigningCertificate))
            });
            let mut found = HashSet::new();
            for (hit, seen, sighting) in by_package.into_iter().chain(by_certificate) {
                if !found.insert(&hit.indicator.value) {
                    continue;
                }
                matches += 1;
                let alert = known_indicator(
                    now,
                    Some(&app.package),
                    indicator_match(hit, &seen.to_ascii_lowercase(), sighting),
                );
                let already = reported.iter().any(|earlier| {
                    earlier.alert.created >= app.installed_ms
                        && same_sighting(&alert, &earlier.alert)
                });
                if !already {
                    self.raise(&alert)?;
                    raised += 1;
                }
            }
        }
        Ok(Some(AppCheck {
            version,
            matches,
            raised,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{AlertEvidence, AlertRule, AlertSeverity, IndicatorSighting};
    use crate::feed::tests::{indicators, open, path, stage};

    const CERTIFICATE: &str = "abababababababababababababababababababababababababababababababab";

    fn history(dir: &std::path::Path) -> Arc<HistoryStore> {
        let path = dir.join("history.db").to_string_lossy().into_owned();
        HistoryStore::open(path, vec![7; 32]).unwrap()
    }

    fn app(package: &str, certificates: &[&str], installed_ms: i64) -> InstalledApp {
        InstalledApp {
            package: package.to_owned(),
            certificates: certificates.iter().map(|c| (*c).to_owned()).collect(),
            installed_ms,
        }
    }

    /// The app and how the indicator was seen, for each open alert, oldest first.
    fn reported(history: &HistoryStore) -> Vec<(String, IndicatorSighting, String)> {
        let mut alerts = history.alerts(true, 100).unwrap();
        alerts.reverse();
        alerts
            .into_iter()
            .map(|alert| {
                assert_eq!(alert.rule, AlertRule::KnownIndicator);
                assert_eq!(alert.severity, AlertSeverity::Critical);
                let AlertEvidence::App { app } = &alert.evidence[0] else {
                    panic!("{:?}", alert.evidence);
                };
                let AlertEvidence::Indicator { sighting, seen, .. } = &alert.evidence[1] else {
                    panic!("{:?}", alert.evidence);
                };
                (app.clone(), *sighting, seen.clone())
            })
            .collect()
    }

    /// ID-13: an app installed under a listed package name, or signed with a listed
    /// certificate, raises one Critical alert per indicator; an app that stays installed
    /// is not reported again, even once dismissed, but is when installed anew.
    #[test]
    fn installed_apps_are_matched_by_package_and_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let feed = open(&dir.path().join("feed"));
        let earlier = now_ms() - 60_000;
        let apps = || {
            vec![
                app("com.example.watch", &["0000"], earlier),
                app(
                    "org.example.notes",
                    &[&CERTIFICATE.to_ascii_uppercase()],
                    earlier,
                ),
                app("org.example.both", &[CERTIFICATE], earlier),
                app("org.example.chat", &[], earlier),
            ]
        };
        assert_eq!(
            history.check_apps(Arc::clone(&feed), apps()).unwrap(),
            None,
            "no list"
        );

        let staged = stage(
            dir.path(),
            1,
            &[(
                "indicators-lab.json",
                indicators(
                    "lab",
                    &[
                        ("package", "com.example.watch"),
                        ("package", "org.example.both"),
                        ("certificate", CERTIFICATE),
                        ("domain", "spy.example"),
                    ],
                ),
            )],
        );
        feed.install(path(&staged)).unwrap();
        assert_eq!(
            history.check_apps(Arc::clone(&feed), apps()).unwrap(),
            Some(AppCheck {
                version: 1,
                matches: 4,
                raised: 4
            })
        );
        let watch = (
            "com.example.watch".to_owned(),
            IndicatorSighting::InstalledPackage,
        );
        assert_eq!(
            reported(&history),
            [
                (watch.0.clone(), watch.1, "com.example.watch".to_owned()),
                (
                    "org.example.notes".to_owned(),
                    IndicatorSighting::SigningCertificate,
                    CERTIFICATE.to_owned()
                ),
                (
                    "org.example.both".to_owned(),
                    IndicatorSighting::InstalledPackage,
                    "org.example.both".to_owned()
                ),
                (
                    "org.example.both".to_owned(),
                    IndicatorSighting::SigningCertificate,
                    CERTIFICATE.to_owned()
                ),
            ]
        );

        // Still installed: nothing new, even once an alert is dismissed.
        let first = history.alerts(true, 100).unwrap().last().unwrap().id;
        history.dismiss_alert(first).unwrap();
        assert_eq!(
            history.check_apps(Arc::clone(&feed), apps()).unwrap(),
            Some(AppCheck {
                version: 1,
                matches: 4,
                raised: 0
            })
        );

        // Installed anew.
        let mut again = apps();
        again[0].installed_ms = now_ms() + 1;
        assert_eq!(
            history.check_apps(Arc::clone(&feed), again).unwrap(),
            Some(AppCheck {
                version: 1,
                matches: 4,
                raised: 1
            })
        );
        assert_eq!(reported(&history).last().unwrap().0, watch.0);
        assert_eq!(history.known_traces().unwrap().alerts, 5);
    }
}

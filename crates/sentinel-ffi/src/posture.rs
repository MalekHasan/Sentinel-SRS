// SPDX-License-Identifier: GPL-3.0-or-later
//! Device settings that open the phone to someone else (ADR-0025): wireless debugging
//! (ID-03) and certificate authorities the user added (ID-10).

use std::sync::PoisonError;

use crate::history::{HistoryError, HistoryStore, now_ms};

/// The device settings Sentinel watches, as Android reports them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DevicePosture {
    /// Wireless debugging, ADB over Wi-Fi, is on.
    pub wireless_debugging: bool,
    /// The certificate authorities the user added to the trusted ones.
    pub user_certificates: Vec<UserCertificate>,
}

/// A certificate authority the user added to the trusted ones.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UserCertificate {
    /// The SHA-256 of the certificate, in hex.
    pub sha256: String,
    /// Who it was issued to, as its subject names them.
    pub subject: String,
}

#[uniffi::export]
impl HistoryStore {
    /// The device settings as they are now (ID-03, ID-10). Wireless debugging turned on,
    /// and each certificate authority added, since the settings seen before, even before
    /// Sentinel last stopped, raises an alert. The first state a history sees reports
    /// what is on and trusted already.
    pub fn posture_seen(&self, posture: DevicePosture) -> Result<(), HistoryError> {
        let posture = sentinel_detect::Posture {
            wireless_debugging: posture.wireless_debugging,
            user_certificates: posture
                .user_certificates
                .into_iter()
                .map(|certificate| sentinel_detect::Certificate {
                    sha256: certificate.sha256.to_ascii_lowercase(),
                    subject: certificate.subject,
                })
                .collect(),
        };
        let now = now_ms();
        // Kept once its alerts are: if one cannot be, the next check finds the change
        // again (audit A-35). An alert raised before it may then be raised twice, which
        // is better than none.
        let _checking = self
            .checking_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let before = self.store.posture()?;
        for alert in sentinel_detect::posture_changes(now, before.as_ref(), &posture) {
            self.raise(&alert)?;
        }
        self.store.swap_posture(&posture, now)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::alerts::{
        AlertAction, AlertEvidence, AlertFeedback, AlertRule, AlertSeverity, RemoteAccessService,
    };

    fn history(dir: &std::path::Path) -> Arc<HistoryStore> {
        let path = dir.join("history.db").to_string_lossy().into_owned();
        HistoryStore::open(path, vec![7; 32]).unwrap()
    }

    fn posture(wireless_debugging: bool, certificates: &[(&str, &str)]) -> DevicePosture {
        DevicePosture {
            wireless_debugging,
            user_certificates: certificates
                .iter()
                .map(|(sha256, subject)| UserCertificate {
                    sha256: (*sha256).to_owned(),
                    subject: (*subject).to_owned(),
                })
                .collect(),
        }
    }

    /// ID-03, ID-10: what is on and trusted is reported when first seen, then only what
    /// is turned on or added since. These alerts name no app, so they cannot be allowed
    /// (AL-05, audit A-08).
    #[test]
    fn wireless_debugging_and_added_certificates_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let work = ("AA", "CN=Work CA,O=Example");
        let proxy = ("bb", "CN=Proxy CA");
        history.posture_seen(posture(false, &[work])).unwrap();
        let alerts = history.alerts(true, 100).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::NewRootCertificate);
        assert_eq!(alerts[0].severity, AlertSeverity::High);
        assert_eq!(
            alerts[0].evidence,
            [AlertEvidence::Certificate {
                sha256: "aa".to_owned(),
                subject: "CN=Work CA,O=Example".to_owned()
            }]
        );
        assert_eq!(alerts[0].actions, [AlertAction::OpenCertificateSettings]);

        // Wireless debugging turned on and a second certificate added.
        history.posture_seen(posture(true, &[work, proxy])).unwrap();
        let alerts = history.alerts(true, 100).unwrap();
        assert_eq!(alerts.len(), 3);
        let debugging = alerts
            .iter()
            .find(|alert| alert.rule == AlertRule::RemoteAccessExposed)
            .unwrap();
        assert_eq!(debugging.severity, AlertSeverity::Warning);
        assert_eq!(
            debugging.evidence,
            [AlertEvidence::RemoteAccess {
                service: RemoteAccessService::WirelessDebugging
            }]
        );
        assert_eq!(debugging.actions, [AlertAction::OpenDeveloperSettings]);
        history.posture_seen(posture(true, &[work, proxy])).unwrap();
        assert_eq!(history.alerts(true, 100).unwrap().len(), 3);

        // It cannot be allowed: turned off and on again, it is reported again.
        assert!(!debugging.can_allow);
        assert!(
            history
                .set_feedback(debugging.id, Some(AlertFeedback::Allowed))
                .is_err()
        );
        history
            .posture_seen(posture(false, &[work, proxy]))
            .unwrap();
        history.posture_seen(posture(true, &[work, proxy])).unwrap();
        assert_eq!(history.alerts(false, 100).unwrap().len(), 4);
    }

    /// Audit A-35: a change whose alert could not be kept is not taken as seen, so the
    /// next check reports it.
    #[test]
    fn a_change_whose_alert_was_not_kept_is_reported_at_the_next_check() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        history.posture_seen(posture(false, &[])).unwrap();
        let refused =
            crate::history::testing::AlertsRefused::new(&dir.path().join("history.db"), 7);
        assert!(history.posture_seen(posture(true, &[])).is_err());
        drop(refused);
        history.posture_seen(posture(true, &[])).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].rule, AlertRule::RemoteAccessExposed);
    }
}

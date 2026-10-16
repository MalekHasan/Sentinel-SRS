// SPDX-License-Identifier: GPL-3.0-or-later
//! Device settings that open the phone to someone else (ADR-0025): ADB over the network
//! (ID-03) and certificate authorities the user added to the trusted ones (ID-10).

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// The device settings Sentinel watches, as last seen. Stored as JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posture {
    /// Wireless debugging, ADB over Wi-Fi, is on (ID-03).
    pub wireless_debugging: bool,
    /// The certificate authorities the user added to the trusted ones (ID-10).
    pub user_certificates: Vec<Certificate>,
}

/// A certificate, as the phone trusts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// The SHA-256 of the certificate, in lower-case hex.
    pub sha256: String,
    /// Who it was issued to, as its subject names them.
    pub subject: String,
}

impl Posture {
    /// The state as stored.
    pub fn to_json(&self) -> String {
        // Serializing this type cannot fail: strings, lists and a flag only.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Result<Posture, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// What changed for the worse between two states of the device settings, as alerts.
/// Unlike network settings, the first state seen (`before` is `None`) is reported too:
/// wireless debugging that is on, or a certificate that is trusted, is a risk however
/// long it has been there.
///
/// - Wireless debugging turned on raises a Warning (ID-03), like any remote-access
///   service exposed (SRS §8.3).
/// - Each certificate authority the user added raises a High alert (ID-10), like a new
///   root certificate (SRS §8.3). A certificate removed and added again is reported
///   again.
pub fn posture_changes(now: i64, before: Option<&Posture>, after: &Posture) -> Vec<Alert> {
    let mut alerts = Vec::new();
    if after.wireless_debugging && !before.is_some_and(|before| before.wireless_debugging) {
        alerts.push(Alert {
            rule: Rule::RemoteAccessExposed,
            severity: Severity::Warning,
            created: now,
            evidence: vec![Evidence::RemoteAccess {
                service: RemoteAccess::WirelessDebugging,
            }],
        });
    }
    for certificate in &after.user_certificates {
        let known = before.is_some_and(|before| {
            before
                .user_certificates
                .iter()
                .any(|known| known.sha256 == certificate.sha256)
        });
        if !known {
            alerts.push(Alert {
                rule: Rule::NewRootCertificate,
                severity: Severity::High,
                created: now,
                evidence: vec![Evidence::Certificate {
                    sha256: certificate.sha256.clone(),
                    subject: certificate.subject.clone(),
                }],
            });
        }
    }
    alerts
}

/// A way in from the network that the user can turn on (ID-03). Stored by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAccess {
    /// ADB over Wi-Fi: a paired computer on the same network can install apps, read
    /// data and control the phone.
    WirelessDebugging,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, evidence_from_json, evidence_to_json};

    fn certificate(sha256: &str, subject: &str) -> Certificate {
        Certificate {
            sha256: sha256.to_owned(),
            subject: subject.to_owned(),
        }
    }

    fn rules(alerts: &[Alert]) -> Vec<(Rule, Severity)> {
        alerts.iter().map(|a| (a.rule, a.severity)).collect()
    }

    /// The first state seen reports what is on and trusted already; nothing else does.
    #[test]
    fn the_first_state_reports_what_is_already_there() {
        assert_eq!(posture_changes(1, None, &Posture::default()), []);
        let open = Posture {
            wireless_debugging: true,
            user_certificates: vec![certificate("aa", "CN=Proxy CA")],
        };
        let alerts = posture_changes(1, None, &open);
        assert_eq!(
            rules(&alerts),
            [
                (Rule::RemoteAccessExposed, Severity::Warning),
                (Rule::NewRootCertificate, Severity::High),
            ]
        );
        assert_eq!(posture_changes(2, Some(&open), &open), []);
    }

    /// ID-03 and ID-10: wireless debugging turned on, and each certificate added, once;
    /// turned off and on, or removed and added, again.
    #[test]
    fn what_is_turned_on_or_added_is_reported() {
        let closed = Posture {
            wireless_debugging: false,
            user_certificates: vec![certificate("aa", "CN=Work CA")],
        };
        let open = Posture {
            wireless_debugging: true,
            user_certificates: vec![
                certificate("aa", "CN=Work CA"),
                certificate("bb", "CN=Proxy CA"),
            ],
        };
        let alerts = posture_changes(5, Some(&closed), &open);
        assert_eq!(
            alerts[0].evidence,
            [Evidence::RemoteAccess {
                service: RemoteAccess::WirelessDebugging
            }]
        );
        assert_eq!(alerts[0].actions(), [Action::OpenDeveloperSettings]);
        assert_eq!(
            alerts[1].evidence,
            [Evidence::Certificate {
                sha256: "bb".to_owned(),
                subject: "CN=Proxy CA".to_owned()
            }]
        );
        assert_eq!(alerts[1].actions(), [Action::OpenCertificateSettings]);
        assert_eq!(alerts[1].app(), None);
        assert_eq!(alerts.len(), 2);
        // Turned off and removed: nothing. Then on and added again: reported again.
        assert_eq!(posture_changes(6, Some(&open), &closed), []);
        assert_eq!(rules(&posture_changes(7, Some(&closed), &open)).len(), 2);
    }

    /// The stored forms are part of the history's format.
    #[test]
    fn the_state_and_the_evidence_are_stored_by_name() {
        let posture = Posture {
            wireless_debugging: true,
            user_certificates: vec![certificate("bb", "CN=Proxy CA")],
        };
        let json = posture.to_json();
        assert_eq!(
            json,
            r#"{"wireless_debugging":true,"user_certificates":[{"sha256":"bb","subject":"CN=Proxy CA"}]}"#
        );
        assert_eq!(Posture::from_json(&json).unwrap(), posture);
        let alerts = posture_changes(1, None, &posture);
        let evidence: Vec<_> = alerts.iter().flat_map(|a| a.evidence.clone()).collect();
        let json = evidence_to_json(&evidence);
        assert_eq!(
            json,
            r#"[{"type":"remote_access","service":"wireless_debugging"},{"type":"certificate","sha256":"bb","subject":"CN=Proxy CA"}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), evidence);
    }
}

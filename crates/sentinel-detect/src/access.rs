// SPDX-License-Identifier: GPL-3.0-or-later
//! Special access that lets an app watch the user (ID-12, ADR-0024): accessibility,
//! device admin and notification access. Android grants none of them without someone
//! turning it on in the settings, and stalkerware asks for all three.

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// A kind of special access an app can hold. The names are stored in the history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// An accessibility service: the app can read the screen and act for the user.
    Accessibility,
    /// A device admin app: it can lock or wipe the phone, and cannot be uninstalled
    /// while it is one.
    DeviceAdmin,
    /// Notification access: the app reads every notification.
    NotificationListener,
}

impl Access {
    /// The name stored in the history.
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Accessibility => "accessibility",
            Access::DeviceAdmin => "device_admin",
            Access::NotificationListener => "notification_listener",
        }
    }

    pub fn from_name(name: &str) -> Option<Access> {
        [
            Access::Accessibility,
            Access::DeviceAdmin,
            Access::NotificationListener,
        ]
        .into_iter()
        .find(|a| a.as_str() == name)
    }
}

/// ID-12: `package` holds `access`, which it did not hold at the last check. High, like
/// a new admin account (SRS §8.3): many apps have good reasons for it, so the user can
/// allow it for the app (AL-05).
pub fn special_access(now: i64, package: &str, access: Access) -> Alert {
    Alert {
        rule: Rule::SpecialAccess,
        severity: Severity::High,
        created: now,
        evidence: vec![
            Evidence::App {
                package: package.to_owned(),
            },
            Evidence::Access { access },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, evidence_from_json, evidence_to_json};

    #[test]
    fn names_round_trip() {
        for access in [
            Access::Accessibility,
            Access::DeviceAdmin,
            Access::NotificationListener,
        ] {
            assert_eq!(Access::from_name(access.as_str()), Some(access));
        }
        assert_eq!(Access::from_name("camera"), None);
    }

    /// ID-12: the alert names the app and the access, and offers Android's settings for
    /// that access first, then blocking the app and looking at what it did.
    #[test]
    fn an_app_with_special_access_can_be_looked_into() {
        let alert = special_access(5, "com.example.watch", Access::NotificationListener);
        assert_eq!(alert.rule, Rule::SpecialAccess);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.app(), Some("com.example.watch"));
        let app = || "com.example.watch".to_owned();
        assert_eq!(
            alert.actions(),
            [
                Action::OpenAccessSettings {
                    access: Access::NotificationListener
                },
                Action::BlockApp { package: app() },
                Action::OpenApp { package: app() },
            ]
        );
    }

    /// The stored JSON of the evidence is part of the history's format.
    #[test]
    fn the_evidence_is_stored_by_name() {
        let alert = special_access(5, "com.example.watch", Access::DeviceAdmin);
        let json = evidence_to_json(&alert.evidence);
        assert_eq!(
            json,
            r#"[{"type":"app","package":"com.example.watch"},{"type":"access","access":"device_admin"}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), alert.evidence);
    }
}

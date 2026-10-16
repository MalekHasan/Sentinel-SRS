// SPDX-License-Identifier: GPL-3.0-or-later
//! Apps that gain special access (ID-12, ADR-0024): accessibility, device admin or
//! notification access, held by an app that did not come with the phone.

use std::collections::BTreeSet;

use sentinel_detect::special_access;

use crate::alerts::SpecialAccess;
use crate::history::{HistoryError, HistoryStore, now_ms};

/// Special access an app holds, as Android reports it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HeldAccess {
    pub app: String,
    pub access: SpecialAccess,
    /// The app came with the phone (it is on the system image). Its access is never
    /// reported: someone who can change the system image needs no special access.
    pub preinstalled: bool,
}

/// What checking the special access apps hold found.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccessCheck {
    /// How much special access apps not preinstalled hold: one per app and kind.
    pub held: u32,
    /// Of those, the ones not held at the last check: each raised a High alert, unless
    /// the user allowed the rule for the app (AL-05) or an open alert already says so.
    pub gained: u32,
}

#[uniffi::export]
impl HistoryStore {
    /// Check the special access apps hold (ID-12): every access an app not preinstalled
    /// holds now and did not hold at the last check raises a High alert. The first check
    /// reports all of it. Access turned off and on again is reported again.
    pub fn check_access(&self, held: Vec<HeldAccess>) -> Result<AccessCheck, HistoryError> {
        let held: Vec<_> = held
            .into_iter()
            .filter(|held| !held.preinstalled)
            .map(|held| (held.app, held.access.into()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let gained = self.store.swap_access(&held)?;
        let now = now_ms();
        for (app, access) in &gained {
            self.raise_unless_open(&special_access(now, app, *access), |new, open| {
                new.evidence == open.evidence
            })?;
        }
        Ok(AccessCheck {
            held: u32::try_from(held.len()).unwrap_or(u32::MAX),
            gained: u32::try_from(gained.len()).unwrap_or(u32::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::alerts::{AlertAction, AlertEvidence, AlertFeedback, AlertRule, AlertSeverity};

    fn history(dir: &std::path::Path) -> Arc<HistoryStore> {
        let path = dir.join("history.db").to_string_lossy().into_owned();
        HistoryStore::open(path, vec![7; 32]).unwrap()
    }

    fn held(app: &str, access: SpecialAccess, preinstalled: bool) -> HeldAccess {
        HeldAccess {
            app: app.to_owned(),
            access,
            preinstalled,
        }
    }

    /// The app and access of each open alert, oldest first.
    fn reported(history: &HistoryStore) -> Vec<(String, SpecialAccess)> {
        let mut alerts = history.alerts(true, 100).unwrap();
        alerts.reverse();
        alerts
            .into_iter()
            .map(|alert| {
                assert_eq!(alert.rule, AlertRule::SpecialAccess);
                assert_eq!(alert.severity, AlertSeverity::High);
                let [AlertEvidence::App { app }, AlertEvidence::Access { access }] =
                    alert.evidence.as_slice()
                else {
                    panic!("{:?}", alert.evidence);
                };
                assert_eq!(
                    alert.actions,
                    [
                        AlertAction::OpenAccessSettings { access: *access },
                        AlertAction::BlockApp { app: app.clone() },
                        AlertAction::OpenApp { app: app.clone() },
                    ]
                );
                (app.clone(), *access)
            })
            .collect()
    }

    /// ID-12: access held by an app that did not come with the phone raises one High
    /// alert when first seen; it is not reported again while held, and is again once
    /// turned off and on; preinstalled apps are never reported.
    #[test]
    fn apps_that_gain_special_access_are_reported() {
        use SpecialAccess::{Accessibility, DeviceAdmin, NotificationListener};

        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let watch = || "com.example.watch".to_owned();
        let phone = vec![
            held("com.example.watch", NotificationListener, false),
            held("com.example.watch", NotificationListener, false),
            held("com.example.watch", Accessibility, false),
            held("com.android.launcher", NotificationListener, true),
            held("com.android.talkback", Accessibility, true),
        ];
        assert_eq!(
            history.check_access(phone.clone()).unwrap(),
            AccessCheck { held: 2, gained: 2 }
        );
        // By app, then by kind of access.
        assert_eq!(
            reported(&history),
            [(watch(), Accessibility), (watch(), NotificationListener)]
        );
        assert_eq!(
            history.check_access(phone.clone()).unwrap(),
            AccessCheck { held: 2, gained: 0 }
        );
        assert_eq!(history.alerts(true, 100).unwrap().len(), 2);

        // Made a device admin: reported.
        let mut admin = phone.clone();
        admin.push(held("com.example.watch", DeviceAdmin, false));
        assert_eq!(
            history.check_access(admin.clone()).unwrap(),
            AccessCheck { held: 3, gained: 1 }
        );
        assert_eq!(reported(&history).last(), Some(&(watch(), DeviceAdmin)));

        // Notification access turned off and on again, after its alert was put away.
        let listener = history
            .alerts(true, 100)
            .unwrap()
            .into_iter()
            .find(|alert| {
                alert.evidence.contains(&AlertEvidence::Access {
                    access: NotificationListener,
                })
            })
            .unwrap();
        assert!(history.dismiss_alert(listener.id).unwrap());
        let off: Vec<_> = admin
            .iter()
            .filter(|held| held.access != NotificationListener)
            .cloned()
            .collect();
        assert_eq!(
            history.check_access(off).unwrap(),
            AccessCheck { held: 2, gained: 0 }
        );
        assert_eq!(
            history.check_access(admin.clone()).unwrap(),
            AccessCheck { held: 3, gained: 1 }
        );
        assert_eq!(
            reported(&history).last(),
            Some(&(watch(), NotificationListener))
        );
        assert_eq!(history.alerts(true, 100).unwrap().len(), 3);
    }

    /// AL-05: once the user allows the rule for an app, its access raises nothing more;
    /// access turned off and on again while its alert is still open raises no second
    /// one.
    #[test]
    fn allowed_or_open_access_is_not_raised_again() {
        use SpecialAccess::{Accessibility, NotificationListener};

        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let keyboard = held("org.example.keyboard", Accessibility, false);
        let watch = held("com.example.watch", NotificationListener, false);
        history.check_access(vec![keyboard.clone()]).unwrap();
        let id = history.alerts(true, 100).unwrap()[0].id;
        assert!(
            history
                .set_feedback(id, Some(AlertFeedback::Allowed))
                .unwrap()
        );
        history.check_access(vec![]).unwrap();
        assert_eq!(
            history.check_access(vec![keyboard.clone()]).unwrap(),
            AccessCheck { held: 1, gained: 1 }
        );
        assert_eq!(history.alerts(false, 100).unwrap().len(), 1);

        history.check_access(vec![watch.clone()]).unwrap();
        history.check_access(vec![]).unwrap();
        history.check_access(vec![watch.clone()]).unwrap();
        assert_eq!(
            reported(&history),
            [("com.example.watch".to_owned(), NotificationListener)]
        );
    }
}

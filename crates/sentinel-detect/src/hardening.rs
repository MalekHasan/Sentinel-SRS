// SPDX-License-Identifier: GPL-3.0-or-later
//! The hardening checklist (MS-12, ADR-0026): steps that make a phone harder to spy on,
//! each with its status where the phone lets Sentinel read it, else a check for the user.

/// How old the security update may be before updating is a step to take: Android's
/// security bulletins are monthly, and makers often ship them a month or two late.
pub const UPDATE_MAX_AGE_DAYS: i64 = 90;

/// How far past the phone's clock the security update's date may be. Some makers ship a
/// month's update before the month begins, dated its 1st or 5th. A date further ahead
/// means the clock or the date is wrong, and the update's age cannot be told.
pub const UPDATE_MAX_AHEAD_DAYS: i64 = 31;

/// A step of the checklist, in the order shown: the most protection first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Android Advanced Protection (Android 16 and later).
    AdvancedProtection,
    /// The latest security update.
    SecurityUpdate,
    /// A screen lock: a PIN, pattern or password.
    ScreenLock,
    /// USB debugging turned off.
    UsbDebugging,
    /// No app allowed to install other apps.
    UnknownApps,
    /// Messaging apps no longer used removed or turned off.
    MessagingApps,
}

/// Where a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Done, as far as the phone shows.
    Done,
    /// Not done: the user can take this step.
    ToDo,
    /// The phone does not let Sentinel read it: the user checks it.
    CheckYourself,
    /// This version of Android does not have it.
    NotAvailable,
}

/// What Sentinel could read about the phone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// Whether this version of Android has Advanced Protection.
    pub advanced_protection_available: bool,
    /// Whether it is on; `None` when it could not be read.
    pub advanced_protection: Option<bool>,
    /// The security update installed, `YYYY-MM-DD`; `None` when unknown.
    pub security_patch: Option<String>,
    /// A PIN, pattern or password locks the screen.
    pub screen_lock: bool,
    /// USB debugging is on.
    pub usb_debugging: bool,
}

/// One step of the checklist and where it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub step: Step,
    pub status: Status,
}

/// MS-12: the checklist for a phone with `facts`, on the day `today_ms` (Unix ms).
pub fn checklist(facts: &Facts, today_ms: i64) -> Vec<Item> {
    let done = |done: bool| if done { Status::Done } else { Status::ToDo };
    let advanced_protection = match (
        facts.advanced_protection_available,
        facts.advanced_protection,
    ) {
        (false, _) => Status::NotAvailable,
        (true, Some(on)) => done(on),
        (true, None) => Status::CheckYourself,
    };
    let today = today_ms.div_euclid(86_400_000);
    let security_update = match facts.security_patch.as_deref().and_then(day_number) {
        Some(patch) if patch - today > UPDATE_MAX_AHEAD_DAYS => Status::CheckYourself,
        Some(patch) => done(today - patch <= UPDATE_MAX_AGE_DAYS),
        None => Status::CheckYourself,
    };
    vec![
        Item {
            step: Step::AdvancedProtection,
            status: advanced_protection,
        },
        Item {
            step: Step::SecurityUpdate,
            status: security_update,
        },
        Item {
            step: Step::ScreenLock,
            status: done(facts.screen_lock),
        },
        Item {
            step: Step::UsbDebugging,
            status: done(!facts.usb_debugging),
        },
        // Android lets an app read only its own permission to install apps.
        Item {
            step: Step::UnknownApps,
            status: Status::CheckYourself,
        },
        // Which apps are used for messaging, and which are no longer used, only the
        // user knows.
        Item {
            step: Step::MessagingApps,
            status: Status::CheckYourself,
        },
    ]
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date, or `None` if it is not one.
fn day_number(date: &str) -> Option<i64> {
    let bytes = date.as_bytes();
    if !date.is_ascii() || bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = &date[range];
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    fn facts() -> Facts {
        Facts {
            advanced_protection_available: true,
            advanced_protection: Some(true),
            security_patch: Some("2026-10-05".to_owned()),
            screen_lock: true,
            usb_debugging: false,
        }
    }

    fn status(items: &[Item], step: Step) -> Status {
        items.iter().find(|item| item.step == step).unwrap().status
    }

    #[test]
    fn dates_count_days_from_1970() {
        assert_eq!(day_number("1970-01-01"), Some(0));
        assert_eq!(day_number("2000-03-01"), Some(11_017));
        assert_eq!(day_number("2026-10-16"), Some(20_742));
        for bad in ["2026-13-01", "2026-1-01", "2026/10/16", "", "2026-10-16T00"] {
            assert_eq!(day_number(bad), None, "{bad}");
        }
    }

    /// MS-12: every step, in order, with what could be read; the two the phone does not
    /// show are checks for the user.
    #[test]
    fn a_hardened_phone_has_every_readable_step_done() {
        let today = 20_742 * DAY;
        let items = checklist(&facts(), today);
        assert_eq!(
            items.iter().map(|item| item.step).collect::<Vec<_>>(),
            [
                Step::AdvancedProtection,
                Step::SecurityUpdate,
                Step::ScreenLock,
                Step::UsbDebugging,
                Step::UnknownApps,
                Step::MessagingApps,
            ]
        );
        assert_eq!(
            items.iter().map(|item| item.status).collect::<Vec<_>>(),
            [
                Status::Done,
                Status::Done,
                Status::Done,
                Status::Done,
                Status::CheckYourself,
                Status::CheckYourself,
            ]
        );
    }

    #[test]
    fn each_readable_step_can_be_left_to_do() {
        let today = 20_742 * DAY;
        let open = Facts {
            advanced_protection: Some(false),
            security_patch: Some("2026-07-17".to_owned()),
            screen_lock: false,
            usb_debugging: true,
            ..facts()
        };
        let items = checklist(&open, today);
        for step in [
            Step::AdvancedProtection,
            Step::SecurityUpdate,
            Step::ScreenLock,
            Step::UsbDebugging,
        ] {
            assert_eq!(status(&items, step), Status::ToDo, "{step:?}");
        }
        // 90 days old is still recent enough; 91 is not.
        let recent = Facts {
            security_patch: Some("2026-07-18".to_owned()),
            ..facts()
        };
        assert_eq!(
            status(&checklist(&recent, today), Step::SecurityUpdate),
            Status::Done
        );
    }

    /// Audit A-52: an update dated far past the phone's clock is not counted as done;
    /// one dated a month ahead, as some makers ship them, is.
    #[test]
    fn an_update_from_the_future_is_left_to_the_user() {
        let today = 20_742 * DAY;
        let update = |date: &str| {
            let facts = Facts {
                security_patch: Some(date.to_owned()),
                ..facts()
            };
            status(&checklist(&facts, today), Step::SecurityUpdate)
        };
        assert_eq!(update("2026-11-16"), Status::Done);
        assert_eq!(update("2026-11-17"), Status::CheckYourself);
        assert_eq!(update("2099-01-01"), Status::CheckYourself);
    }

    #[test]
    fn what_cannot_be_read_is_left_to_the_user() {
        let unknown = Facts {
            advanced_protection: None,
            security_patch: Some("unknown".to_owned()),
            ..facts()
        };
        let items = checklist(&unknown, 0);
        assert_eq!(
            status(&items, Step::AdvancedProtection),
            Status::CheckYourself
        );
        assert_eq!(status(&items, Step::SecurityUpdate), Status::CheckYourself);
        let old_android = Facts {
            advanced_protection_available: false,
            advanced_protection: None,
            ..facts()
        };
        assert_eq!(
            status(&checklist(&old_android, 0), Step::AdvancedProtection),
            Status::NotAvailable
        );
    }
}

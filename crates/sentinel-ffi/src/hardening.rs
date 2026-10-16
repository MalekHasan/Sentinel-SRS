// SPDX-License-Identifier: GPL-3.0-or-later
//! The hardening checklist (MS-12, ADR-0026), as seen from Kotlin.

use sentinel_detect::{Facts, Status, Step};

use crate::history::now_ms;

/// What the app could read about the phone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HardeningFacts {
    /// Whether this version of Android has Advanced Protection (Android 16 and later).
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

/// A step of the checklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HardeningStep {
    AdvancedProtection,
    SecurityUpdate,
    ScreenLock,
    UsbDebugging,
    UnknownApps,
    MessagingApps,
}

/// Where a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HardeningStatus {
    /// Done, as far as the phone shows.
    Done,
    /// Not done: the user can take this step.
    ToDo,
    /// The phone does not let the app read it: the user checks it.
    CheckYourself,
    /// This version of Android does not have it.
    NotAvailable,
}

/// One step of the checklist and where it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct HardeningItem {
    pub step: HardeningStep,
    pub status: HardeningStatus,
}

/// MS-12: the hardening checklist for a phone with `facts`, as of today, most
/// protection first.
#[uniffi::export]
pub fn hardening_checklist(facts: HardeningFacts) -> Vec<HardeningItem> {
    let facts = Facts {
        advanced_protection_available: facts.advanced_protection_available,
        advanced_protection: facts.advanced_protection,
        security_patch: facts.security_patch,
        screen_lock: facts.screen_lock,
        usb_debugging: facts.usb_debugging,
    };
    sentinel_detect::checklist(&facts, now_ms())
        .into_iter()
        .map(|item| HardeningItem {
            step: match item.step {
                Step::AdvancedProtection => HardeningStep::AdvancedProtection,
                Step::SecurityUpdate => HardeningStep::SecurityUpdate,
                Step::ScreenLock => HardeningStep::ScreenLock,
                Step::UsbDebugging => HardeningStep::UsbDebugging,
                Step::UnknownApps => HardeningStep::UnknownApps,
                Step::MessagingApps => HardeningStep::MessagingApps,
            },
            status: match item.status {
                Status::Done => HardeningStatus::Done,
                Status::ToDo => HardeningStatus::ToDo,
                Status::CheckYourself => HardeningStatus::CheckYourself,
                Status::NotAvailable => HardeningStatus::NotAvailable,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-12 across the boundary: today's date decides whether the update is recent.
    #[test]
    fn the_checklist_is_worked_out_as_of_today() {
        let today = now_ms().div_euclid(86_400_000);
        // The day `days_ago` days before today, as YYYY-MM-DD.
        let date = |days_ago: i64| {
            let (year, month, day) = civil(today - days_ago);
            format!("{year:04}-{month:02}-{day:02}")
        };
        let facts = |patch: String| HardeningFacts {
            advanced_protection_available: false,
            advanced_protection: None,
            security_patch: Some(patch),
            screen_lock: false,
            usb_debugging: true,
        };
        let items = hardening_checklist(facts(date(10)));
        assert_eq!(
            items,
            [
                HardeningItem {
                    step: HardeningStep::AdvancedProtection,
                    status: HardeningStatus::NotAvailable
                },
                HardeningItem {
                    step: HardeningStep::SecurityUpdate,
                    status: HardeningStatus::Done
                },
                HardeningItem {
                    step: HardeningStep::ScreenLock,
                    status: HardeningStatus::ToDo
                },
                HardeningItem {
                    step: HardeningStep::UsbDebugging,
                    status: HardeningStatus::ToDo
                },
                HardeningItem {
                    step: HardeningStep::UnknownApps,
                    status: HardeningStatus::CheckYourself
                },
                HardeningItem {
                    step: HardeningStep::MessagingApps,
                    status: HardeningStatus::CheckYourself
                },
            ]
        );
        assert_eq!(
            hardening_checklist(facts(date(200)))[1].status,
            HardeningStatus::ToDo
        );
    }

    /// Howard Hinnant's civil_from_days: the day `days` after 1970-01-01.
    fn civil(days: i64) -> (i64, i64, i64) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        (year, month, day)
    }
}

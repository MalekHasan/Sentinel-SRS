// SPDX-License-Identifier: GPL-3.0-or-later
//! The action journal (SRS §9, ADR-0018), as seen from Kotlin: each change the user made
//! to the firewall, and whether it can still be undone.

use sentinel_detect::Setting;
use sentinel_store::Undo;

use crate::firewall::{FirewallMode, FirewallRule};

/// One firewall setting, before or after an action.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum JournalState {
    /// The rule about one app and destination, by its key: `rule`, or none.
    Rule {
        key: String,
        rule: Option<FirewallRule>,
    },
    /// The firewall mode; `since_ms` is when Block new apps was turned on.
    Mode {
        mode: FirewallMode,
        since_ms: Option<i64>,
    },
    /// Isolation: since when it was on, or `None` when it was off.
    Isolation { since_ms: Option<i64> },
}

/// One action the user took (SRS §9).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JournalEntry {
    pub id: i64,
    /// When, Unix milliseconds.
    pub at_ms: i64,
    /// The alert the action was taken from, if any.
    pub alert_id: Option<i64>,
    pub before: JournalState,
    pub after: JournalState,
    /// When it was undone, if it was.
    pub undone_ms: Option<i64>,
    /// Whether undoing it now would put `before` back: it was not undone yet, and
    /// nothing changed its setting since.
    pub can_undo: bool,
}

/// What undoing an action did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UndoResult {
    /// The setting is back as it was before the action, in force from now on.
    Undone,
    /// It was undone before.
    AlreadyUndone,
    /// The setting was changed since; it was left as it is.
    ChangedSince,
    /// The action cannot be undone, or there is no such action.
    CannotUndo,
}

impl From<&Setting> for JournalState {
    fn from(setting: &Setting) -> Self {
        match setting {
            Setting::Rule { key, rule } => JournalState::Rule {
                key: key.clone(),
                rule: rule.clone().map(Into::into),
            },
            Setting::Mode(mode) => JournalState::Mode {
                mode: (*mode).into(),
                since_ms: match mode {
                    sentinel_detect::FirewallMode::Monitor => None,
                    sentinel_detect::FirewallMode::BlockUnknown { since } => Some(*since),
                },
            },
            Setting::Isolation(isolation) => JournalState::Isolation {
                since_ms: isolation.as_ref().map(|i| i.since),
            },
        }
    }
}

impl From<sentinel_store::JournalEntry> for JournalEntry {
    fn from(entry: sentinel_store::JournalEntry) -> Self {
        JournalEntry {
            id: entry.id,
            at_ms: entry.at,
            alert_id: entry.alert,
            before: entry.change.before().into(),
            after: entry.change.after().into(),
            undone_ms: entry.undone_at,
            can_undo: entry.can_undo,
        }
    }
}

impl From<Undo> for UndoResult {
    fn from(undo: Undo) -> Self {
        match undo {
            Undo::Undone => UndoResult::Undone,
            Undo::AlreadyUndone => UndoResult::AlreadyUndone,
            Undo::ChangedSince => UndoResult::ChangedSince,
            Undo::CannotUndo | Undo::NotFound => UndoResult::CannotUndo,
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! The action journal (SRS §9, ADR-0018): each change the user makes to the firewall,
//! kept as what it changed from and to, so that it can be undone.
//!
//! An action changes one [`Setting`]: the rule about one app and destination, the
//! firewall mode, or isolation. Undoing it puts that setting back as it was before, but
//! only while the setting is still as the action left it: once something else changed
//! it, undoing would overwrite that later change.

use serde::{Deserialize, Serialize};

use crate::{FirewallMode, FirewallRule, Isolation};

/// One setting of the firewall, in one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// The rule about what `key` names ([`FirewallRule::key`]): `rule`, or none.
    Rule {
        key: String,
        rule: Option<FirewallRule>,
    },
    Mode(FirewallMode),
    /// Network isolation, while on.
    Isolation(Option<Isolation>),
}

/// An action: one setting, before and after. The two states differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    before: Setting,
    after: Setting,
}

/// How a setting is stored in the journal's `before_state` and `after_state` columns.
#[derive(Serialize, Deserialize)]
#[serde(tag = "setting", rename_all = "snake_case", deny_unknown_fields)]
enum Stored {
    Rule {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<FirewallRule>,
    },
    Mode {
        mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
    },
    Isolation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        own_app: Option<String>,
    },
}

impl Setting {
    /// Whether `self` and `other` are states of the same setting.
    pub fn same_setting(&self, other: &Setting) -> bool {
        match (self, other) {
            (Setting::Rule { key, .. }, Setting::Rule { key: other, .. }) => key == other,
            (Setting::Mode(_), Setting::Mode(_)) => true,
            (Setting::Isolation(_), Setting::Isolation(_)) => true,
            _ => false,
        }
    }

    pub fn to_json(&self) -> String {
        let stored = match self {
            Setting::Rule { key, rule } => Stored::Rule {
                key: key.clone(),
                rule: rule.clone(),
            },
            Setting::Mode(mode) => Stored::Mode {
                mode: mode.id().to_owned(),
                since: match mode {
                    FirewallMode::Monitor => None,
                    FirewallMode::BlockUnknown { since } => Some(*since),
                },
            },
            Setting::Isolation(isolation) => Stored::Isolation {
                since: isolation.as_ref().map(|i| i.since),
                own_app: isolation.as_ref().map(|i| i.own_app.clone()),
            },
        };
        // Serializing this type cannot fail: strings, numbers and enums only.
        serde_json::to_string(&stored).unwrap_or_default()
    }

    /// A stored setting, checked: a rule must be valid and match its key, a mode must
    /// be one this version knows, and isolation has both its fields or neither.
    pub fn from_json(json: &str) -> Option<Setting> {
        match serde_json::from_str(json).ok()? {
            Stored::Rule { key, rule } => {
                let rule = match rule {
                    Some(rule) => Some(FirewallRule::from_json(&rule.to_json())?),
                    None => None,
                };
                if key.is_empty() || rule.as_ref().is_some_and(|rule| rule.key() != key) {
                    return None;
                }
                Some(Setting::Rule { key, rule })
            }
            Stored::Mode { mode, since } => {
                let mode = FirewallMode::from_id(&mode, since)?;
                if mode == FirewallMode::Monitor && since.is_some() {
                    return None;
                }
                Some(Setting::Mode(mode))
            }
            Stored::Isolation { since, own_app } => match (since, own_app) {
                (Some(since), Some(own_app)) => {
                    Some(Setting::Isolation(Some(Isolation { since, own_app })))
                }
                (None, None) => Some(Setting::Isolation(None)),
                _ => None,
            },
        }
    }
}

impl Change {
    /// The change from `before` to `after`: `None` when they are the same state, so
    /// that nothing changed, or states of different settings.
    pub fn new(before: Setting, after: Setting) -> Option<Change> {
        (before.same_setting(&after) && before != after).then_some(Change { before, after })
    }

    pub fn before(&self) -> &Setting {
        &self.before
    }

    pub fn after(&self) -> &Setting {
        &self.after
    }

    /// What the action did, as the journal's `action` column names it.
    pub fn action(&self) -> &'static str {
        match (&self.before, &self.after) {
            (_, Setting::Rule { rule: Some(_), .. }) => "keep_rule",
            (_, Setting::Rule { rule: None, .. }) => "remove_rule",
            (_, Setting::Mode(_)) => "set_mode",
            (_, Setting::Isolation(Some(_))) => "isolate",
            (_, Setting::Isolation(None)) => "end_isolation",
        }
    }

    /// The action that undoes this one: the same setting, from after back to before.
    pub fn undo(&self) -> Change {
        Change {
            before: self.after.clone(),
            after: self.before.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Destination, RuleAction};

    fn block_ads() -> FirewallRule {
        FirewallRule::new(
            Some("org.example.chat"),
            Some(Destination::domain("ads.example").unwrap()),
            RuleAction::Block,
        )
        .unwrap()
    }

    fn rule(rule: Option<FirewallRule>) -> Setting {
        Setting::Rule {
            key: block_ads().key(),
            rule,
        }
    }

    fn isolated(since: i64) -> Setting {
        Setting::Isolation(Some(Isolation {
            since,
            own_app: "io.github.malekhasan.sentinel".to_owned(),
        }))
    }

    /// The stored form is part of the history's format: fixed here, and read back.
    #[test]
    fn settings_are_stored_as_json() {
        let cases = [
            (
                rule(Some(block_ads())),
                r#"{"setting":"rule","key":"org.example.chat domain:ads.example","rule":{"app":"org.example.chat","destination":{"type":"domain","name":"ads.example"},"action":"block"}}"#,
            ),
            (
                rule(None),
                r#"{"setting":"rule","key":"org.example.chat domain:ads.example"}"#,
            ),
            (
                Setting::Mode(FirewallMode::Monitor),
                r#"{"setting":"mode","mode":"monitor"}"#,
            ),
            (
                Setting::Mode(FirewallMode::BlockUnknown { since: 5 }),
                r#"{"setting":"mode","mode":"block-unknown","since":5}"#,
            ),
            (
                isolated(7),
                r#"{"setting":"isolation","since":7,"own_app":"io.github.malekhasan.sentinel"}"#,
            ),
            (Setting::Isolation(None), r#"{"setting":"isolation"}"#),
        ];
        for (setting, json) in cases {
            assert_eq!(setting.to_json(), json);
            assert_eq!(Setting::from_json(json), Some(setting), "{json}");
        }
    }

    #[test]
    fn unreadable_settings_are_refused() {
        for bad in [
            "not json",
            r#"{"setting":"country"}"#,
            r#"{"setting":"rule","key":""}"#,
            // The rule is about something else than its key says.
            r#"{"setting":"rule","key":"* *","rule":{"app":"org.example.chat","destination":null,"action":"block"}}"#,
            // A rule that would be refused when made.
            r#"{"setting":"rule","key":"* *","rule":{"app":null,"destination":null,"action":"block"}}"#,
            r#"{"setting":"mode","mode":"lockdown"}"#,
            r#"{"setting":"mode","mode":"block-unknown"}"#,
            r#"{"setting":"mode","mode":"monitor","since":5}"#,
            r#"{"setting":"isolation","since":7}"#,
            r#"{"setting":"isolation","own_app":"io.github.malekhasan.sentinel"}"#,
            r#"{"setting":"isolation","extra":1}"#,
        ] {
            assert_eq!(Setting::from_json(bad), None, "{bad}");
        }
    }

    /// An action changes one setting; nothing is journalled when nothing changed.
    #[test]
    fn a_change_is_one_setting_from_one_state_to_another() {
        assert_eq!(Change::new(rule(None), rule(None)), None, "nothing changed");
        assert_eq!(Change::new(isolated(7), isolated(7)), None);
        let other_key = Setting::Rule {
            key: "* *".to_owned(),
            rule: None,
        };
        assert_eq!(Change::new(rule(None), other_key), None, "another rule");
        assert_eq!(
            Change::new(Setting::Mode(FirewallMode::Monitor), isolated(7)),
            None,
            "another setting"
        );
    }

    /// Each action has a name in the journal, and undoing it is the opposite action.
    #[test]
    fn each_action_is_named_and_undone_by_its_opposite() {
        let allow_ads = FirewallRule {
            action: RuleAction::Allow,
            ..block_ads()
        };
        let monitor = Setting::Mode(FirewallMode::Monitor);
        let block_new = Setting::Mode(FirewallMode::BlockUnknown { since: 5 });
        let cases = [
            (
                rule(None),
                rule(Some(block_ads())),
                "keep_rule",
                "remove_rule",
            ),
            (
                rule(Some(block_ads())),
                rule(Some(allow_ads)),
                "keep_rule",
                "keep_rule",
            ),
            (
                rule(Some(block_ads())),
                rule(None),
                "remove_rule",
                "keep_rule",
            ),
            (monitor, block_new, "set_mode", "set_mode"),
            (
                Setting::Isolation(None),
                isolated(7),
                "isolate",
                "end_isolation",
            ),
        ];
        for (before, after, action, undo) in cases {
            let change = Change::new(before.clone(), after.clone()).unwrap();
            assert_eq!(change.action(), action);
            assert_eq!((change.before(), change.after()), (&before, &after));
            let undone = change.undo();
            assert_eq!(undone.action(), undo);
            assert_eq!((undone.before(), undone.after()), (&after, &before));
        }
    }
}

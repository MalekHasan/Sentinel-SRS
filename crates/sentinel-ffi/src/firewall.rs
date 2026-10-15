// SPDX-License-Identifier: GPL-3.0-or-later
//! Firewall rules (SRS CM-10) as seen from Kotlin. The core decides with them; see
//! ADR-0015.

use sentinel_detect::{Destination, Network};

use crate::history::HistoryError;

/// What a rule does with what it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RuleAction {
    Allow,
    Block,
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RuleDestination {
    /// A domain and every name below it.
    Domain { name: String },
    /// One address (`192.0.2.1`) or a range (`192.0.2.0/24`, `2001:db8::/32`).
    Network { range: String },
}

/// One firewall rule: an app, a destination, or both.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FirewallRule {
    /// The app, by package name; `None` for every app.
    pub app: Option<String>,
    /// Where; `None` for everywhere.
    pub destination: Option<RuleDestination>,
    pub action: RuleAction,
}

/// A rule as stored.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HistoryRule {
    /// What the rule is about; a new rule about the same app and destination replaces
    /// it, and removing a rule takes this key.
    pub key: String,
    pub rule: FirewallRule,
    /// When it was made or last changed.
    pub created_ms: i64,
}

impl TryFrom<FirewallRule> for sentinel_detect::FirewallRule {
    type Error = HistoryError;

    fn try_from(rule: FirewallRule) -> Result<Self, HistoryError> {
        let bad = |e: sentinel_detect::RuleError| HistoryError::BadRule {
            reason: e.to_string(),
        };
        let destination = match rule.destination {
            Some(RuleDestination::Domain { name }) => {
                Some(Destination::domain(&name).map_err(bad)?)
            }
            Some(RuleDestination::Network { range }) => {
                Some(Destination::network(&range).map_err(bad)?)
            }
            None => None,
        };
        let action = match rule.action {
            RuleAction::Allow => sentinel_detect::RuleAction::Allow,
            RuleAction::Block => sentinel_detect::RuleAction::Block,
        };
        sentinel_detect::FirewallRule::new(rule.app.as_deref(), destination, action).map_err(bad)
    }
}

impl From<sentinel_detect::FirewallRule> for FirewallRule {
    fn from(rule: sentinel_detect::FirewallRule) -> Self {
        FirewallRule {
            app: rule.app,
            destination: rule.destination.map(|destination| match destination {
                Destination::Domain { name } => RuleDestination::Domain { name },
                Destination::Network { network } => RuleDestination::Network {
                    range: Network::to_string(&network),
                },
            }),
            action: match rule.action {
                sentinel_detect::RuleAction::Allow => RuleAction::Allow,
                sentinel_detect::RuleAction::Block => RuleAction::Block,
            },
        }
    }
}

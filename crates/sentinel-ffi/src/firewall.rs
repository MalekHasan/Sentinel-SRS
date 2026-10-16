// SPDX-License-Identifier: GPL-3.0-or-later
//! Firewall rules (SRS CM-10) as seen from Kotlin. The core decides with them; see
//! ADR-0015.

use sentinel_detect::{Destination, Network};

use crate::history::HistoryError;

/// What the firewall does with what no rule matches (CM-08, ADR-0016).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FirewallMode {
    /// Only the rules block.
    Monitor,
    /// Apps installed since this mode was turned on are blocked until a rule allows
    /// them.
    BlockUnknown,
}

impl From<sentinel_detect::FirewallMode> for FirewallMode {
    fn from(mode: sentinel_detect::FirewallMode) -> Self {
        match mode {
            sentinel_detect::FirewallMode::Monitor => FirewallMode::Monitor,
            sentinel_detect::FirewallMode::BlockUnknown { .. } => FirewallMode::BlockUnknown,
        }
    }
}

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
    /// Every name the tracker list gives this company, as the list spells it (RA-01).
    Company { name: String },
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

/// Whether an app may use the network as a whole (RA-01, CM-08), for the app detail
/// screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct AppAccess {
    /// The rule about the app as a whole, if there is one.
    pub rule: Option<RuleAction>,
    /// Block-unknown keeps it off the network for being new, and no rule is about it.
    pub blocked_as_new: bool,
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
            Some(RuleDestination::Company { name }) => {
                Some(Destination::company(&name).map_err(bad)?)
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

impl From<sentinel_detect::RuleAction> for RuleAction {
    fn from(action: sentinel_detect::RuleAction) -> Self {
        match action {
            sentinel_detect::RuleAction::Allow => RuleAction::Allow,
            sentinel_detect::RuleAction::Block => RuleAction::Block,
        }
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
                Destination::Company { company } => RuleDestination::Company { name: company },
            }),
            action: rule.action.into(),
        }
    }
}

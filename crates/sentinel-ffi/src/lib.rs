// SPDX-License-Identifier: GPL-3.0-or-later
//! The Sentinel core as seen from Kotlin.
//!
//! The API grows with Phase A: engine control, flow events and the encrypted history
//! now, then alerts.

mod access;
mod alerts;
mod apps;
mod engine;
mod enrich;
mod feed;
mod firewall;
mod flows;
mod hardening;
mod history;
mod hunt;
mod journal;
mod posture;
mod sensors;

pub use access::{AccessCheck, HeldAccess};
pub use alerts::{
    AlertAction, AlertDelivery, AlertEvidence, AlertFeedback, AlertListener, AlertRule,
    AlertSeverity, AllowedRule, HistoryAlert, RemoteAccessService, SensorKind, SpecialAccess,
};
pub use apps::{AppCheck, InstalledApp};
pub use engine::{Engine, EngineError, EngineListener, EngineSnapshot, SocketProtector};
pub use enrich::{
    CategoryFact, CompanyFact, IpDatabase, IpDatabaseError, IpSources, TrackerDatabase,
    TrackerDatabaseError,
};
pub use feed::{
    Feed, FeedFailure, FeedFile, FeedOffer, FeedSource, FeedStatus, trusted_feed_keys,
    trusted_feed_threshold,
};
pub use firewall::{FirewallRule, HistoryRule, RuleAction, RuleDestination};
pub use flows::{FlowObserver, FlowOwner, FlowProto, FlowRecord, LiveApp, NameSource};
pub use hardening::{
    HardeningFacts, HardeningItem, HardeningStatus, HardeningStep, hardening_checklist,
};
pub use history::{
    HistoryApp, HistoryAway, HistoryCompany, HistoryDestination, HistoryError, HistoryFlow,
    HistoryGap, HistoryStore, wipe_history,
};
pub use hunt::{HuntReport, KnownTraces};
pub use journal::{JournalEntry, JournalState, UndoResult};
pub use posture::{DevicePosture, UserCertificate};
pub use sensors::SensorUse;

uniffi::setup_scaffolding!();

/// Version of the Rust core, shown on the app's about screen.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// The TLS server name in the first bytes of a connection, if there is one.
///
/// Exported so the Android tests can check that the engine code runs on the device.
#[uniffi::export]
pub fn server_name_from_client_hello(first_bytes: Vec<u8>) -> Option<String> {
    match sentinel_vpn::scan_client_hello(&first_bytes) {
        sentinel_vpn::ClientHelloScan::Done(name) => name,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        assert!(!core_version().is_empty());
    }

    #[test]
    fn non_tls_has_no_server_name() {
        assert_eq!(
            server_name_from_client_hello(b"GET / HTTP/1.1\r\n".to_vec()),
            None
        );
    }
}

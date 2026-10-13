// SPDX-License-Identifier: GPL-3.0-or-later
//! The Sentinel core as seen from Kotlin.
//!
//! A0 Spike 2: proves the path Rust → UniFFI → Kotlin → Android app works on every
//! supported ABI. The real API (engine control, flows, alerts) grows from here in Phase A.

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

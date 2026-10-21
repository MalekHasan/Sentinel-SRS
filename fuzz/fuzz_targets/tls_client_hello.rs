// SPDX-License-Identifier: GPL-3.0-or-later
//! The TLS server name scanner (CM-02) on whatever an app sends first on a connection.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_vpn::{ClientHelloScan, MAX_HELLO, scan_client_hello};

fuzz_target!(|data: &[u8]| {
    match scan_client_hello(data) {
        ClientHelloScan::NeedMore { total } => {
            assert!(total > data.len(), "asks for no more than it has");
            assert!(total <= MAX_HELLO, "asks for {total} bytes");
        }
        ClientHelloScan::Done(Some(name)) => {
            assert!(!name.is_empty() && name.len() <= 253);
            assert!(!name.ends_with('.'));
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b)),
                "{name:?}"
            );
            assert!(
                name.split('.')
                    .all(|label| !label.is_empty() && label.len() <= 63)
            );
        }
        ClientHelloScan::Done(None) | ClientHelloScan::NotTls | ClientHelloScan::Unreadable => {}
    }
});

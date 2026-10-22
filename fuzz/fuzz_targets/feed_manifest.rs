// SPDX-License-Identifier: GPL-3.0-or-later
//! The indicator feed's signed envelope and its manifest (ADR-0005), as downloaded or
//! imported from a folder, before any signature is checked (audit A-49).
#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_feed::{Envelope, Manifest};

fuzz_target!(|data: &[u8]| {
    // A manifest it reads, it writes and reads back the same.
    if let Ok(manifest) = Manifest::from_json(data) {
        let again = Manifest::from_json(&manifest.to_json()).expect("its own manifest reads back");
        assert_eq!(again, manifest);
        assert_eq!(again.files_digest(), manifest.files_digest());
    }
    if let Ok(envelope) = Envelope::from_json(data) {
        let _ = envelope.payload_bytes();
    }
});

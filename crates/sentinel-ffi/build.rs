// SPDX-License-Identifier: GPL-3.0-or-later
//! Compiles the indicator feed's trust root into the library: the public key in every
//! `keys/feed/*.pub` file of the repository (ADR-0005, ADR-0019, docs/FEED-SIGNING.md).
//! Adding a key is a reviewed commit of its `.pub` file; a file that does not hold a key
//! fails the build.

use std::path::Path;
use std::{env, fs};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR");
    let dir = Path::new(&manifest_dir).join("../../keys/feed");
    println!("cargo::rerun-if-changed={}", dir.display());
    let mut keys = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "pub") {
                continue;
            }
            println!("cargo::rerun-if-changed={}", path.display());
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let key = text.trim();
            assert!(
                key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
                "{} must hold one public key: 64 hex characters, as `sentinel-feed-tool keygen` writes it",
                path.display()
            );
            keys.push(key.to_ascii_lowercase());
        }
    }
    keys.sort();
    let out = Path::new(&env::var("OUT_DIR").expect("Cargo sets OUT_DIR")).join("trusted_keys.rs");
    fs::write(&out, format!("const TRUSTED_KEYS: &[&str] = &{keys:?};\n"))
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out.display()));
}

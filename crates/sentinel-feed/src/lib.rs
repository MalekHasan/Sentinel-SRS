// SPDX-License-Identifier: GPL-3.0-or-later
//! Signed indicator-feed bundles (SRS MS-10, §14.3).
//!
//! A bundle is a directory holding data files plus `manifest.dsse.json`. The manifest
//! lists every file with its SHA-256 and size, and carries the feed name, a version that
//! only goes up, and an expiry time. It is wrapped in a [DSSE] envelope and signed with
//! Ed25519 keys that are kept offline. See `docs/adr/0005-signed-feed-format.md`.
//!
//! Checks performed:
//!
//! - signature by at least `threshold` distinct trusted keys (strict Ed25519 verification);
//! - payload type, schema version and feed name;
//! - rollback: an update must have a higher version than the installed bundle;
//! - freeze: an update must not be expired, and must not claim to be created in the future;
//! - every listed file has the expected size and SHA-256;
//! - every listed path is a plain relative path, so a bundle cannot write outside its folder.
//!
//! [DSSE]: https://github.com/secure-systems-lab/dsse

mod envelope;
mod error;
mod manifest;
mod sign;
mod trust;
mod verify;

pub use envelope::{Envelope, EnvelopeSignature, PAYLOAD_TYPE};
pub use error::FeedError;
pub use manifest::{FileEntry, MANIFEST_SCHEMA, Manifest};
pub use sign::{SecretKey, sign_manifest};
pub use trust::{KeyId, TrustRoot};
pub use verify::{
    Freshness, UpdatePolicy, VerifiedManifest, verify_installed, verify_update, verify_update_dir,
};

/// File name of the signed manifest inside a bundle directory.
pub const MANIFEST_FILE: &str = "manifest.dsse.json";

/// Largest envelope we are willing to parse. Real manifests are a few kilobytes.
pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

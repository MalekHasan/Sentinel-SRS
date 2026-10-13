// SPDX-License-Identifier: GPL-3.0-or-later

use thiserror::Error;

/// Every way a bundle can be rejected. Callers show these to users only as
/// "the indicator update could not be verified", and log the detail locally.
#[derive(Debug, Error)]
pub enum FeedError {
    #[error("envelope is larger than {max} bytes")]
    TooLarge { max: usize },
    #[error("envelope or manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("envelope field is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("unexpected payload type {0:?}")]
    PayloadType(String),
    #[error("not enough valid signatures from trusted keys: {valid} of {required}")]
    Signatures { valid: usize, required: usize },
    #[error("unsupported manifest schema {0}")]
    Schema(u32),
    #[error("manifest is for feed {found:?}, expected {expected:?}")]
    FeedName { expected: String, found: String },
    #[error("version {found} is not newer than installed version {installed}")]
    Rollback { installed: u64, found: u64 },
    #[error("version {found} does not match the installed version {expected}")]
    VersionMismatch { expected: u64, found: u64 },
    #[error("manifest expired at {expires} (now {now})")]
    Expired { expires: u64, now: u64 },
    #[error("manifest claims to be created at {created}, which is in the future (now {now})")]
    CreatedInFuture { created: u64, now: u64 },
    #[error("manifest expires ({expires}) before it was created ({created})")]
    BadValidity { created: u64, expires: u64 },
    #[error("invalid file path in manifest: {0:?}")]
    BadPath(String),
    #[error("file listed twice in manifest: {0:?}")]
    DuplicatePath(String),
    #[error("manifest lists {count} files, more than the limit of {max}")]
    TooManyFiles { count: usize, max: usize },
    #[error("invalid SHA-256 in manifest for {0:?}")]
    BadDigest(String),
    #[error("file {path:?} has size {found}, expected {expected}")]
    SizeMismatch {
        path: String,
        expected: u64,
        found: u64,
    },
    #[error("file {0:?} does not match its SHA-256")]
    DigestMismatch(String),
    #[error("file {0:?} is not listed in the manifest")]
    NotListed(String),
    #[error("invalid key: {0}")]
    BadKey(String),
    #[error("I/O error on {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

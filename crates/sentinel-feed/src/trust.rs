// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::FeedError;

/// Identifier of a public key: lowercase hex SHA-256 of its 32 raw bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn of(key: &VerifyingKey) -> Self {
        KeyId(hex::encode(Sha256::digest(key.as_bytes())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

/// The public keys an app trusts for one feed, and how many must sign.
///
/// The keys are compiled into the app. Rotating them needs an app update; see ADR-0005.
#[derive(Debug, Clone)]
pub struct TrustRoot {
    keys: Vec<(KeyId, VerifyingKey)>,
    threshold: usize,
}

impl TrustRoot {
    pub fn new(keys: Vec<VerifyingKey>, threshold: usize) -> Result<Self, FeedError> {
        let mut unique: Vec<(KeyId, VerifyingKey)> = Vec::new();
        for key in keys {
            let id = KeyId::of(&key);
            if !unique.iter().any(|(existing, _)| *existing == id) {
                unique.push((id, key));
            }
        }
        if threshold == 0 || threshold > unique.len() {
            return Err(FeedError::BadKey(format!(
                "threshold {threshold} is impossible with {} distinct keys",
                unique.len()
            )));
        }
        Ok(TrustRoot {
            keys: unique,
            threshold,
        })
    }

    /// Parse public keys written as 64 hex characters (see `sentinel-feed-tool keygen`).
    pub fn from_hex_keys<S: AsRef<str>>(keys: &[S], threshold: usize) -> Result<Self, FeedError> {
        let parsed = keys
            .iter()
            .map(|k| parse_public_key_hex(k.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(parsed, threshold)
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub(crate) fn keys(&self) -> &[(KeyId, VerifyingKey)] {
        &self.keys
    }
}

pub(crate) fn parse_public_key_hex(text: &str) -> Result<VerifyingKey, FeedError> {
    let bytes: [u8; 32] = hex::decode(text.trim())
        .map_err(|e| FeedError::BadKey(e.to_string()))?
        .try_into()
        .map_err(|_| FeedError::BadKey("public key must be 32 bytes".into()))?;
    // Rejects encodings that are not points on the curve.
    let key = VerifyingKey::from_bytes(&bytes).map_err(|e| FeedError::BadKey(e.to_string()))?;
    if key.is_weak() {
        return Err(FeedError::BadKey("weak public key".into()));
    }
    Ok(key)
}

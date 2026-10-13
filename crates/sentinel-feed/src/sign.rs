// SPDX-License-Identifier: GPL-3.0-or-later
//! Signing. Runs only on the offline signing machine (see `docs/FEED-SIGNING.md`).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::envelope::{encode, pae};
use crate::{Envelope, EnvelopeSignature, FeedError, KeyId, Manifest, PAYLOAD_TYPE};

/// An Ed25519 signing key. The 32-byte seed is wiped from memory on drop.
pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecretKey(SigningKey::from_bytes(&seed))
    }

    /// Parse a key file written by `sentinel-feed-tool keygen`: 64 hex characters.
    pub fn from_hex(text: &str) -> Result<Self, FeedError> {
        let mut seed: [u8; 32] = hex::decode(text.trim())
            .map_err(|e| FeedError::BadKey(e.to_string()))?
            .try_into()
            .map_err(|_| FeedError::BadKey("secret key must be 32 bytes".into()))?;
        let key = Self::from_seed(seed);
        seed.fill(0);
        Ok(key)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public().as_bytes())
    }

    pub fn key_id(&self) -> KeyId {
        KeyId::of(&self.public())
    }
}

/// Sign the exact manifest bytes with each key and return the envelope.
///
/// The bytes are validated first, so a malformed manifest is never signed.
pub fn sign_manifest(manifest_json: &[u8], keys: &[&SecretKey]) -> Result<Envelope, FeedError> {
    Manifest::from_json(manifest_json)?;
    let message = pae(PAYLOAD_TYPE, manifest_json);
    let signatures = keys
        .iter()
        .map(|key| EnvelopeSignature {
            keyid: key.key_id().to_string(),
            sig: encode(&key.0.sign(&message).to_bytes()),
        })
        .collect();
    Ok(Envelope {
        payload_type: PAYLOAD_TYPE.to_owned(),
        payload: encode(manifest_json),
        signatures,
    })
}

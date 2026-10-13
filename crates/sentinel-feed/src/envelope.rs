// SPDX-License-Identifier: GPL-3.0-or-later
//! DSSE envelope (Dead Simple Signing Envelope, v1).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::{FeedError, MAX_ENVELOPE_BYTES};

/// Payload type of a Sentinel feed manifest. Signatures cover this string, so a
/// signature made for any other kind of document cannot be replayed as a manifest.
pub const PAYLOAD_TYPE: &str = "application/vnd.sentinel.feed-manifest+json; version=1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 (standard alphabet, padded) of the manifest JSON bytes.
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSignature {
    /// Hint only; it is not covered by the signature. See [`crate::KeyId`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    /// Base64 of the 64-byte Ed25519 signature over [`pae`].
    pub sig: String,
}

impl Envelope {
    pub fn from_json(bytes: &[u8]) -> Result<Self, FeedError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(FeedError::TooLarge {
                max: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn to_json(&self) -> Vec<u8> {
        // Serialising plain strings cannot fail.
        let mut out = serde_json::to_vec_pretty(self).unwrap_or_default();
        out.push(b'\n');
        out
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, FeedError> {
        Ok(STANDARD.decode(&self.payload)?)
    }
}

/// DSSE pre-authentication encoding: the exact bytes that are signed.
///
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, lengths in ASCII decimal.
pub(crate) fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_spec_example() {
        // Example from the DSSE protocol specification.
        let got = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            got,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn rejects_oversized_envelope() {
        let big = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            Envelope::from_json(&big),
            Err(FeedError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = br#"{"payloadType":"x","payload":"","signatures":[],"extra":1}"#;
        assert!(matches!(Envelope::from_json(json), Err(FeedError::Json(_))));
    }
}

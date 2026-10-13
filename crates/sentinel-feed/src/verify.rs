// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};

use crate::envelope::pae;
use crate::{Envelope, FeedError, KeyId, MANIFEST_FILE, Manifest, PAYLOAD_TYPE, TrustRoot};

/// What the caller knows when deciding whether to accept a downloaded or imported bundle.
#[derive(Debug, Clone)]
pub struct UpdatePolicy {
    /// Expected feed name, e.g. `sentinel-indicators`.
    pub feed: String,
    /// Version currently installed, if any. An update must be strictly newer.
    pub installed_version: Option<u64>,
    /// Current time, Unix seconds.
    pub now: u64,
    /// How far in the future `created` may be, to tolerate a slightly wrong device clock.
    pub max_clock_skew: u64,
}

/// Whether an installed bundle is still within its validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Current,
    /// The list still works, but the app must tell the user it is out of date (MS-15).
    Expired {
        since: u64,
    },
}

/// A manifest whose signatures and metadata have been checked.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: Manifest,
    signed_by: Vec<KeyId>,
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn signed_by(&self) -> &[KeyId] {
        &self.signed_by
    }

    pub fn freshness(&self, now: u64) -> Freshness {
        if now >= self.manifest.expires {
            Freshness::Expired {
                since: self.manifest.expires,
            }
        } else {
            Freshness::Current
        }
    }

    /// Check one file's contents against the manifest.
    pub fn check_file(&self, path: &str, contents: &[u8]) -> Result<(), FeedError> {
        let entry = self
            .manifest
            .file(path)
            .ok_or_else(|| FeedError::NotListed(path.to_owned()))?;
        if contents.len() as u64 != entry.size {
            return Err(FeedError::SizeMismatch {
                path: path.to_owned(),
                expected: entry.size,
                found: contents.len() as u64,
            });
        }
        if hex::encode(Sha256::digest(contents)) != entry.sha256 {
            return Err(FeedError::DigestMismatch(path.to_owned()));
        }
        Ok(())
    }

    /// Check every listed file under `dir`. Files that are not listed are ignored and
    /// must never be used. Symbolic links are rejected.
    pub fn check_dir(&self, dir: &Path) -> Result<(), FeedError> {
        for entry in &self.manifest.files {
            let path = dir.join(&entry.path);
            let io_err = |source| FeedError::Io {
                path: entry.path.clone(),
                source,
            };
            let meta = fs::symlink_metadata(&path).map_err(io_err)?;
            if !meta.is_file() {
                return Err(FeedError::BadPath(entry.path.clone()));
            }
            if meta.len() != entry.size {
                return Err(FeedError::SizeMismatch {
                    path: entry.path.clone(),
                    expected: entry.size,
                    found: meta.len(),
                });
            }
            let mut contents = Vec::with_capacity(entry.size as usize);
            fs::File::open(&path)
                .and_then(|f| f.take(entry.size + 1).read_to_end(&mut contents))
                .map_err(io_err)?;
            self.check_file(&entry.path, &contents)?;
        }
        Ok(())
    }
}

/// Verify a new bundle before installing it: signatures, feed name, rollback, freshness.
pub fn verify_update(
    envelope_json: &[u8],
    trust: &TrustRoot,
    policy: &UpdatePolicy,
) -> Result<VerifiedManifest, FeedError> {
    let verified = verify_signed(envelope_json, trust, &policy.feed)?;
    let m = &verified.manifest;
    if let Some(installed) = policy.installed_version
        && m.version <= installed
    {
        return Err(FeedError::Rollback {
            installed,
            found: m.version,
        });
    }
    if m.created > policy.now.saturating_add(policy.max_clock_skew) {
        return Err(FeedError::CreatedInFuture {
            created: m.created,
            now: policy.now,
        });
    }
    if policy.now >= m.expires {
        return Err(FeedError::Expired {
            expires: m.expires,
            now: policy.now,
        });
    }
    Ok(verified)
}

/// Re-verify the bundle that is already installed (at start and every hour, SRS SP-04).
///
/// Expiry is not an error here: an old list is better than none. Use
/// [`VerifiedManifest::freshness`] to warn the user.
pub fn verify_installed(
    envelope_json: &[u8],
    trust: &TrustRoot,
    feed: &str,
    expected_version: u64,
) -> Result<VerifiedManifest, FeedError> {
    let verified = verify_signed(envelope_json, trust, feed)?;
    if verified.manifest.version != expected_version {
        return Err(FeedError::VersionMismatch {
            expected: expected_version,
            found: verified.manifest.version,
        });
    }
    Ok(verified)
}

/// Read `manifest.dsse.json` from a bundle directory.
pub(crate) fn read_envelope(dir: &Path) -> Result<Vec<u8>, FeedError> {
    let path = dir.join(MANIFEST_FILE);
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .and_then(|f| {
            f.take(crate::MAX_ENVELOPE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|source| FeedError::Io {
            path: MANIFEST_FILE.to_owned(),
            source,
        })?;
    Ok(bytes)
}

fn verify_signed(
    envelope_json: &[u8],
    trust: &TrustRoot,
    feed: &str,
) -> Result<VerifiedManifest, FeedError> {
    let envelope = Envelope::from_json(envelope_json)?;
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(FeedError::PayloadType(envelope.payload_type));
    }
    let payload = envelope.payload_bytes()?;
    let message = pae(&envelope.payload_type, &payload);

    // Count each trusted key at most once, whatever the keyid hints say.
    let mut signed_by: Vec<KeyId> = Vec::new();
    let mut seen: HashSet<KeyId> = HashSet::new();
    for sig in &envelope.signatures {
        let Ok(bytes) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig.sig)
        else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&bytes) else {
            continue;
        };
        for (id, key) in trust.keys() {
            if seen.contains(id) || (!sig.keyid.is_empty() && sig.keyid != id.as_str()) {
                continue;
            }
            if key.verify_strict(&message, &signature).is_ok() {
                seen.insert(id.clone());
                signed_by.push(id.clone());
                break;
            }
        }
    }
    if signed_by.len() < trust.threshold() {
        return Err(FeedError::Signatures {
            valid: signed_by.len(),
            required: trust.threshold(),
        });
    }

    // Only parse the manifest once it is known to be signed.
    let manifest = Manifest::from_json(&payload)?;
    if manifest.feed != feed {
        return Err(FeedError::FeedName {
            expected: feed.to_owned(),
            found: manifest.feed,
        });
    }
    Ok(VerifiedManifest {
        manifest,
        signed_by,
    })
}

/// Verify a whole bundle directory as an update: manifest, signatures, then every file.
pub fn verify_update_dir(
    dir: &Path,
    trust: &TrustRoot,
    policy: &UpdatePolicy,
) -> Result<VerifiedManifest, FeedError> {
    let verified = verify_update(&read_envelope(dir)?, trust, policy)?;
    verified.check_dir(dir)?;
    Ok(verified)
}

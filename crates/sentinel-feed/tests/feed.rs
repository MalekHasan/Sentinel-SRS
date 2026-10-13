// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end checks for the signed feed (SRS MS-10: "Feed signature and provenance
//! checked on load"; §14.3: version and rollback protection).

// Helpers outside #[test] functions unwrap too; a failure there should fail the test.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

use sentinel_feed::{
    Envelope, FeedError, FileEntry, Freshness, MANIFEST_FILE, MANIFEST_SCHEMA, Manifest, SecretKey,
    TrustRoot, UpdatePolicy, sign_manifest, verify_installed, verify_update, verify_update_dir,
};
use sha2::{Digest, Sha256};

const FEED: &str = "sentinel-indicators";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn entry(path: &str, contents: &[u8]) -> FileEntry {
    FileEntry {
        path: path.into(),
        sha256: hex::encode(Sha256::digest(contents)),
        size: contents.len() as u64,
    }
}

fn manifest(version: u64, files: Vec<FileEntry>) -> Manifest {
    Manifest {
        schema: MANIFEST_SCHEMA,
        feed: FEED.into(),
        version,
        created: NOW - DAY,
        expires: NOW + 13 * DAY,
        files,
    }
}

fn policy(installed: Option<u64>) -> UpdatePolicy {
    UpdatePolicy {
        feed: FEED.into(),
        installed_version: installed,
        now: NOW,
        max_clock_skew: 3600,
    }
}

fn trust(keys: &[&SecretKey], threshold: usize) -> TrustRoot {
    TrustRoot::new(keys.iter().map(|k| k.public()).collect(), threshold).unwrap()
}

fn signed(m: &Manifest, keys: &[&SecretKey]) -> Vec<u8> {
    sign_manifest(&m.to_json(), keys).unwrap().to_json()
}

#[test]
fn accepts_a_correctly_signed_update() {
    let k = key(1);
    let env = signed(&manifest(5, vec![]), &[&k]);
    let v = verify_update(&env, &trust(&[&k], 1), &policy(Some(4))).unwrap();
    assert_eq!(v.manifest().version, 5);
    assert_eq!(v.signed_by(), &[k.key_id()]);
    assert_eq!(v.freshness(NOW), Freshness::Current);
}

#[test]
fn rejects_signature_from_untrusted_key() {
    let env = signed(&manifest(5, vec![]), &[&key(2)]);
    let err = verify_update(&env, &trust(&[&key(1)], 1), &policy(None)).unwrap_err();
    assert!(matches!(
        err,
        FeedError::Signatures {
            valid: 0,
            required: 1
        }
    ));
}

#[test]
fn rejects_modified_payload() {
    let k = key(1);
    let mut env: Envelope = serde_json::from_slice(&signed(&manifest(5, vec![]), &[&k])).unwrap();
    // Re-encode a different, valid manifest under the old signature.
    let other = manifest(6, vec![]);
    env.payload = base64_encode(&other.to_json());
    let err = verify_update(&env.to_json(), &trust(&[&k], 1), &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::Signatures { valid: 0, .. }));
}

#[test]
fn rejects_wrong_payload_type_even_if_signed() {
    let k = key(1);
    let mut env: Envelope = serde_json::from_slice(&signed(&manifest(5, vec![]), &[&k])).unwrap();
    env.payload_type = "application/json".into();
    let err = verify_update(&env.to_json(), &trust(&[&k], 1), &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::PayloadType(_)));
}

#[test]
fn threshold_counts_each_key_once() {
    let (a, b) = (key(1), key(2));
    let root = trust(&[&a, &b], 2);
    // The same key twice does not meet a threshold of two.
    let env = signed(&manifest(5, vec![]), &[&a, &a]);
    let err = verify_update(&env, &root, &policy(None)).unwrap_err();
    assert!(matches!(
        err,
        FeedError::Signatures {
            valid: 1,
            required: 2
        }
    ));
    // Two different trusted keys do.
    let env = signed(&manifest(5, vec![]), &[&a, &b]);
    assert!(verify_update(&env, &root, &policy(None)).is_ok());
}

#[test]
fn ignores_misleading_keyid_hints() {
    let (a, b) = (key(1), key(2));
    let mut env: Envelope = serde_json::from_slice(&signed(&manifest(5, vec![]), &[&a])).unwrap();
    env.signatures[0].keyid = b.key_id().to_string();
    // The hint points at b, the signature is a's: it must not count for either.
    let err = verify_update(&env.to_json(), &trust(&[&a, &b], 1), &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::Signatures { valid: 0, .. }));
}

#[test]
fn rejects_rollback_and_replay() {
    let k = key(1);
    let root = trust(&[&k], 1);
    let env = signed(&manifest(5, vec![]), &[&k]);
    assert!(matches!(
        verify_update(&env, &root, &policy(Some(5))),
        Err(FeedError::Rollback {
            installed: 5,
            found: 5
        })
    ));
    assert!(matches!(
        verify_update(&env, &root, &policy(Some(9))),
        Err(FeedError::Rollback {
            installed: 9,
            found: 5
        })
    ));
}

#[test]
fn rejects_expired_and_future_updates() {
    let k = key(1);
    let root = trust(&[&k], 1);

    let mut m = manifest(5, vec![]);
    m.created = NOW - 30 * DAY;
    m.expires = NOW - DAY;
    let err = verify_update(&signed(&m, &[&k]), &root, &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::Expired { .. }));

    let mut m = manifest(5, vec![]);
    m.created = NOW + 2 * 3600;
    let err = verify_update(&signed(&m, &[&k]), &root, &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::CreatedInFuture { .. }));
}

#[test]
fn rejects_bundle_for_another_feed() {
    let k = key(1);
    let mut m = manifest(5, vec![]);
    m.feed = "sentinel-trackers".into();
    let err = verify_update(&signed(&m, &[&k]), &trust(&[&k], 1), &policy(None)).unwrap_err();
    assert!(matches!(err, FeedError::FeedName { .. }));
}

#[test]
fn installed_bundle_stays_usable_after_expiry_but_reports_it() {
    let k = key(1);
    let env = signed(&manifest(5, vec![]), &[&k]);
    let v = verify_installed(&env, &trust(&[&k], 1), FEED, 5).unwrap();
    let later = NOW + 30 * DAY;
    assert!(matches!(v.freshness(later), Freshness::Expired { .. }));
    assert!(matches!(
        verify_installed(&env, &trust(&[&k], 1), FEED, 4),
        Err(FeedError::VersionMismatch { .. })
    ));
}

#[test]
fn signing_refuses_an_invalid_manifest() {
    let mut m = manifest(5, vec![]);
    m.expires = m.created;
    assert!(sign_manifest(&m.to_json(), &[&key(1)]).is_err());
}

fn write_bundle(dir: &Path, files: &[(&str, &[u8])], version: u64, k: &SecretKey) {
    let mut entries = Vec::new();
    for (path, contents) in files {
        let full = dir.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, contents).unwrap();
        entries.push(entry(path, contents));
    }
    fs::write(
        dir.join(MANIFEST_FILE),
        signed(&manifest(version, entries), &[k]),
    )
    .unwrap();
}

#[test]
fn verifies_bundle_files_and_detects_tampering() {
    let k = key(1);
    let root = trust(&[&k], 1);
    let dir = tempfile::tempdir().unwrap();
    let files: &[(&str, &[u8])] = &[
        ("indicators/stalkerware.json", b"[\"com.example.spy\"]"),
        ("indicators/mercenary.json", b"[\"bad.example\"]"),
    ];
    write_bundle(dir.path(), files, 7, &k);
    // An unlisted extra file is ignored, not trusted.
    fs::write(dir.path().join("README.txt"), b"not signed").unwrap();
    assert!(verify_update_dir(dir.path(), &root, &policy(Some(6))).is_ok());

    // Same size, different content.
    fs::write(
        dir.path().join("indicators/mercenary.json"),
        b"[\"bad.exampl3\"]",
    )
    .unwrap();
    assert!(matches!(
        verify_update_dir(dir.path(), &root, &policy(Some(6))),
        Err(FeedError::DigestMismatch(_))
    ));

    // Different size.
    fs::write(dir.path().join("indicators/mercenary.json"), b"[]").unwrap();
    assert!(matches!(
        verify_update_dir(dir.path(), &root, &policy(Some(6))),
        Err(FeedError::SizeMismatch { .. })
    ));

    // Missing file.
    fs::remove_file(dir.path().join("indicators/mercenary.json")).unwrap();
    assert!(matches!(
        verify_update_dir(dir.path(), &root, &policy(Some(6))),
        Err(FeedError::Io { .. })
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_files() {
    let k = key(1);
    let dir = tempfile::tempdir().unwrap();
    let contents: &[u8] = b"[]";
    write_bundle(dir.path(), &[("a.json", contents)], 1, &k);
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), contents).unwrap();
    fs::remove_file(dir.path().join("a.json")).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("a.json")).unwrap();
    assert!(matches!(
        verify_update_dir(dir.path(), &trust(&[&k], 1), &policy(None)),
        Err(FeedError::BadPath(_))
    ));
}

#[test]
fn key_files_round_trip() {
    let k = key(3);
    let parsed = SecretKey::from_hex(&k.to_hex()).unwrap();
    assert_eq!(parsed.public_hex(), k.public_hex());
    let root = TrustRoot::from_hex_keys(&[k.public_hex()], 1).unwrap();
    assert_eq!(root.threshold(), 1);
    assert!(TrustRoot::from_hex_keys(&["00".repeat(31)], 1).is_err());
    assert!(TrustRoot::from_hex_keys(&[k.public_hex()], 2).is_err());
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

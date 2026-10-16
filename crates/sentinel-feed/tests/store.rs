// SPDX-License-Identifier: GPL-3.0-or-later
//! Installing bundles on disk (ADR-0019): a bundle comes into force only once everything
//! in it passed every check where it will be used, and the bundle in force is checked
//! again later (SRS SP-04).

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use sentinel_feed::{
    BundleStore, FeedError, FileEntry, MANIFEST_FILE, MANIFEST_SCHEMA, Manifest, Offer, SecretKey,
    TrustRoot, VerifiedManifest, sign_manifest,
};
use sha2::{Digest, Sha256};

const FEED: &str = "sentinel-indicators";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn trust() -> TrustRoot {
    TrustRoot::new(vec![key(1).public()], 1).unwrap()
}

/// Stage bundle `version` with `files` in a new directory, signed by `signer`.
fn stage(root: &Path, version: u64, files: &[(&str, &[u8])], signer: &SecretKey) -> PathBuf {
    let dir = root.join(format!("staging-{version}-{}", files.len()));
    fs::create_dir_all(&dir).unwrap();
    let mut entries = Vec::new();
    for (path, contents) in files {
        let target = dir.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, contents).unwrap();
        entries.push(FileEntry {
            path: (*path).into(),
            sha256: hex::encode(Sha256::digest(contents)),
            size: contents.len() as u64,
        });
    }
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA,
        feed: FEED.into(),
        version,
        created: NOW - DAY,
        expires: NOW + 13 * DAY,
        files: entries,
    };
    let envelope = sign_manifest(&manifest.to_json(), &[signer]).unwrap();
    fs::write(dir.join(MANIFEST_FILE), envelope.to_json()).unwrap();
    dir
}

fn accept(_: &Path, _: &VerifiedManifest) -> Result<(), FeedError> {
    Ok(())
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn an_installed_bundle_is_in_force_and_checked_again() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("feed");
    let store = BundleStore::new(&root, FEED);
    assert_eq!(store.current_version(), None);
    assert!(store.installed(&trust(), accept).unwrap().is_none());

    let staged = stage(
        tmp.path(),
        3,
        &[("indicators-a.json", b"{}"), ("data/ip.db", b"ip")],
        &key(1),
    );
    fs::write(staged.join("unlisted.txt"), b"not signed").unwrap();
    let installed = store.install(&staged, &trust(), NOW, accept).unwrap();
    assert_eq!(installed.verified.manifest().version, 3);
    assert_eq!(installed.dir, root.join("bundle-3"));
    assert_eq!(store.current_version(), Some(3));
    assert_eq!(fs::read(installed.dir.join("data/ip.db")).unwrap(), b"ip");
    assert!(
        !installed.dir.join("unlisted.txt").exists(),
        "only what the manifest lists is installed"
    );
    assert_eq!(names(&root), ["bundle-3", "current"]);

    let again = store.installed(&trust(), accept).unwrap().unwrap();
    assert_eq!(again.verified.manifest().version, 3);
}

#[test]
fn an_update_replaces_the_bundle_and_an_older_one_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("feed");
    let store = BundleStore::new(&root, FEED);
    let v3 = stage(tmp.path(), 3, &[("a.json", b"three")], &key(1));
    store.install(&v3, &trust(), NOW, accept).unwrap();

    // A manifest is judged before any file it lists is fetched.
    let manifest = |dir: &Path| fs::read(dir.join(MANIFEST_FILE)).unwrap();
    let v4 = stage(
        tmp.path(),
        4,
        &[("a.json", b"four"), ("b.json", b"new")],
        &key(1),
    );
    let v2 = stage(tmp.path(), 2, &[("a.json", b"two")], &key(1));
    let same = stage(tmp.path(), 3, &[("a.json", b"three")], &key(1));
    assert!(matches!(
        store.offer(&manifest(&same), &trust(), NOW).unwrap(),
        Offer::UpToDate
    ));
    let Offer::Update(offered) = store.offer(&manifest(&v4), &trust(), NOW).unwrap() else {
        panic!("version 4 is newer");
    };
    assert_eq!(offered.manifest().files.len(), 2);
    assert!(matches!(
        store.offer(&manifest(&v2), &trust(), NOW),
        Err(FeedError::Rollback {
            installed: 3,
            found: 2
        })
    ));
    let unsigned = stage(tmp.path(), 5, &[("a.json", b"five")], &key(2));
    assert!(matches!(
        store.offer(&manifest(&unsigned), &trust(), NOW),
        Err(FeedError::Signatures { .. })
    ));
    assert!(matches!(
        store.offer(&manifest(&v4), &trust(), NOW + 20 * DAY),
        Err(FeedError::Expired { .. })
    ));

    store.install(&v4, &trust(), NOW, accept).unwrap();
    assert_eq!(store.current_version(), Some(4));
    assert_eq!(
        names(&root),
        ["bundle-4", "current"],
        "the older bundle is gone"
    );
    assert!(matches!(
        store.install(&v2, &trust(), NOW, accept),
        Err(FeedError::Rollback { .. })
    ));
    assert_eq!(store.current_version(), Some(4));
}

/// A tampered bundle, one signed by another key, or one whose contents the caller
/// refuses never comes into force, and leaves nothing behind.
#[test]
fn a_bad_update_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("feed");
    let store = BundleStore::new(&root, FEED);
    let v1 = stage(tmp.path(), 1, &[("a.json", b"one")], &key(1));
    store.install(&v1, &trust(), NOW, accept).unwrap();

    let tampered = stage(tmp.path(), 2, &[("a.json", b"two")], &key(1));
    fs::write(tampered.join("a.json"), b"TWO").unwrap();
    assert!(matches!(
        store.install(&tampered, &trust(), NOW, accept),
        Err(FeedError::DigestMismatch(_))
    ));
    let missing = stage(
        tmp.path(),
        2,
        &[("a.json", b"two"), ("b.json", b"b")],
        &key(1),
    );
    fs::remove_file(missing.join("b.json")).unwrap();
    assert!(matches!(
        store.install(&missing, &trust(), NOW, accept),
        Err(FeedError::Io { .. })
    ));
    let other_key = stage(tmp.path(), 2, &[("a.json", b"two")], &key(2));
    assert!(matches!(
        store.install(&other_key, &trust(), NOW, accept),
        Err(FeedError::Signatures { .. })
    ));
    let refused = stage(tmp.path(), 2, &[("indicators-a.json", b"two")], &key(1));
    let refuse = |dir: &Path, _: &VerifiedManifest| -> Result<(), FeedError> {
        assert!(
            dir.join("indicators-a.json").is_file(),
            "checked where it will be used"
        );
        Err(FeedError::BadContent {
            path: "indicators-a.json".into(),
            reason: "no provenance".into(),
        })
    };
    assert!(matches!(
        store.install(&refused, &trust(), NOW, refuse),
        Err(FeedError::BadContent { .. })
    ));

    assert_eq!(store.current_version(), Some(1));
    assert_eq!(names(&root), ["bundle-1", "current"]);
    assert_eq!(fs::read(root.join("bundle-1/a.json")).unwrap(), b"one");
}

/// SP-04: a bundle in force that no longer passes its checks is removed, and then any
/// good bundle can be installed, even one with a lower version.
#[test]
fn a_bundle_that_fails_its_check_again_is_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("feed");
    let store = BundleStore::new(&root, FEED);
    let v5 = stage(tmp.path(), 5, &[("a.json", b"five")], &key(1));
    store.install(&v5, &trust(), NOW, accept).unwrap();

    fs::write(root.join("bundle-5/a.json"), b"FIVE").unwrap();
    assert!(matches!(
        store.installed(&trust(), accept),
        Err(FeedError::DigestMismatch(_))
    ));
    assert_eq!(store.current_version(), None);
    assert!(names(&root).is_empty());
    assert!(store.installed(&trust(), accept).unwrap().is_none());

    // A key that is no longer trusted, as after a leaked key is dropped.
    let v6 = stage(tmp.path(), 6, &[("a.json", b"six")], &key(1));
    store.install(&v6, &trust(), NOW, accept).unwrap();
    let new_trust = TrustRoot::new(vec![key(3).public()], 1).unwrap();
    assert!(matches!(
        store.installed(&new_trust, accept),
        Err(FeedError::Signatures { .. })
    ));
    let v2 = stage(tmp.path(), 2, &[("a.json", b"two")], &key(3));
    store.install(&v2, &new_trust, NOW, accept).unwrap();
    assert_eq!(store.current_version(), Some(2));

    // A pointer to a bundle that is not there.
    fs::remove_dir_all(root.join("bundle-2")).unwrap();
    assert!(store.installed(&new_trust, accept).is_err());
    assert_eq!(store.current_version(), None);
}

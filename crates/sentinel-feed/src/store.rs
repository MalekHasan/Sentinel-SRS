// SPDX-License-Identifier: GPL-3.0-or-later
//! Installed bundles on disk (ADR-0019).
//!
//! `<root>/current` holds the version in force, and `<root>/bundle-<version>/` its
//! manifest and files. An update is staged elsewhere, verified, moved file by file into a
//! new bundle directory, checked again there, and only then made current by replacing
//! `current` in one rename. A crash at any point leaves either the old bundle or the new
//! one in force, never a mix of the two.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::verify::read_envelope;
use crate::{
    FeedError, MANIFEST_FILE, TrustRoot, UpdatePolicy, VerifiedManifest, verify_installed,
    verify_update,
};

/// How far in the future a bundle's creation time may be, for phones whose clock is a
/// little behind (ADR-0005).
pub const MAX_CLOCK_SKEW: u64 = 60 * 60;

const CURRENT: &str = "current";
const BUNDLE_PREFIX: &str = "bundle-";

/// Where the installed bundles of one feed live.
#[derive(Debug, Clone)]
pub struct BundleStore {
    root: PathBuf,
    feed: String,
}

/// The bundle in force, verified.
#[derive(Debug, Clone)]
pub struct Installed {
    /// Its directory: listed files are at their paths below it.
    pub dir: PathBuf,
    pub verified: VerifiedManifest,
}

/// What a downloaded manifest offers.
#[derive(Debug, Clone)]
pub enum Offer {
    /// The bundle in force is this one.
    UpToDate,
    /// A newer bundle, signed and current: fetch its files, then install it.
    Update(VerifiedManifest),
}

impl BundleStore {
    /// The bundles of feed `feed` under `root`.
    pub fn new(root: impl Into<PathBuf>, feed: impl Into<String>) -> BundleStore {
        BundleStore {
            root: root.into(),
            feed: feed.into(),
        }
    }

    /// The version in force, if any: what an update must be newer than.
    pub fn current_version(&self) -> Option<u64> {
        let text = fs::read_to_string(self.root.join(CURRENT)).ok()?;
        text.trim().parse().ok()
    }

    /// Check the bundle in force again, signature and every file (at start and every
    /// hour, SRS SP-04), with `check` for what the files hold. A bundle that fails is
    /// removed, so that nothing uses it, and the error says why. `None` when no bundle
    /// is installed.
    pub fn installed(
        &self,
        trust: &TrustRoot,
        mut check: impl FnMut(&Path, &VerifiedManifest) -> Result<(), FeedError>,
    ) -> Result<Option<Installed>, FeedError> {
        let Some(version) = self.current_version() else {
            return Ok(None);
        };
        let dir = self.bundle_dir(version);
        let checked = read_envelope(&dir)
            .and_then(|envelope| verify_installed(&envelope, trust, &self.feed, version))
            .and_then(|verified| {
                verified.check_dir(&dir)?;
                check(&dir, &verified)?;
                Ok(verified)
            });
        match checked {
            Ok(verified) => Ok(Some(Installed { dir, verified })),
            Err(e) => {
                let _ = fs::remove_file(self.root.join(CURRENT));
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    /// Check a downloaded manifest, before fetching any file it lists: signed by trusted
    /// keys, for this feed, newer than the bundle in force, and current at `now` (Unix
    /// seconds).
    pub fn offer(&self, envelope: &[u8], trust: &TrustRoot, now: u64) -> Result<Offer, FeedError> {
        match verify_update(envelope, trust, &self.policy(now)) {
            Ok(verified) => Ok(Offer::Update(verified)),
            Err(FeedError::Rollback { installed, found }) if found == installed => {
                Ok(Offer::UpToDate)
            }
            Err(e) => Err(e),
        }
    }

    /// Install the bundle staged in `staging`: its manifest and the files it lists.
    /// Everything is checked again where it will be used: signature, version, expiry,
    /// every file's size and SHA-256, and `check` for what the files hold. Only then does
    /// the bundle come into force; older bundles are removed. Files in `staging` that the
    /// manifest does not list are left there.
    pub fn install(
        &self,
        staging: &Path,
        trust: &TrustRoot,
        now: u64,
        mut check: impl FnMut(&Path, &VerifiedManifest) -> Result<(), FeedError>,
    ) -> Result<Installed, FeedError> {
        let envelope = read_envelope(staging)?;
        let verified = verify_update(&envelope, trust, &self.policy(now))?;
        let version = verified.manifest().version;
        fs::create_dir_all(&self.root).map_err(|e| io(&self.root, e))?;
        let incoming = self.root.join(format!("{BUNDLE_PREFIX}{version}.incoming"));
        let _ = fs::remove_dir_all(&incoming);
        let result = (|| {
            fs::create_dir(&incoming).map_err(|e| io(&incoming, e))?;
            move_file(staging, &incoming, MANIFEST_FILE)?;
            for entry in &verified.manifest().files {
                move_file(staging, &incoming, &entry.path)?;
            }
            // Checked where it will be used, so that nothing changed it on the way.
            let verified = verify_update(&read_envelope(&incoming)?, trust, &self.policy(now))?;
            verified.check_dir(&incoming)?;
            check(&incoming, &verified)?;
            let dir = self.bundle_dir(version);
            let _ = fs::remove_dir_all(&dir);
            fs::rename(&incoming, &dir).map_err(|e| io(&dir, e))?;
            self.set_current(version)?;
            Ok(Installed { dir, verified })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&incoming);
            return result;
        }
        self.remove_others(version);
        result
    }

    fn policy(&self, now: u64) -> UpdatePolicy {
        UpdatePolicy {
            feed: self.feed.clone(),
            installed_version: self.current_version(),
            now,
            max_clock_skew: MAX_CLOCK_SKEW,
        }
    }

    fn bundle_dir(&self, version: u64) -> PathBuf {
        self.root.join(format!("{BUNDLE_PREFIX}{version}"))
    }

    /// Replace `current` in one rename, after its contents reached the disk.
    fn set_current(&self, version: u64) -> Result<(), FeedError> {
        let next = self.root.join(format!("{CURRENT}.next"));
        let mut file = fs::File::create(&next).map_err(|e| io(&next, e))?;
        file.write_all(format!("{version}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| io(&next, e))?;
        fs::rename(&next, self.root.join(CURRENT)).map_err(|e| io(&next, e))
    }

    /// Remove every bundle directory but the one in force, and leftovers of updates
    /// that did not finish.
    fn remove_others(&self, version: u64) {
        let keep = format!("{BUNDLE_PREFIX}{version}");
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(BUNDLE_PREFIX) && name != keep {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// Move `path` from `from` to `to`, making its parent directories. Copies when the two
/// are on different file systems.
fn move_file(from: &Path, to: &Path, path: &str) -> Result<(), FeedError> {
    let source = from.join(path);
    let target = to.join(path);
    let meta = fs::symlink_metadata(&source).map_err(|e| io(&source, e))?;
    if !meta.is_file() {
        return Err(FeedError::BadPath(path.to_owned()));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
    }
    if fs::rename(&source, &target).is_err() {
        fs::copy(&source, &target).map_err(|e| io(&source, e))?;
    }
    Ok(())
}

fn io(path: &Path, source: std::io::Error) -> FeedError {
    FeedError::Io {
        path: path.display().to_string(),
        source,
    }
}

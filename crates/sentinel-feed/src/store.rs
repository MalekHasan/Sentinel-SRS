// SPDX-License-Identifier: GPL-3.0-or-later
//! Installed bundles on disk (ADR-0019).
//!
//! `<root>/current` holds the version in force, and `<root>/bundle-<version>/` its
//! manifest and files. An update is staged elsewhere, verified, moved file by file into a
//! new bundle directory, checked again there, and only then made current by replacing
//! `current` in one rename. Every file and directory reaches the disk before the rename
//! that depends on it (audit A-20). A crash or a power cut at any point leaves either the
//! old bundle or the new one in force, never a mix of the two.
//!
//! `<root>/floor` holds the highest version that was in force: what an update must be
//! newer than, even after the bundle in force was removed (audit A-19).

use std::fs;
use std::io::{ErrorKind, Write as _};
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
const FLOOR: &str = "floor";
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
    /// hour, SRS SP-04), with `check` for what the files hold. `None` when no bundle is
    /// installed. A bundle that fails is not used, and the error says why:
    /// - a file that cannot be read, but is there, is a disk that may come back: the
    ///   bundle stays, and the next check tries again (audit A-19);
    /// - a signature no trusted key made, as once an app update drops a leaked key: the
    ///   bundle is removed, and a good bundle of any version may install (ADR-0019);
    /// - anything else, such as a file changed or gone: the bundle is removed, and only
    ///   its own version or a newer one may install. Were any version allowed, a bundle
    ///   removed this way would open the door to older ones (audit A-19).
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
            Err(FeedError::Io { path, source }) if source.kind() != ErrorKind::NotFound => {
                Err(FeedError::Io { path, source })
            }
            Err(e) => {
                if matches!(e, FeedError::Signatures { .. }) {
                    let _ = fs::remove_file(self.root.join(FLOOR));
                } else {
                    let _ = self.raise_floor(version);
                }
                let _ = fs::remove_file(self.root.join(CURRENT));
                let _ = fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    /// The highest version that was in force, if it is still the floor.
    fn floor(&self) -> Option<u64> {
        let text = fs::read_to_string(self.root.join(FLOOR)).ok()?;
        text.trim().parse().ok()
    }

    /// Check a downloaded manifest, before fetching any file it lists: signed by trusted
    /// keys, for this feed, newer than the bundle in force, and current at `now` (Unix
    /// seconds).
    pub fn offer(&self, envelope: &[u8], trust: &TrustRoot, now: u64) -> Result<Offer, FeedError> {
        match verify_update(envelope, trust, &self.policy(now)) {
            Ok(verified) => Ok(Offer::Update(verified)),
            Err(FeedError::Rollback { found, .. }) if Some(found) == self.current_version() => {
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
            // On the disk before anything points at it (audit A-20).
            sync(&incoming.join(MANIFEST_FILE))?;
            for entry in &verified.manifest().files {
                sync(&incoming.join(&entry.path))?;
                let mut parent = incoming.join(&entry.path);
                while parent.pop() && parent != incoming {
                    sync(&parent)?;
                }
            }
            sync(&incoming)?;
            let dir = self.bundle_dir(version);
            let _ = fs::remove_dir_all(&dir);
            fs::rename(&incoming, &dir).map_err(|e| io(&dir, e))?;
            sync(&self.root)?;
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

    /// What an update must be newer than: the bundle in force, and the floor. With
    /// none in force, the version that was in force may come back, but no older one.
    fn policy(&self, now: u64) -> UpdatePolicy {
        let floor = self.floor();
        let installed_version = match self.current_version() {
            Some(current) => Some(floor.map_or(current, |floor| floor.max(current))),
            None => floor.and_then(|floor| floor.checked_sub(1)),
        };
        UpdatePolicy {
            feed: self.feed.clone(),
            installed_version,
            now,
            max_clock_skew: MAX_CLOCK_SKEW,
        }
    }

    fn bundle_dir(&self, version: u64) -> PathBuf {
        self.root.join(format!("{BUNDLE_PREFIX}{version}"))
    }

    /// Make `version` current, then the floor if it is higher. A power cut between the
    /// two leaves the floor below `current`, which [`Self::policy`] allows for, and
    /// [`Self::installed`] raises the floor before it removes a bundle.
    fn set_current(&self, version: u64) -> Result<(), FeedError> {
        self.replace(CURRENT, version)?;
        self.raise_floor(version)
    }

    /// Make `version` the floor if it is higher.
    fn raise_floor(&self, version: u64) -> Result<(), FeedError> {
        if self.floor().is_none_or(|floor| floor < version) {
            self.replace(FLOOR, version)?;
        }
        Ok(())
    }

    /// Replace the file `name` with `version` in one rename, after its contents reached
    /// the disk, and the rename after it.
    fn replace(&self, name: &str, version: u64) -> Result<(), FeedError> {
        let next = self.root.join(format!("{name}.next"));
        let mut file = fs::File::create(&next).map_err(|e| io(&next, e))?;
        file.write_all(format!("{version}\n").as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| io(&next, e))?;
        fs::rename(&next, self.root.join(name)).map_err(|e| io(&next, e))?;
        sync(&self.root)
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

/// Waits until `path`, a file or a directory, has reached the disk.
fn sync(path: &Path) -> Result<(), FeedError> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| io(path, e))
}

fn io(path: &Path, source: std::io::Error) -> FeedError {
    FeedError::Io {
        path: path.display().to_string(),
        source,
    }
}

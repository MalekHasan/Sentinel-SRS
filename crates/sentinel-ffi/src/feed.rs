// SPDX-License-Identifier: GPL-3.0-or-later
//! The signed indicator feed (SRS MS-10, SP-04; ADR-0005, ADR-0019), as seen from Kotlin.
//!
//! Kotlin fetches the files, over HTTPS or from a folder the user picks; the core decides
//! what may be fetched and what comes into force. A manifest is checked before anything
//! it lists is fetched. A staged bundle comes into force only once its signature,
//! version, expiry, every file's SHA-256, every indicator's provenance and the data files
//! all pass where they will be used. The bundle in force is checked again at start and
//! every hour, and removed if it fails.
//!
//! The engine matches traffic against the indicators of the bundle in force
//! ([`Feed::matcher`]): a new bundle is matched against as soon as it is installed, and
//! a removed one no longer matches anything.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use sentinel_enrich::{IpDb, TrackerDb};
use sentinel_feed::{BundleStore, FeedError, Offer, TrustRoot, VerifiedManifest};
use sentinel_ioc::{IndicatorFile, Matcher, is_indicator_file};

use crate::history::now_ms;

/// The name every bundle of the indicator feed carries.
const FEED_NAME: &str = "sentinel-indicators";

/// How many trusted keys must sign a bundle (ADR-0005: one in Phase A).
const TRUSTED_THRESHOLD: u32 = 1;

/// The data files of a bundle that this edition reads, as named in the feed.
pub const IP_DATABASE_FILE: &str = "ip.db";
pub const TRACKER_LIST_FILE: &str = "trackers.db";

include!(concat!(env!("OUT_DIR"), "/trusted_keys.rs"));

/// The public keys this build trusts to sign the feed, compiled in from `keys/feed`.
#[uniffi::export]
pub fn trusted_feed_keys() -> Vec<String> {
    TRUSTED_KEYS.iter().map(|key| (*key).to_owned()).collect()
}

/// How many of [`trusted_feed_keys`] must sign a bundle.
#[uniffi::export]
pub fn trusted_feed_threshold() -> u32 {
    TRUSTED_THRESHOLD
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FeedFailure {
    /// The keys given cannot check any bundle: there are none, fewer than the threshold,
    /// or one is not a key.
    #[error("no keys to check indicator lists with: {reason}")]
    NoKeys { reason: String },
    /// A bundle failed a check: signature, feed, version, expiry, a file's size or
    /// SHA-256, an indicator's provenance or a data file. `reason` is for the log; the
    /// user is told only that the list could not be verified.
    #[error("the indicator list was refused: {reason}")]
    Refused { reason: String },
    /// Files could not be read or written.
    #[error("the indicator list could not be stored: {reason}")]
    Failed { reason: String },
}

impl From<FeedError> for FeedFailure {
    fn from(e: FeedError) -> Self {
        match e {
            FeedError::Io { .. } => FeedFailure::Failed {
                reason: e.to_string(),
            },
            other => FeedFailure::Refused {
                reason: other.to_string(),
            },
        }
    }
}

/// One source of the indicators in force.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FeedSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub licence: String,
    pub indicators: u32,
}

/// The bundle in force.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FeedStatus {
    pub version: u64,
    /// When the list was made, Unix milliseconds: the date results show (MS-15).
    pub created_ms: i64,
    /// From then on the list is out of date. It is still used, and the app says so.
    pub expires_ms: i64,
    pub sources: Vec<FeedSource>,
    /// Indicators this version uses, from every source.
    pub indicators: u32,
    /// Indicators of kinds or threats this version does not know, left out.
    pub skipped: u32,
}

/// One file of an offered bundle, to fetch.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FeedFile {
    /// Its path in the bundle, and so its name next to the manifest where it is
    /// published.
    pub path: String,
    /// Its exact size: a download that grows larger can stop there.
    pub size: u64,
}

/// What a downloaded manifest offers.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FeedOffer {
    /// The bundle in force is this one.
    UpToDate,
    /// A newer bundle: fetch these files next to its manifest, then install it.
    Update { version: u64, files: Vec<FeedFile> },
}

/// The bundle in force, as last checked.
struct InForce {
    dir: PathBuf,
    files: Vec<String>,
    status: FeedStatus,
}

/// The indicator feed's bundles in one directory, checked with one trust root.
#[derive(uniffi::Object)]
pub struct Feed {
    store: BundleStore,
    trust: TrustRoot,
    in_force: Mutex<Option<InForce>>,
    /// The indicators of the bundle in force, apart from `in_force` so that the engine
    /// never waits for a check or an install to read them.
    matcher: RwLock<Option<Arc<Matcher>>>,
}

#[uniffi::export]
impl Feed {
    /// The feed whose bundles live in `dir`, trusting bundles that `threshold` of
    /// `trusted_keys` (64 hex characters each) signed. Nothing is read yet: call
    /// [`Feed::recheck`] to check the bundle in force.
    #[uniffi::constructor]
    pub fn open(
        dir: String,
        trusted_keys: Vec<String>,
        threshold: u32,
    ) -> Result<Arc<Self>, FeedFailure> {
        let trust = TrustRoot::from_hex_keys(&trusted_keys, threshold as usize).map_err(|e| {
            FeedFailure::NoKeys {
                reason: e.to_string(),
            }
        })?;
        Ok(Arc::new(Feed {
            store: BundleStore::new(dir, FEED_NAME),
            trust,
            in_force: Mutex::new(None),
            matcher: RwLock::new(None),
        }))
    }

    /// The bundle in force as last checked, without checking it again.
    pub fn status(&self) -> Option<FeedStatus> {
        self.lock().as_ref().map(|in_force| in_force.status.clone())
    }

    /// Check the bundle in force again, signature and every file (at start and every
    /// hour, SP-04). `None` when there is none. A bundle that fails is removed, and the
    /// error says why.
    pub fn recheck(&self) -> Result<Option<FeedStatus>, FeedFailure> {
        let mut in_force = self.lock();
        *in_force = None;
        let mut checked = None;
        let installed = self.store.installed(&self.trust, |dir, verified| {
            checked = Some(contents(dir, verified, false)?);
            Ok(())
        });
        // Until now the indicators of the last check stay in use; from now on, only
        // those of a bundle that passed this one.
        let installed = match installed {
            Ok(installed) => installed,
            Err(e) => {
                self.set_matcher(None);
                return Err(e.into());
            }
        };
        let (Some(installed), Some((status, matcher))) = (installed, checked) else {
            self.set_matcher(None);
            return Ok(None);
        };
        self.set_matcher(Some(matcher));
        *in_force = Some(InForce {
            files: listed(&installed.verified),
            dir: installed.dir,
            status: status.clone(),
        });
        Ok(Some(status))
    }

    /// Check a downloaded manifest (`manifest.dsse.json`) before fetching anything it
    /// lists: signed by trusted keys, for this feed, newer than the bundle in force, and
    /// current.
    pub fn offer(&self, manifest: Vec<u8>) -> Result<FeedOffer, FeedFailure> {
        let _guard = self.lock();
        Ok(
            match self.store.offer(&manifest, &self.trust, now_secs())? {
                Offer::UpToDate => FeedOffer::UpToDate,
                Offer::Update(verified) => FeedOffer::Update {
                    version: verified.manifest().version,
                    files: verified
                        .manifest()
                        .files
                        .iter()
                        .map(|file| FeedFile {
                            path: file.path.clone(),
                            size: file.size,
                        })
                        .collect(),
                },
            },
        )
    }

    /// Install the bundle staged in `staging_dir`: its `manifest.dsse.json` and the files
    /// it lists. It comes into force only if everything passes; otherwise the bundle in
    /// force stays. Put `staging_dir` next to the feed's directory, so that files move
    /// rather than copy.
    pub fn install(&self, staging_dir: String) -> Result<FeedStatus, FeedFailure> {
        let mut in_force = self.lock();
        let mut checked = None;
        let installed = self.store.install(
            Path::new(&staging_dir),
            &self.trust,
            now_secs(),
            |dir, verified| {
                checked = Some(contents(dir, verified, true)?);
                Ok(())
            },
        )?;
        let (status, matcher) = checked.ok_or_else(|| FeedFailure::Refused {
            reason: "the bundle was not checked".into(),
        })?;
        self.set_matcher(Some(matcher));
        *in_force = Some(InForce {
            files: listed(&installed.verified),
            dir: installed.dir,
            status: status.clone(),
        });
        Ok(status)
    }

    /// Where the bundle in force keeps file `path`, if it lists one. Only files of a
    /// bundle that passed its last check are given.
    pub fn file(&self, path: String) -> Option<String> {
        let in_force = self.lock();
        let in_force = in_force.as_ref()?;
        in_force
            .files
            .contains(&path)
            .then(|| in_force.dir.join(&path).to_string_lossy().into_owned())
    }
}

impl Feed {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<InForce>> {
        self.in_force.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The domain and address indicators of the bundle in force, as last checked (ID-13);
    /// `None` when there is none.
    pub(crate) fn matcher(&self) -> Option<Arc<Matcher>> {
        self.matcher
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The version of the bundle in force and its indicators, read together (MS-02).
    pub(crate) fn in_force(&self) -> Option<(u64, Arc<Matcher>)> {
        let in_force = self.lock();
        let version = in_force.as_ref()?.status.version;
        Some((version, self.matcher()?))
    }

    fn set_matcher(&self, matcher: Option<Matcher>) {
        *self.matcher.write().unwrap_or_else(PoisonError::into_inner) = matcher.map(Arc::new);
    }
}

fn now_secs() -> u64 {
    u64::try_from(now_ms() / 1000).unwrap_or(0)
}

fn listed(verified: &VerifiedManifest) -> Vec<String> {
    verified
        .manifest()
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect()
}

/// Check what a bundle's files hold, where they will be used: every indicator file has
/// provenance on every indicator and is named after its source (MS-10); when
/// `data_files`, the IP database and tracker list load. Files this edition does not read
/// are left alone. Gives the bundle's status and its indicators, ready to match.
fn contents(
    dir: &Path,
    verified: &VerifiedManifest,
    data_files: bool,
) -> Result<(FeedStatus, Matcher), FeedError> {
    let manifest = verified.manifest();
    let mut sources = Vec::new();
    let mut files = Vec::new();
    let mut skipped = 0usize;
    for file in &manifest.files {
        let path = file.path.as_str();
        let bad = |reason: String| FeedError::BadContent {
            path: path.to_owned(),
            reason,
        };
        let read = || {
            fs::read(dir.join(path)).map_err(|source| FeedError::Io {
                path: path.to_owned(),
                source,
            })
        };
        if is_indicator_file(path) {
            let parsed = IndicatorFile::parse(&read()?).map_err(|e| bad(e.to_string()))?;
            if parsed.file_name() != path {
                return Err(bad(format!("its source is {:?}", parsed.source.id)));
            }
            skipped += parsed.skipped;
            sources.push(FeedSource {
                indicators: count(parsed.indicators.len()),
                id: parsed.source.id.clone(),
                name: parsed.source.name.clone(),
                url: parsed.source.url.clone(),
                licence: parsed.source.licence.clone(),
            });
            files.push(parsed);
        } else if data_files && path == IP_DATABASE_FILE {
            IpDb::from_bytes(&read()?).map_err(|e| bad(e.to_string()))?;
        } else if data_files && path == TRACKER_LIST_FILE {
            TrackerDb::from_bytes(&read()?).map_err(|e| bad(e.to_string()))?;
        }
    }
    let status = FeedStatus {
        version: manifest.version,
        created_ms: millis(manifest.created),
        expires_ms: millis(manifest.expires),
        indicators: sources.iter().map(|source| source.indicators).sum(),
        skipped: count(skipped),
        sources,
    };
    Ok((status, Matcher::new(files)))
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn millis(secs: u64) -> i64 {
    i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use sentinel_enrich::{IpDbBuilder, Sources, TrackerDbBuilder};
    use sentinel_feed::{
        FileEntry, MANIFEST_FILE, MANIFEST_SCHEMA, Manifest, SecretKey, sign_manifest,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const DAY: u64 = 86_400;

    fn key() -> SecretKey {
        SecretKey::from_seed([9; 32])
    }

    pub(crate) fn open(dir: &Path) -> Arc<Feed> {
        Feed::open(
            dir.to_string_lossy().into_owned(),
            vec![key().public_hex()],
            1,
        )
        .unwrap()
    }

    /// Indicator file of `source` holding `(kind, value)` indicators of the
    /// stalkerware family "Example".
    pub(crate) fn indicators(source: &str, values: &[(&str, &str)]) -> Vec<u8> {
        let list: Vec<Value> = values
            .iter()
            .map(|(kind, value)| {
                json!({
                    "kind": kind,
                    "value": value,
                    "family": "Example",
                    "threat": "stalkerware",
                    "date": "2025-01-31",
                    "report": "https://example.org/report",
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "schema": 1,
            "source": {
                "id": source,
                "name": format!("Source {source}"),
                "url": "https://example.org/data",
                "licence": "CC BY 4.0",
            },
            "indicators": list,
        }))
        .unwrap()
    }

    /// Stage bundle `version` holding `files` in a new directory under `root`.
    pub(crate) fn stage(root: &Path, version: u64, files: &[(&str, Vec<u8>)]) -> PathBuf {
        let dir = root.join(format!("staging-{version}-{}", files.len()));
        fs::create_dir_all(&dir).unwrap();
        let mut entries = Vec::new();
        for (path, contents) in files {
            fs::write(dir.join(path), contents).unwrap();
            entries.push(FileEntry {
                path: (*path).into(),
                sha256: hex::encode(Sha256::digest(contents)),
                size: contents.len() as u64,
            });
        }
        let now = now_secs();
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA,
            feed: FEED_NAME.into(),
            version,
            created: now - DAY,
            expires: now + 13 * DAY,
            files: entries,
        };
        let envelope = sign_manifest(&manifest.to_json(), &[&key()]).unwrap();
        fs::write(dir.join(MANIFEST_FILE), envelope.to_json()).unwrap();
        dir
    }

    pub(crate) fn path(dir: &Path) -> String {
        dir.to_string_lossy().into_owned()
    }

    fn ip_db() -> Vec<u8> {
        let mut builder = IpDbBuilder::new(Sources {
            network: "test".into(),
            country: "test".into(),
        });
        builder
            .add_network(
                "203.0.113.0".parse().unwrap(),
                "203.0.113.255".parse().unwrap(),
                64_500,
            )
            .unwrap();
        builder.build().unwrap()
    }

    fn tracker_list() -> Vec<u8> {
        let mut builder = TrackerDbBuilder::new();
        let source = builder.add_source("test").unwrap();
        builder
            .add_domain(source, "ads.example", Some("Example Ads"), &["Advertising"])
            .unwrap();
        builder.build().unwrap()
    }

    /// MS-10: a manifest is judged before its files are fetched; a bundle installs with
    /// its sources, comes into force, and is checked again when the app starts.
    #[test]
    fn a_bundle_is_offered_installed_and_checked_again() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("feed");
        let feed = open(&root);
        assert_eq!(feed.status(), None);
        assert_eq!(feed.recheck().unwrap(), None);

        let staged = stage(
            tmp.path(),
            1,
            &[
                (
                    "indicators-alpha.json",
                    indicators(
                        "alpha",
                        &[
                            ("domain", "spy.example"),
                            ("file-hash", "abc"),
                            ("package", "com.spy.app"),
                        ],
                    ),
                ),
                (
                    "indicators-beta.json",
                    indicators("beta", &[("address", "203.0.113.9")]),
                ),
                (IP_DATABASE_FILE, ip_db()),
                (TRACKER_LIST_FILE, tracker_list()),
                ("other-edition.bin", b"not read here".to_vec()),
            ],
        );
        let manifest = fs::read(staged.join(sentinel_feed::MANIFEST_FILE)).unwrap();
        let FeedOffer::Update { version, files } = feed.offer(manifest.clone()).unwrap() else {
            panic!("a first bundle is an update");
        };
        assert_eq!(version, 1);
        assert_eq!(files.len(), 5);
        assert_eq!(files[0].path, "indicators-alpha.json");

        let status = feed.install(path(&staged)).unwrap();
        assert_eq!(status.version, 1);
        assert_eq!(status.indicators, 3);
        assert_eq!(status.skipped, 1);
        let sources: Vec<_> = status
            .sources
            .iter()
            .map(|s| (s.id.as_str(), s.indicators))
            .collect();
        assert_eq!(sources, [("alpha", 2), ("beta", 1)]);
        assert_eq!(status.sources[0].licence, "CC BY 4.0");
        assert!(status.expires_ms > status.created_ms);
        assert_eq!(feed.status(), Some(status.clone()));
        assert_eq!(feed.offer(manifest).unwrap(), FeedOffer::UpToDate);

        let ip = feed.file(IP_DATABASE_FILE.into()).unwrap();
        assert_eq!(fs::read(&ip).unwrap(), ip_db());
        assert!(ip.starts_with(&path(&root)));
        assert_eq!(feed.file("unlisted.txt".into()), None);
        let matcher = feed.matcher().unwrap();
        assert_eq!(matcher.len(), 2, "the domain and the address");
        assert_eq!(matcher.name("cdn.spy.example").unwrap().source.id, "alpha");
        assert!(matcher.address("203.0.113.9".parse().unwrap()).is_some());

        // As when the app starts again.
        let reopened = open(&root);
        assert_eq!(
            reopened.status(),
            None,
            "nothing is used before it is checked"
        );
        assert!(reopened.matcher().is_none());
        assert_eq!(reopened.recheck().unwrap(), Some(status));
        assert!(reopened.matcher().unwrap().name("spy.example").is_some());
    }

    /// ID-13: the indicators matched are those of the bundle in force: a newer bundle's
    /// as soon as it is installed, and still the old ones when an update is refused.
    #[test]
    fn the_indicators_in_force_are_matched() {
        let tmp = tempfile::tempdir().unwrap();
        let feed = open(&tmp.path().join("feed"));
        assert!(feed.matcher().is_none());
        let first = stage(
            tmp.path(),
            1,
            &[(
                "indicators-alpha.json",
                indicators("alpha", &[("domain", "spy.example")]),
            )],
        );
        feed.install(path(&first)).unwrap();
        let old = feed.matcher().unwrap();
        assert!(old.name("spy.example").is_some());

        let refused = stage(
            tmp.path(),
            2,
            &[(
                "indicators-gamma.json",
                indicators("alpha", &[("domain", "other.example")]),
            )],
        );
        assert!(feed.install(path(&refused)).is_err());
        assert!(Arc::ptr_eq(&feed.matcher().unwrap(), &old));

        let second = stage(
            tmp.path(),
            3,
            &[(
                "indicators-alpha.json",
                indicators("alpha", &[("domain", "other.example")]),
            )],
        );
        feed.install(path(&second)).unwrap();
        let new = feed.matcher().unwrap();
        assert!(new.name("spy.example").is_none());
        assert!(new.name("x.other.example").is_some());
        assert!(
            old.name("spy.example").is_some(),
            "a matcher already taken is not changed under its holder"
        );
    }

    /// MS-10: provenance on every indicator is checked on load, and a file must be the
    /// one its name says. The data files must load. A refused bundle changes nothing.
    #[test]
    fn a_bundle_with_bad_contents_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("feed");
        let feed = open(&root);
        let good = stage(
            tmp.path(),
            1,
            &[("indicators-alpha.json", indicators("alpha", &[]))],
        );
        let before = feed.install(path(&good)).unwrap();

        let mut no_report: Value =
            serde_json::from_slice(&indicators("alpha", &[("domain", "spy.example")])).unwrap();
        no_report["indicators"][0]["report"] = json!("");
        for (version, files) in [
            (
                2,
                vec![(
                    "indicators-alpha.json",
                    serde_json::to_vec(&no_report).unwrap(),
                )],
            ),
            (3, vec![("indicators-gamma.json", indicators("alpha", &[]))]),
            (4, vec![(IP_DATABASE_FILE, b"not an IP database".to_vec())]),
            (5, vec![(TRACKER_LIST_FILE, b"not a tracker list".to_vec())]),
        ] {
            let staged = stage(tmp.path(), version, &files);
            let refused = feed.install(path(&staged));
            assert!(
                matches!(refused, Err(FeedFailure::Refused { .. })),
                "{version}: {refused:?}"
            );
            assert_eq!(feed.status(), Some(before.clone()));
        }
        assert_eq!(open(&root).recheck().unwrap(), Some(before));
    }

    /// SP-04: a bundle in force that no longer matches what was signed is removed at the
    /// next check, and none of its files is given out.
    #[test]
    fn a_changed_bundle_is_removed_when_checked_again() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("feed");
        let feed = open(&root);
        let staged = stage(
            tmp.path(),
            1,
            &[
                (
                    "indicators-alpha.json",
                    indicators("alpha", &[("domain", "spy.example")]),
                ),
                (IP_DATABASE_FILE, ip_db()),
            ],
        );
        feed.install(path(&staged)).unwrap();
        assert!(feed.matcher().is_some());
        let ip = feed.file(IP_DATABASE_FILE.into()).unwrap();
        fs::write(&ip, b"changed").unwrap();
        assert!(matches!(feed.recheck(), Err(FeedFailure::Refused { .. })));
        assert_eq!(feed.status(), None);
        assert_eq!(feed.file(IP_DATABASE_FILE.into()), None);
        assert!(
            feed.matcher().is_none(),
            "its indicators match nothing more"
        );
        assert_eq!(feed.recheck().unwrap(), None);
    }

    /// The bundles the Android device tests install (apps/android/scripts/make-test-feed.sh)
    /// pass every check, in order, so that a change of format cannot leave them behind.
    #[test]
    fn the_device_tests_bundles_install() {
        let android = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/android");
        let key = fs::read_to_string(android.join("scripts/test-feed/test-key.pub")).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let feed = Feed::open(
            path(&tmp.path().join("feed")),
            vec![key.trim().to_owned()],
            1,
        )
        .unwrap();
        for version in 1..=3u64 {
            let fixture = android.join(format!("app/src/androidTest/assets/feed/v{version}"));
            let staged = tmp.path().join(format!("staged-{version}"));
            fs::create_dir(&staged).unwrap();
            for entry in fs::read_dir(&fixture).unwrap() {
                let entry = entry.unwrap();
                fs::copy(entry.path(), staged.join(entry.file_name())).unwrap();
            }
            let status = feed.install(path(&staged)).unwrap();
            assert_eq!(status.version, version);
            assert_eq!(status.indicators, version as u32);
            assert_eq!(status.sources[0].id, "sentinel-test");
            // The name the device tests look up (IndicatorAlertTest).
            assert!(
                feed.matcher()
                    .unwrap()
                    .name("planted.sentinel-test.example")
                    .is_some()
            );
        }
    }

    /// Without keys nothing can be checked, so nothing is installed; every key compiled
    /// into this build is a key.
    #[test]
    fn a_feed_needs_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = path(tmp.path());
        for (keys, threshold) in [
            (vec![], 1),
            (vec!["not a key".to_owned()], 1),
            (vec![key().public_hex()], 2),
            (vec![key().public_hex()], 0),
        ] {
            assert!(matches!(
                Feed::open(dir.clone(), keys, threshold),
                Err(FeedFailure::NoKeys { .. })
            ));
        }
        for key in trusted_feed_keys() {
            assert!(Feed::open(dir.clone(), vec![key], 1).is_ok());
        }
        assert_eq!(trusted_feed_threshold(), 1);
    }
}

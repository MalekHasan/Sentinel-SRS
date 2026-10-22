// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::FeedError;

/// Current manifest schema. Any change to the fields below needs a new schema number,
/// because older apps reject fields they do not know.
pub const MANIFEST_SCHEMA: u32 = 1;

/// Upper bound on files per bundle, so a hostile manifest cannot make us do unbounded work.
pub const MAX_FILES: usize = 1000;

const MAX_PATH_LEN: usize = 200;

/// The signed description of a bundle. Times are Unix seconds (UTC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    /// Which feed this is, e.g. `sentinel-indicators`. Stops a valid bundle of one feed
    /// from being installed as another.
    pub feed: String,
    /// Strictly increasing. Never reused, never decreased.
    pub version: u64,
    pub created: u64,
    pub expires: u64,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Relative path inside the bundle, `/`-separated.
    pub path: String,
    /// Lowercase hex SHA-256 of the file contents.
    pub sha256: String,
    pub size: u64,
}

impl Manifest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, FeedError> {
        let manifest: Manifest = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn to_json(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).unwrap_or_default();
        out.push(b'\n');
        out
    }

    /// One SHA-256 over every listed file's path and SHA-256, in order: the same for
    /// two manifests that list the same files, whatever their versions and dates. A
    /// valid path holds no line break, so the lines cannot run into each other.
    pub fn files_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        for entry in &self.files {
            digest.update(format!("{}\n{}\n", entry.path, entry.sha256));
        }
        digest.finalize().into()
    }

    /// Structural checks that do not depend on time, keys or installed state.
    pub fn validate(&self) -> Result<(), FeedError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(FeedError::Schema(self.schema));
        }
        if self.expires <= self.created {
            return Err(FeedError::BadValidity {
                created: self.created,
                expires: self.expires,
            });
        }
        if self.files.len() > MAX_FILES {
            return Err(FeedError::TooManyFiles {
                count: self.files.len(),
                max: MAX_FILES,
            });
        }
        let mut seen = HashSet::new();
        for entry in &self.files {
            validate_path(&entry.path)?;
            if !seen.insert(entry.path.as_str()) {
                return Err(FeedError::DuplicatePath(entry.path.clone()));
            }
            if entry.sha256.len() != 64
                || !entry
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(FeedError::BadDigest(entry.path.clone()));
            }
        }
        Ok(())
    }

    pub fn file(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.path == path)
    }
}

/// Accept only plain relative paths made of safe characters, so that joining a listed
/// path onto the bundle directory can never point outside it, on any OS.
pub(crate) fn validate_path(path: &str) -> Result<(), FeedError> {
    let bad = || FeedError::BadPath(path.to_owned());
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(bad());
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'))
    {
        return Err(bad());
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(bad());
        }
    }
    if path.eq_ignore_ascii_case(crate::MANIFEST_FILE) {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA,
            feed: "sentinel-indicators".into(),
            version: 1,
            created: 1_000,
            expires: 2_000,
            files: vec![FileEntry {
                path: "indicators/stalkerware.json".into(),
                sha256: "a".repeat(64),
                size: 3,
            }],
        }
    }

    #[test]
    fn valid_manifest_round_trips() {
        let m = manifest();
        assert_eq!(Manifest::from_json(&m.to_json()).unwrap(), m);
    }

    /// The files digest tells lists apart by what they hold, not by their versions.
    #[test]
    fn the_files_digest_depends_on_the_files_only() {
        let m = manifest();
        let mut later = manifest();
        later.version = 2;
        later.created = 1_500;
        later.expires = 3_000;
        assert_eq!(later.files_digest(), m.files_digest());

        let mut other = manifest();
        other.files[0].sha256 = "b".repeat(64);
        assert_ne!(other.files_digest(), m.files_digest());
        let mut moved = manifest();
        moved.files[0].path = "indicators/spyware.json".into();
        assert_ne!(moved.files_digest(), m.files_digest());
        let mut more = manifest();
        more.files.push(FileEntry {
            path: "ip.db".into(),
            sha256: "c".repeat(64),
            size: 1,
        });
        assert_ne!(more.files_digest(), m.files_digest());
    }

    #[test]
    fn rejects_paths_that_could_escape_the_bundle() {
        for path in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a//b",
            "./a",
            "a/",
            "C:\\x",
            "a\\b",
            "a b",
            "ü.json",
            "manifest.dsse.json",
            "MANIFEST.DSSE.JSON",
        ] {
            assert!(validate_path(path).is_err(), "accepted {path:?}");
        }
        for path in ["a", "a/b.json", "indicators/v1/stalker-ware_1.json"] {
            assert!(validate_path(path).is_ok(), "rejected {path:?}");
        }
    }

    #[test]
    fn rejects_duplicates_bad_digests_and_bad_validity() {
        let mut m = manifest();
        m.files.push(m.files[0].clone());
        assert!(matches!(m.validate(), Err(FeedError::DuplicatePath(_))));

        let mut m = manifest();
        m.files[0].sha256 = "A".repeat(64);
        assert!(matches!(m.validate(), Err(FeedError::BadDigest(_))));

        let mut m = manifest();
        m.expires = m.created;
        assert!(matches!(m.validate(), Err(FeedError::BadValidity { .. })));

        let mut m = manifest();
        m.schema = 2;
        assert!(matches!(m.validate(), Err(FeedError::Schema(2))));
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let json =
            br#"{"schema":1,"feed":"f","version":1,"created":1,"expires":2,"files":[],"x":0}"#;
        assert!(matches!(Manifest::from_json(json), Err(FeedError::Json(_))));
    }
}

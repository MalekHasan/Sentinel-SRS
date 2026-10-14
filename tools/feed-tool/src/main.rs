// SPDX-License-Identifier: GPL-3.0-or-later
//! `sentinel-feed-tool`: keys, manifests, signing and verification for indicator feeds.
//!
//! The signing steps are meant for an offline machine. See `docs/FEED-SIGNING.md`.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use sentinel_feed::{
    FileEntry, Freshness, MANIFEST_FILE, MANIFEST_SCHEMA, Manifest, SecretKey, TrustRoot,
    UpdatePolicy, sign_manifest, verify_installed, verify_update_dir,
};
use sha2::{Digest, Sha256};

const DAY: u64 = 86_400;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new signing key. Run this on the offline signing machine.
    Keygen {
        /// Where to write the secret key (created with owner-only permissions).
        #[arg(long)]
        secret: PathBuf,
        /// Where to write the public key (safe to publish and commit).
        #[arg(long)]
        public: PathBuf,
    },
    /// Hash every file in a bundle directory and write an unsigned manifest.
    Manifest {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "sentinel-indicators")]
        feed: String,
        #[arg(long)]
        version: u64,
        /// How long the bundle stays current. Weekly feeds use 14 days.
        #[arg(long, default_value_t = 14)]
        valid_days: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an unsigned manifest. Run this on the offline signing machine.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        /// One or more secret key files.
        #[arg(long = "secret", required = true)]
        secrets: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a bundle directory as an app would.
    Verify {
        #[arg(long)]
        dir: PathBuf,
        /// Trusted public key files.
        #[arg(long = "public", required = true)]
        publics: Vec<PathBuf>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long, default_value = "sentinel-indicators")]
        feed: String,
        /// Version already installed; the bundle must be newer. Omit for a first install.
        #[arg(long)]
        installed_version: Option<u64>,
        /// Check an installed bundle instead: version must equal this, expiry only warns.
        #[arg(long, conflicts_with = "installed_version")]
        installed: Option<u64>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { secret, public } => keygen(&secret, &public),
        Command::Manifest {
            dir,
            feed,
            version,
            valid_days,
            out,
        } => manifest(&dir, feed, version, valid_days, &out),
        Command::Sign {
            manifest,
            secrets,
            out,
        } => sign(&manifest, &secrets, &out),
        Command::Verify {
            dir,
            publics,
            threshold,
            feed,
            installed_version,
            installed,
        } => verify(
            &dir,
            &publics,
            threshold,
            feed,
            installed_version,
            installed,
        ),
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn keygen(secret: &Path, public: &Path) -> Result<()> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("no secure randomness: {e}"))?;
    let key = SecretKey::from_seed(seed);
    seed.fill(0);

    write_new(secret, format!("{}\n", key.to_hex()).as_bytes(), true)?;
    write_new(public, format!("{}\n", key.public_hex()).as_bytes(), false)?;
    eprintln!("key id: {}", key.key_id());
    Ok(())
}

/// Create a file that must not exist yet. Secret files are owner-read/write only.
fn write_new(path: &Path, contents: &[u8], secret: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {} (it must not exist yet)", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn manifest(dir: &Path, feed: String, version: u64, valid_days: u64, out: &Path) -> Result<()> {
    ensure!(valid_days > 0, "--valid-days must be at least 1");
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let created = now()?;
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA,
        feed,
        version,
        created,
        expires: created + valid_days * DAY,
        files,
    };
    manifest
        .validate()
        .context("the bundle cannot be described by a valid manifest")?;
    fs::write(out, manifest.to_json())?;
    eprintln!(
        "manifest: feed {} version {} with {} files, expires in {} days",
        manifest.feed,
        manifest.version,
        manifest.files.len(),
        valid_days
    );
    Ok(())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<FileEntry>) -> Result<()> {
    for item in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let item = item?;
        let path = item.path();
        let kind = item.file_type()?;
        if kind.is_symlink() {
            bail!(
                "symbolic links are not allowed in a bundle: {}",
                path.display()
            );
        }
        if kind.is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)?
            .components()
            .map(|c| c.as_os_str().to_str().context("file name is not UTF-8"))
            .collect::<Result<Vec<_>>>()?
            .join("/");
        if relative == MANIFEST_FILE {
            continue;
        }
        let contents = fs::read(&path)?;
        out.push(FileEntry {
            path: relative,
            sha256: hex::encode(Sha256::digest(&contents)),
            size: contents.len() as u64,
        });
    }
    Ok(())
}

fn sign(manifest_path: &Path, secrets: &[PathBuf], out: &Path) -> Result<()> {
    let manifest_json = fs::read(manifest_path)?;
    let manifest = Manifest::from_json(&manifest_json).context("not a valid manifest")?;
    let keys = secrets
        .iter()
        .map(|p| {
            let text =
                fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?;
            Ok(SecretKey::from_hex(&text)?)
        })
        .collect::<Result<Vec<_>>>()?;

    // Show what is being signed, so the person signing can compare it with the review.
    eprintln!(
        "signing feed {} version {}",
        manifest.feed, manifest.version
    );
    eprintln!(
        "expires {} (Unix time), {} files:",
        manifest.expires,
        manifest.files.len()
    );
    for f in &manifest.files {
        eprintln!("  {}  {:>10}  {}", f.sha256, f.size, f.path);
    }
    let refs: Vec<&SecretKey> = keys.iter().collect();
    let envelope = sign_manifest(&manifest_json, &refs)?;
    write_new(out, &envelope.to_json(), false)?;
    for k in &keys {
        eprintln!("signed with key id {}", k.key_id());
    }
    Ok(())
}

fn verify(
    dir: &Path,
    publics: &[PathBuf],
    threshold: usize,
    feed: String,
    installed_version: Option<u64>,
    installed: Option<u64>,
) -> Result<()> {
    let keys = publics
        .iter()
        .map(|p| fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display())))
        .collect::<Result<Vec<_>>>()?;
    let trust = TrustRoot::from_hex_keys(&keys, threshold)?;
    let now = now()?;

    let verified = match installed {
        Some(version) => {
            let envelope = fs::read(dir.join(MANIFEST_FILE))?;
            let v = verify_installed(&envelope, &trust, &feed, version)?;
            v.check_dir(dir)?;
            v
        }
        None => verify_update_dir(
            dir,
            &trust,
            &UpdatePolicy {
                feed,
                installed_version,
                now,
                max_clock_skew: 3600,
            },
        )?,
    };
    let m = verified.manifest();
    println!(
        "OK: feed {} version {}, {} files, signed by {} key(s)",
        m.feed,
        m.version,
        m.files.len(),
        verified.signed_by().len()
    );
    if let Freshness::Expired { since } = verified.freshness(now) {
        println!("WARNING: this bundle expired at {since} (Unix time)");
    }
    Ok(())
}

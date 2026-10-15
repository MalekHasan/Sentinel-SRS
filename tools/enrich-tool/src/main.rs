// SPDX-License-Identifier: GPL-3.0-or-later
//! `sentinel-enrich-tool`: builds the offline IP database (SRS DT-01, ADR-0010) and the
//! tracker list (DT-06) from the public data sets, and looks addresses and hostnames up
//! in them.
//!
//! The outputs are feed data files: sign them into a feed bundle with
//! `sentinel-feed-tool`.

use std::fs::{self, File};
use std::io::BufReader;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_enrich::upstream::{read_dbip_country, read_iptoasn};
use sentinel_enrich::upstream_trackers::{read_ddg_app_trackers, read_tracker_radar_domain};
use sentinel_enrich::{IpDb, IpDbBuilder, Sources, TrackerDb, TrackerDbBuilder};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the database from IPtoASN and DB-IP Lite files (uncompressed).
    Build {
        /// IPtoASN's `ip2asn-combined.tsv` (or its IPv4 and IPv6 files, repeated).
        #[arg(long, required = true)]
        iptoasn: Vec<PathBuf>,
        /// DB-IP Lite's `dbip-country-lite-YYYY-MM.csv`.
        #[arg(long, required = true)]
        dbip_country: Vec<PathBuf>,
        /// How the app names the network source, with its date, for example
        /// "IPtoASN 2026-10-15".
        #[arg(long)]
        network_source: String,
        /// How the app names the country source, for example "DB-IP Lite 2026-10".
        #[arg(long)]
        country_source: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Look addresses up in a database.
    Lookup {
        #[arg(long)]
        db: PathBuf,
        addresses: Vec<IpAddr>,
    },
    /// Build the tracker list from DuckDuckGo Tracker Radar and DuckDuckGo's app tracker
    /// list. Both are CC BY-NC-SA 4.0, and so is the file built from them.
    Trackers {
        /// One region folder of Tracker Radar's domain files, for example
        /// `tracker-radar/domains/US`.
        #[arg(long, requires = "radar_source")]
        radar: Option<PathBuf>,
        /// How the app names Tracker Radar, with its date, for example
        /// "DuckDuckGo Tracker Radar 2026-10-15".
        #[arg(long, requires = "radar")]
        radar_source: Option<String>,
        /// The app tracker list, `tracker-blocklists/app/android-tds.json`.
        #[arg(long, requires = "app_trackers_source")]
        app_trackers: Option<PathBuf>,
        /// How the app names it, for example "DuckDuckGo app tracker list 2026-10-15".
        #[arg(long, requires = "app_trackers")]
        app_trackers_source: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Look hostnames up in a tracker list.
    TrackerLookup {
        #[arg(long)]
        db: PathBuf,
        hostnames: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Build {
            iptoasn,
            dbip_country,
            network_source,
            country_source,
            out,
        } => {
            let mut builder = IpDbBuilder::new(Sources {
                network: network_source,
                country: country_source,
            });
            for path in &iptoasn {
                let file =
                    File::open(path).with_context(|| format!("opening {}", path.display()))?;
                let lines = read_iptoasn(BufReader::new(file), &mut builder)
                    .with_context(|| format!("reading {}", path.display()))?;
                eprintln!("{}: {lines} lines", path.display());
            }
            for path in &dbip_country {
                let file =
                    File::open(path).with_context(|| format!("opening {}", path.display()))?;
                let lines = read_dbip_country(BufReader::new(file), &mut builder)
                    .with_context(|| format!("reading {}", path.display()))?;
                eprintln!("{}: {lines} lines", path.display());
            }
            let bytes = builder.build().context("building the database")?;
            // Check what was written before anyone signs it.
            IpDb::from_bytes(&bytes).context("the database just built does not load")?;
            fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
            eprintln!("{}: {} bytes", out.display(), bytes.len());
        }
        Command::Lookup { db, addresses } => {
            let bytes = fs::read(&db).with_context(|| format!("reading {}", db.display()))?;
            let db = IpDb::from_bytes(&bytes).context("loading the database")?;
            let sources = db.sources();
            println!(
                "networks: {}; countries: {}",
                sources.network, sources.country
            );
            for address in addresses {
                let info = db.lookup(address);
                println!(
                    "{address}\tAS{}\t{}\t{}",
                    info.asn
                        .map_or_else(|| "?".to_owned(), |asn| asn.to_string()),
                    info.network_owner.unwrap_or("?"),
                    info.country.unwrap_or("?"),
                );
            }
        }
        Command::Trackers {
            radar,
            radar_source,
            app_trackers,
            app_trackers_source,
            out,
        } => {
            let mut builder = TrackerDbBuilder::new();
            if let (Some(dir), Some(label)) = (radar, radar_source) {
                let source = builder.add_source(&label)?;
                // In name order, so the file does not depend on the folder's order.
                let mut files = fs::read_dir(&dir)
                    .with_context(|| format!("reading {}", dir.display()))?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                files.retain(|path| path.extension().is_some_and(|ext| ext == "json"));
                files.sort();
                let mut added = 0;
                for path in &files {
                    let json = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    added += usize::from(
                        read_tracker_radar_domain(&json, source, &mut builder)
                            .with_context(|| format!("reading {}", path.display()))?,
                    );
                }
                eprintln!(
                    "{}: {} domain files, {added} with an owner or a category",
                    dir.display(),
                    files.len()
                );
            }
            if let (Some(path), Some(label)) = (app_trackers, app_trackers_source) {
                let source = builder.add_source(&label)?;
                let json = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let domains = read_ddg_app_trackers(&json, source, &mut builder)
                    .with_context(|| format!("reading {}", path.display()))?;
                eprintln!("{}: {domains} domains", path.display());
            }
            let bytes = builder.build().context("building the tracker list")?;
            // Check what was written before anyone signs it.
            let db = TrackerDb::from_bytes(&bytes)
                .context("the tracker list just built does not load")?;
            anyhow::ensure!(!db.is_empty(), "no tracker list given");
            fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
            eprintln!(
                "{}: {} domains, {} bytes",
                out.display(),
                db.len(),
                bytes.len()
            );
        }
        Command::TrackerLookup { db, hostnames } => {
            let bytes = fs::read(&db).with_context(|| format!("reading {}", db.display()))?;
            let db = TrackerDb::from_bytes(&bytes).context("loading the tracker list")?;
            println!("lists: {}", db.sources().join("; "));
            for hostname in hostnames {
                let Some(info) = db.lookup(&hostname) else {
                    println!("{hostname}\tnot listed");
                    continue;
                };
                let company = info.company.map_or_else(
                    || "?".to_owned(),
                    |c| format!("{} [{}: {}]", c.value, c.domain, c.sources.join("; ")),
                );
                let categories = info.categories.map_or_else(
                    || "?".to_owned(),
                    |c| {
                        let list = c.value.join(", ");
                        format!("{list} [{}: {}]", c.domain, c.sources.join("; "))
                    },
                );
                println!("{hostname}\t{company}\t{categories}");
            }
        }
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! `sentinel-enrich-tool`: builds the offline IP database (SRS DT-01, ADR-0010) from the
//! public data sets, and looks addresses up in it.
//!
//! The output is a feed data file: sign it into a feed bundle with `sentinel-feed-tool`.

use std::fs::{self, File};
use std::io::BufReader;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_enrich::upstream::{read_dbip_country, read_iptoasn};
use sentinel_enrich::{IpDb, IpDbBuilder, Sources};

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
    }
    Ok(())
}

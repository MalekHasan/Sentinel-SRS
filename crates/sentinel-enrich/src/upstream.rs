// SPDX-License-Identifier: GPL-3.0-or-later
//! Readers for the public data sets the database is built from (LICENCE-REVIEW.md §1).

use std::io::BufRead;
use std::net::IpAddr;

use crate::{BuildError, IpDbBuilder};

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Reads IPtoASN (iptoasn.com, PDDL): `ip2asn-combined.tsv`, or its IPv4 or IPv6 file.
/// Each line is: range start, range end, AS number, country code, AS description,
/// separated by tabs. AS 0 ("Not routed") lines name no network. Returns the number of
/// lines read.
pub fn read_iptoasn(
    input: impl BufRead,
    builder: &mut IpDbBuilder,
) -> Result<usize, UpstreamError> {
    read_lines(input, |line| {
        let fields: Vec<&str> = line.split('\t').collect();
        let [first, last, asn, _country, owner] = fields[..] else {
            return Err("expected 5 tab-separated fields".to_owned());
        };
        let asn: u32 = asn
            .parse()
            .map_err(|_| format!("{asn:?} is not an AS number"))?;
        builder
            .add_network(address(first)?, address(last)?, asn)
            .map_err(|e| e.to_string())?;
        builder
            .name_network(asn, owner)
            .map_err(|e: BuildError| e.to_string())
    })
}

/// Reads DB-IP Lite's country file (db-ip.com, CC BY 4.0): `dbip-country-lite-*.csv`.
/// Each line is: range start, range end, country code. Returns the number of lines read.
pub fn read_dbip_country(
    input: impl BufRead,
    builder: &mut IpDbBuilder,
) -> Result<usize, UpstreamError> {
    read_lines(input, |line| {
        let fields: Vec<&str> = line.split(',').map(|f| f.trim_matches('"')).collect();
        let [first, last, country] = fields[..] else {
            return Err("expected 3 comma-separated fields".to_owned());
        };
        builder
            .add_country(address(first)?, address(last)?, country)
            .map_err(|e| e.to_string())
    })
}

fn read_lines(
    input: impl BufRead,
    mut each: impl FnMut(&str) -> Result<(), String>,
) -> Result<usize, UpstreamError> {
    let mut count = 0;
    for (index, line) in input.lines().enumerate() {
        let line = line?;
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        each(line).map_err(|reason| UpstreamError::Line {
            line: index + 1,
            reason,
        })?;
        count += 1;
    }
    Ok(count)
}

fn address(text: &str) -> Result<IpAddr, String> {
    text.parse()
        .map_err(|_| format!("{text:?} is not an IP address"))
}

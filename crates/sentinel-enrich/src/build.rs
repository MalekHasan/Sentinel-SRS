// SPDX-License-Identifier: GPL-3.0-or-later
//! Writing a database from address ranges.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::format::{MAGIC, MAX_ENTRIES, MAX_TEXT, NO_COUNTRY, Sources, VERSION};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("{first} to {last} is not a range of one address family, lowest first")]
    BadRange { first: IpAddr, last: IpAddr },
    #[error("{0:?} is not a two-letter country code")]
    BadCountry(String),
    #[error("ranges overlap at {0}")]
    Overlap(IpAddr),
    #[error("a table has more than {MAX_ENTRIES} entries")]
    TooLarge,
    #[error("text longer than {MAX_TEXT} bytes: {0:?}")]
    TextTooLong(String),
}

/// Collects ranges from the source data sets, then writes the database file.
#[derive(Debug)]
pub struct IpDbBuilder {
    sources: Sources,
    v4_network: Vec<(u32, u32, u32)>,
    v6_network: Vec<(u128, u128, u32)>,
    v4_country: Vec<(u32, u32, [u8; 2])>,
    v6_country: Vec<(u128, u128, [u8; 2])>,
    names: BTreeMap<u32, String>,
}

impl IpDbBuilder {
    pub fn new(sources: Sources) -> Self {
        IpDbBuilder {
            sources,
            v4_network: Vec::new(),
            v6_network: Vec::new(),
            v4_country: Vec::new(),
            v6_country: Vec::new(),
            names: BTreeMap::new(),
        }
    }

    /// The addresses `first` to `last`, inclusive, belong to network `asn`. ASN 0 means
    /// "not routed" and is skipped.
    pub fn add_network(&mut self, first: IpAddr, last: IpAddr, asn: u32) -> Result<(), BuildError> {
        if asn == 0 {
            return Ok(());
        }
        match range(first, last)? {
            Range::V4(a, b) => self.v4_network.push((a, b, asn)),
            Range::V6(a, b) => self.v6_network.push((a, b, asn)),
        }
        Ok(())
    }

    /// The addresses `first` to `last`, inclusive, are in `country` (ISO 3166 two
    /// letters). DB-IP's "ZZ" (unknown) is skipped.
    pub fn add_country(
        &mut self,
        first: IpAddr,
        last: IpAddr,
        country: &str,
    ) -> Result<(), BuildError> {
        if country == "ZZ" {
            return Ok(());
        }
        let code: [u8; 2] = country
            .as_bytes()
            .try_into()
            .ok()
            .filter(|code: &[u8; 2]| code.iter().all(u8::is_ascii_uppercase))
            .ok_or_else(|| BuildError::BadCountry(country.to_owned()))?;
        match range(first, last)? {
            Range::V4(a, b) => self.v4_country.push((a, b, code)),
            Range::V6(a, b) => self.v6_country.push((a, b, code)),
        }
        Ok(())
    }

    /// The registered name of network `asn`. The first name given is kept.
    pub fn name_network(&mut self, asn: u32, owner: &str) -> Result<(), BuildError> {
        let owner = owner.trim();
        if asn == 0 || owner.is_empty() {
            return Ok(());
        }
        if owner.len() > MAX_TEXT {
            return Err(BuildError::TextTooLong(owner.to_owned()));
        }
        self.names.entry(asn).or_insert_with(|| owner.to_owned());
        Ok(())
    }

    /// The database file. Adjacent ranges with the same value are merged.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let v4_network = table(self.v4_network, 0)?;
        let v6_network = table(self.v6_network, 0)?;
        let v4_country = table(self.v4_country, NO_COUNTRY)?;
        let v6_country = table(self.v6_country, NO_COUNTRY)?;
        // Only names of networks the tables use.
        let used: BTreeSet<u32> = v4_network
            .iter()
            .map(|(_, asn)| *asn)
            .chain(v6_network.iter().map(|(_, asn)| *asn))
            .collect();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        write_text(&mut out, &self.sources.network)?;
        write_text(&mut out, &self.sources.country)?;
        write_table(
            &mut out,
            &v4_network,
            |o, k| o.extend_from_slice(&k.to_le_bytes()),
            |o, v| o.extend_from_slice(&v.to_le_bytes()),
        );
        write_table(
            &mut out,
            &v6_network,
            |o, k| o.extend_from_slice(&k.to_le_bytes()),
            |o, v| o.extend_from_slice(&v.to_le_bytes()),
        );
        write_table(
            &mut out,
            &v4_country,
            |o, k| o.extend_from_slice(&k.to_le_bytes()),
            |o, v| o.extend_from_slice(v),
        );
        write_table(
            &mut out,
            &v6_country,
            |o, k| o.extend_from_slice(&k.to_le_bytes()),
            |o, v| o.extend_from_slice(v),
        );
        let names: Vec<_> = self
            .names
            .iter()
            .filter(|(asn, _)| used.contains(asn))
            .collect();
        out.extend_from_slice(&(names.len() as u32).to_le_bytes());
        for (asn, name) in names {
            out.extend_from_slice(&asn.to_le_bytes());
            write_text(&mut out, name)?;
        }
        Ok(out)
    }
}

enum Range {
    V4(u32, u32),
    V6(u128, u128),
}

fn range(first: IpAddr, last: IpAddr) -> Result<Range, BuildError> {
    let range = match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => Range::V4(a.into(), b.into()),
        (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => Range::V6(a.into(), b.into()),
        _ => return Err(BuildError::BadRange { first, last }),
    };
    Ok(range)
}

/// An address as a number.
trait Address: Copy + Ord {
    /// The address one past this one, if there is one.
    fn next(self) -> Option<Self>;
    fn ip(self) -> IpAddr;
}

impl Address for u32 {
    fn next(self) -> Option<Self> {
        self.checked_add(1)
    }
    fn ip(self) -> IpAddr {
        std::net::Ipv4Addr::from(self).into()
    }
}

impl Address for u128 {
    fn next(self) -> Option<Self> {
        self.checked_add(1)
    }
    fn ip(self) -> IpAddr {
        std::net::Ipv6Addr::from(self).into()
    }
}

/// Turn inclusive ranges into (start, value) entries, with `none` filling the gaps.
fn table<K: Address, V: Copy + PartialEq>(
    mut ranges: Vec<(K, K, V)>,
    none: V,
) -> Result<Vec<(K, V)>, BuildError> {
    ranges.sort_unstable_by_key(|(first, _, _)| *first);
    let mut entries: Vec<(K, V)> = Vec::with_capacity(ranges.len());
    // One past the last address covered so far; None once the end of the address space
    // is covered, or before the first range.
    let mut next_free: Option<K> = None;
    let mut started = false;
    for (first, last, value) in ranges {
        if started {
            match next_free {
                None => return Err(BuildError::Overlap(first.ip())),
                Some(free) if first < free => return Err(BuildError::Overlap(first.ip())),
                Some(free) if first > free => entries.push((free, none)),
                Some(_) => {}
            }
        }
        let contiguous = started && next_free == Some(first);
        if !(contiguous && entries.last().is_some_and(|(_, v)| *v == value)) {
            entries.push((first, value));
        }
        started = true;
        next_free = last.next();
    }
    if let Some(free) = next_free.filter(|_| started) {
        entries.push((free, none));
    }
    if entries.len() > MAX_ENTRIES {
        return Err(BuildError::TooLarge);
    }
    Ok(entries)
}

fn write_table<K, V>(
    out: &mut Vec<u8>,
    entries: &[(K, V)],
    key: impl Fn(&mut Vec<u8>, &K),
    value: impl Fn(&mut Vec<u8>, &V),
) {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, v) in entries {
        key(out, k);
        value(out, v);
    }
}

fn write_text(out: &mut Vec<u8>, text: &str) -> Result<(), BuildError> {
    if text.len() > MAX_TEXT {
        return Err(BuildError::TextTooLong(text.to_owned()));
    }
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

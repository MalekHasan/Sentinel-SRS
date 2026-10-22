// SPDX-License-Identifier: GPL-3.0-or-later
//! The database file and its lookups.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! magic "SNTLIPDB", version u32
//! text: where networks come from        text: where countries come from
//! table: IPv4 network   (start u32,  ASN u32)
//! table: IPv6 network   (start u128, ASN u32)
//! table: IPv4 country   (start u32,  country [u8; 2])
//! table: IPv6 country   (start u128, country [u8; 2])
//! names: (ASN u32, text) sorted by ASN
//! ```
//!
//! A table is a count (u32) and its entries. Starts are strictly increasing; an entry
//! covers addresses from its start up to the next start. ASN 0 and country `[0, 0]`
//! mean "nothing known" and fill the gaps between ranges. A text is a length (u32) and
//! UTF-8 bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const MAGIC: &[u8; 8] = b"SNTLIPDB";
pub(crate) const VERSION: u32 = 1;
/// No table is longer than this, so a damaged file cannot make us allocate without
/// limit. The full public data sets have a few million ranges.
pub(crate) const MAX_ENTRIES: usize = 16 * 1024 * 1024;
/// Longest source label or network owner name.
pub(crate) const MAX_TEXT: usize = 1024;
/// "Nothing known" in a country table.
pub(crate) const NO_COUNTRY: [u8; 2] = [0, 0];

/// Where the answers come from, as the database's builder labelled them, for example
/// "IPtoASN 2026-10-15" (SRS DT-02: "why we believe this").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sources {
    /// Source of networks and their owners.
    pub network: String,
    /// Source of countries.
    pub country: String,
}

/// What the database knows about one address. Every part may be unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpInfo<'a> {
    pub asn: Option<u32>,
    /// The network's registered name, for example "CLOUDFLARENET".
    pub network_owner: Option<&'a str>,
    /// ISO 3166 two-letter code. Approximate: where the address is registered or
    /// announced, not where a particular server stands.
    pub country: Option<&'a str>,
}

/// A loaded database. Lookups never fail; unknown addresses return empty answers.
#[derive(Debug)]
pub struct IpDb {
    sources: Sources,
    v4_network: Table<u32, u32>,
    v6_network: Table<u128, u32>,
    v4_country: Table<u32, [u8; 2]>,
    v6_country: Table<u128, [u8; 2]>,
    /// Sorted by ASN.
    names: Vec<(u32, String)>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoadError {
    #[error("not a Sentinel IP database")]
    NotAnIpDb,
    #[error("IP database version {0} is not supported")]
    UnsupportedVersion(u32),
    #[error("the IP database is cut short")]
    Truncated,
    #[error("the IP database has a table or text larger than allowed")]
    TooLarge,
    #[error("the IP database has entries out of order")]
    NotSorted,
    #[error("the IP database has an invalid country code")]
    BadCountry,
    #[error("the IP database has text that is not valid UTF-8")]
    BadText,
    #[error("the IP database has data after its end")]
    TrailingBytes,
}

impl IpDb {
    /// Check and load a database file's contents.
    pub fn from_bytes(bytes: &[u8]) -> Result<IpDb, LoadError> {
        let mut r = Reader { bytes, pos: 0 };
        if r.take(MAGIC.len()).map_err(|_| LoadError::NotAnIpDb)? != MAGIC {
            return Err(LoadError::NotAnIpDb);
        }
        let version = r.u32()?;
        if version != VERSION {
            return Err(LoadError::UnsupportedVersion(version));
        }
        let sources = Sources {
            network: r.text()?,
            country: r.text()?,
        };
        let v4_network = r.table(4, |b| u32_at(b, 0), |b| Ok(u32_at(b, 4)))?;
        let v6_network = r.table(16, |b| u128_at(b, 0), |b| Ok(u32_at(b, 16)))?;
        let v4_country = r.table(4, |b| u32_at(b, 0), |b| country_at(b, 4))?;
        let v6_country = r.table(16, |b| u128_at(b, 0), |b| country_at(b, 16))?;
        let count = r.count(4 + 4)?;
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            let asn = r.u32()?;
            if asn == 0 || names.last().is_some_and(|(last, _)| *last >= asn) {
                return Err(LoadError::NotSorted);
            }
            names.push((asn, r.text()?));
        }
        if r.pos != bytes.len() {
            return Err(LoadError::TrailingBytes);
        }
        Ok(IpDb {
            sources,
            v4_network,
            v6_network,
            v4_country,
            v6_country,
            names,
        })
    }

    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    pub fn lookup(&self, ip: IpAddr) -> IpInfo<'_> {
        // An IPv4 address written as IPv6 is the IPv4 address: mapped (::ffff:a.b.c.d)
        // or through NAT64 (64:ff9b::a.b.c.d).
        let ip = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .or_else(|| nat64(v6))
                .map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        let (asn, country) = match ip {
            IpAddr::V4(v4) => {
                let key = u32::from(v4);
                (self.v4_network.get(key), self.v4_country.get(key))
            }
            IpAddr::V6(v6) => {
                let key = u128::from(v6);
                (self.v6_network.get(key), self.v6_country.get(key))
            }
        };
        let asn = asn.copied().filter(|asn| *asn != 0);
        IpInfo {
            asn,
            network_owner: asn.and_then(|asn| self.owner(asn)),
            country: country
                .filter(|code| **code != NO_COUNTRY)
                .and_then(|code| std::str::from_utf8(code).ok()),
        }
    }

    fn owner(&self, asn: u32) -> Option<&str> {
        let i = self.names.binary_search_by_key(&asn, |(a, _)| *a).ok()?;
        Some(&self.names[i].1)
    }
}

/// The IPv4 address an address of NAT64's well-known prefix stands for: `64:ff9b::/96`
/// (RFC 6052), as on a network that reaches IPv4 only through NAT64 (audit A-23).
fn nat64(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let [a, b, c, d] = v6.octets()[12..] else {
        return None;
    };
    (v6.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]).then(|| Ipv4Addr::new(a, b, c, d))
}

/// Range starts and the value from each start up to the next.
#[derive(Debug)]
struct Table<K, V> {
    starts: Vec<K>,
    values: Vec<V>,
}

impl<K: Ord + Copy, V> Table<K, V> {
    fn get(&self, key: K) -> Option<&V> {
        // The last range that starts at or before the key.
        let after = self.starts.partition_point(|start| *start <= key);
        after.checked_sub(1).map(|i| &self.values[i])
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], LoadError> {
        let end = self.pos.checked_add(n).ok_or(LoadError::Truncated)?;
        let slice = self.bytes.get(self.pos..end).ok_or(LoadError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, LoadError> {
        Ok(u32_at(self.take(4)?, 0))
    }

    /// A count of entries of `entry_size` bytes, checked against the bytes left.
    fn count(&mut self, entry_size: usize) -> Result<usize, LoadError> {
        let count = self.u32()? as usize;
        if count > MAX_ENTRIES {
            return Err(LoadError::TooLarge);
        }
        let needed = count.checked_mul(entry_size).ok_or(LoadError::TooLarge)?;
        if needed > self.bytes.len() - self.pos {
            return Err(LoadError::Truncated);
        }
        Ok(count)
    }

    fn text(&mut self) -> Result<String, LoadError> {
        let len = self.u32()? as usize;
        if len > MAX_TEXT {
            return Err(LoadError::TooLarge);
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| LoadError::BadText)
    }

    fn table<K: Ord + Copy, V: Copy>(
        &mut self,
        key_size: usize,
        key: impl Fn(&[u8]) -> K,
        value: impl Fn(&[u8]) -> Result<V, LoadError>,
    ) -> Result<Table<K, V>, LoadError> {
        let value_size = std::mem::size_of::<V>();
        let count = self.count(key_size + value_size)?;
        let mut starts = Vec::with_capacity(count);
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let entry = self.take(key_size + value_size)?;
            let start = key(entry);
            if starts.last().is_some_and(|last| *last >= start) {
                return Err(LoadError::NotSorted);
            }
            starts.push(start);
            values.push(value(entry)?);
        }
        Ok(Table { starts, values })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn u128_at(bytes: &[u8], at: usize) -> u128 {
    let mut word = [0u8; 16];
    word.copy_from_slice(&bytes[at..at + 16]);
    u128::from_le_bytes(word)
}

fn country_at(bytes: &[u8], at: usize) -> Result<[u8; 2], LoadError> {
    let code = [bytes[at], bytes[at + 1]];
    if code == NO_COUNTRY || code.iter().all(u8::is_ascii_uppercase) {
        Ok(code)
    } else {
        Err(LoadError::BadCountry)
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! Matching against the indicators in force (ID-13): the names apps look up or connect
//! to and the addresses they connect to, and the package names and signing certificates
//! of installed apps.
//!
//! Lookups run on the packet engine's threads for every DNS query, TLS server name and
//! new connection, so each is a few hash lookups and allocates only for a name not
//! already in lower case.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::sync::Arc;

use crate::{Indicator, IndicatorFile, Kind, Source};

/// An indicator something matched, with the source that lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub indicator: Indicator,
    pub source: Arc<Source>,
}

/// The indicators of a list, ready to match: domains and addresses against traffic,
/// package names and signing certificates against installed apps.
#[derive(Debug, Default)]
pub struct Matcher {
    domains: HashMap<String, Hit>,
    addresses: HashMap<IpAddr, Hit>,
    packages: HashMap<String, Hit>,
    certificates: HashMap<String, Hit>,
}

impl Matcher {
    /// The matcher for `files`. An indicator listed by more than one source keeps the
    /// first source's provenance.
    pub fn new(files: impl IntoIterator<Item = IndicatorFile>) -> Matcher {
        let mut matcher = Matcher::default();
        for file in files {
            let source = Arc::new(file.source);
            for indicator in file.indicators {
                let hit = || Hit {
                    indicator: indicator.clone(),
                    source: Arc::clone(&source),
                };
                match indicator.kind {
                    Kind::Domain => {
                        if let Entry::Vacant(entry) = matcher.domains.entry(indicator.value.clone())
                        {
                            entry.insert(hit());
                        }
                    }
                    Kind::Address => {
                        // Checked when the file was read: the value is an address.
                        if let Ok(address) = indicator.value.parse::<IpAddr>()
                            && let Entry::Vacant(entry) = matcher.addresses.entry(address)
                        {
                            entry.insert(hit());
                        }
                    }
                    Kind::Package => {
                        if let Entry::Vacant(entry) =
                            matcher.packages.entry(indicator.value.clone())
                        {
                            entry.insert(hit());
                        }
                    }
                    Kind::Certificate => {
                        if let Entry::Vacant(entry) =
                            matcher.certificates.entry(indicator.value.clone())
                        {
                            entry.insert(hit());
                        }
                    }
                }
            }
        }
        matcher
    }

    /// The domain indicator `name` falls under: `name` itself or a domain above it.
    /// Case and a trailing dot do not matter.
    pub fn name(&self, name: &str) -> Option<&Hit> {
        if self.domains.is_empty() {
            return None;
        }
        let name = name.strip_suffix('.').unwrap_or(name);
        let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(name.to_ascii_lowercase())
        } else {
            Cow::Borrowed(name)
        };
        let mut rest = name.as_ref();
        // A domain indicator has at least two labels: a lone top-level label never
        // matches.
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(hit) = self.domains.get(rest) {
                return Some(hit);
            }
            rest = parent;
        }
        None
    }

    /// The address indicator `address` is. An IPv4 address written as IPv6
    /// (`::ffff:192.0.2.1`) is the IPv4 address.
    pub fn address(&self, address: IpAddr) -> Option<&Hit> {
        if self.addresses.is_empty() {
            return None;
        }
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
            v4 => v4,
        };
        self.addresses.get(&address)
    }

    /// The package indicator an app installed as `package` is. Package names are
    /// compared exactly, as Android does.
    pub fn package(&self, package: &str) -> Option<&Hit> {
        self.packages.get(package)
    }

    /// The certificate indicator a signing certificate with this SHA-256 (hex, either
    /// case) is.
    pub fn certificate(&self, sha256: &str) -> Option<&Hit> {
        if sha256.bytes().any(|b| b.is_ascii_uppercase()) {
            self.certificates.get(&sha256.to_ascii_lowercase())
        } else {
            self.certificates.get(sha256)
        }
    }

    /// How many indicators it matches against.
    pub fn len(&self) -> usize {
        self.domains.len() + self.addresses.len() + self.packages.len() + self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

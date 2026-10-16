// SPDX-License-Identifier: GPL-3.0-or-later
//! Matching what the phone's traffic names against the indicators in force (ID-13): the
//! names apps look up or connect to, and the addresses they connect to.
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

/// The domain and address indicators of a list, ready to match. Package names and
/// signing certificates are matched against installed apps, not traffic, and are not
/// kept here.
#[derive(Debug, Default)]
pub struct Matcher {
    domains: HashMap<String, Hit>,
    addresses: HashMap<IpAddr, Hit>,
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
                    Kind::Package | Kind::Certificate => {}
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

    /// How many indicators it matches against.
    pub fn len(&self) -> usize {
        self.domains.len() + self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

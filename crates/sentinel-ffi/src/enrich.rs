// SPDX-License-Identifier: GPL-3.0-or-later
//! The offline IP database (SRS DT-01) and tracker list (DT-06), as seen from Kotlin
//! (ADR-0010).

use std::path::Path;
use std::sync::Arc;

use sentinel_enrich::{IpDb, TrackerDb};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum IpDatabaseError {
    #[error("the IP database cannot be read: {reason}")]
    Unreadable { reason: String },
    #[error("the IP database is not valid: {reason}")]
    Invalid { reason: String },
}

/// Where the network and country of an address come from, with their dates (DT-02).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IpSources {
    pub network: String,
    pub country: String,
}

/// The network, its owner and the approximate country of IP addresses, from the IP
/// database file in the feed.
#[derive(uniffi::Object)]
pub struct IpDatabase {
    pub(crate) db: IpDb,
}

#[uniffi::export]
impl IpDatabase {
    /// Load and check the database at `path`.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, IpDatabaseError> {
        let bytes = std::fs::read(Path::new(&path)).map_err(|e| IpDatabaseError::Unreadable {
            reason: e.to_string(),
        })?;
        let db = IpDb::from_bytes(&bytes).map_err(|e| IpDatabaseError::Invalid {
            reason: e.to_string(),
        })?;
        Ok(Arc::new(IpDatabase { db }))
    }

    pub fn sources(&self) -> IpSources {
        let sources = self.db.sources();
        IpSources {
            network: sources.network.clone(),
            country: sources.country.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TrackerDatabaseError {
    #[error("the tracker list cannot be read: {reason}")]
    Unreadable { reason: String },
    #[error("the tracker list is not valid: {reason}")]
    Invalid { reason: String },
}

/// Which company each hostname belongs to and what kind of service it is, from the
/// tracker list file in the feed (DT-06).
#[derive(uniffi::Object)]
pub struct TrackerDatabase {
    pub(crate) db: TrackerDb,
}

#[uniffi::export]
impl TrackerDatabase {
    /// Load and check the tracker list at `path`.
    #[uniffi::constructor]
    pub fn open(path: String) -> Result<Arc<Self>, TrackerDatabaseError> {
        let bytes =
            std::fs::read(Path::new(&path)).map_err(|e| TrackerDatabaseError::Unreadable {
                reason: e.to_string(),
            })?;
        let db = TrackerDb::from_bytes(&bytes).map_err(|e| TrackerDatabaseError::Invalid {
            reason: e.to_string(),
        })?;
        Ok(Arc::new(TrackerDatabase { db }))
    }

    /// The lists it was built from, with their dates.
    pub fn sources(&self) -> Vec<String> {
        self.db.sources().to_vec()
    }
}

/// The company a destination belongs to, from the tracker lists, and why we believe it
/// (DT-02, DT-06).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CompanyFact {
    pub company: String,
    /// The listed domain it comes from: the destination itself or a domain above it.
    pub listed_domain: String,
    /// The lists that say so, with their dates.
    pub sources: Vec<String>,
}

/// What kind of service a destination is, from the tracker lists: for example
/// "Advertising", "Analytics" or "CDN"; and why we believe it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CategoryFact {
    pub categories: Vec<String>,
    pub listed_domain: String,
    pub sources: Vec<String>,
}

impl TrackerDatabase {
    /// What the tracker list says about `hostname`.
    pub(crate) fn lookup(&self, hostname: &str) -> (Option<CompanyFact>, Option<CategoryFact>) {
        let Some(info) = self.db.lookup(hostname) else {
            return (None, None);
        };
        let owned = |sources: Vec<&str>| sources.into_iter().map(str::to_owned).collect();
        (
            info.company.map(|c| CompanyFact {
                company: c.value.to_owned(),
                listed_domain: c.domain.to_owned(),
                sources: owned(c.sources),
            }),
            info.categories.map(|c| CategoryFact {
                categories: owned(c.value),
                listed_domain: c.domain.to_owned(),
                sources: owned(c.sources),
            }),
        )
    }
}

impl From<&CompanyFact> for sentinel_store::Listed<String> {
    fn from(fact: &CompanyFact) -> Self {
        sentinel_store::Listed {
            value: fact.company.clone(),
            domain: fact.listed_domain.clone(),
            sources: fact.sources.clone(),
        }
    }
}

impl From<sentinel_store::Listed<String>> for CompanyFact {
    fn from(listed: sentinel_store::Listed<String>) -> Self {
        CompanyFact {
            company: listed.value,
            listed_domain: listed.domain,
            sources: listed.sources,
        }
    }
}

impl From<&CategoryFact> for sentinel_store::Listed<Vec<String>> {
    fn from(fact: &CategoryFact) -> Self {
        sentinel_store::Listed {
            value: fact.categories.clone(),
            domain: fact.listed_domain.clone(),
            sources: fact.sources.clone(),
        }
    }
}

impl From<sentinel_store::Listed<Vec<String>>> for CategoryFact {
    fn from(listed: sentinel_store::Listed<Vec<String>>) -> Self {
        CategoryFact {
            categories: listed.value,
            listed_domain: listed.domain,
            sources: listed.sources,
        }
    }
}

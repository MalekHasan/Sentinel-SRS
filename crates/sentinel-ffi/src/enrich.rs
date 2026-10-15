// SPDX-License-Identifier: GPL-3.0-or-later
//! The offline IP database (SRS DT-01, ADR-0010), as seen from Kotlin.

use std::path::Path;
use std::sync::Arc;

use sentinel_enrich::IpDb;

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

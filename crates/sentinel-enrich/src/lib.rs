// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline destination data for each flow (SRS DT-01): the network (autonomous system
//! number, ASN) an IP address belongs to, who owns that network, and roughly which
//! country the address is in; and, from tracker lists, which company a hostname belongs
//! to and what kind of tracking it does (DT-06). Nothing is looked up on the network:
//! the data comes from public data sets, compiled into compact files that ship as signed
//! feed files (ADR-0010).
//!
//! The IP database holds sorted range tables and the tracker list a sorted domain table,
//! so a lookup is a binary search: a few microseconds at most, at the size of the real
//! data sets.

mod build;
mod format;
mod trackers;
pub mod upstream;
#[cfg(feature = "tracker-lists")]
pub mod upstream_trackers;

pub use build::{BuildError, IpDbBuilder};
pub use format::{IpDb, IpInfo, LoadError, Sources};
pub use trackers::{
    Listed, SourceId, TrackerBuildError, TrackerDb, TrackerDbBuilder, TrackerInfo, TrackerLoadError,
};

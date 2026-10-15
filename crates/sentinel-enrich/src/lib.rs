// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline destination data for each flow (SRS DT-01): the network (autonomous system
//! number, ASN) an IP address belongs to, who owns that network, and roughly which
//! country the address is in. Nothing is looked up on the network: the data comes from
//! public data sets, compiled into one compact file that ships as a signed feed file
//! (ADR-0010).
//!
//! The file holds sorted range tables, so a lookup is a binary search: well under a
//! microsecond with millions of ranges.

mod build;
mod format;
pub mod upstream;

pub use build::{BuildError, IpDbBuilder};
pub use format::{IpDb, IpInfo, LoadError, Sources};

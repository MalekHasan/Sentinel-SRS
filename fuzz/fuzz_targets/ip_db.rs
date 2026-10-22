// SPDX-License-Identifier: GPL-3.0-or-later
//! The IP database from the feed (`ip.db`, DT-01, audit A-49): a file it accepts can be
//! looked up at any address.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use sentinel_enrich::IpDb;

fuzz_target!(|data: &[u8]| {
    let Ok(db) = IpDb::from_bytes(data) else {
        return;
    };
    let _ = db.sources();
    // The ends of both address spaces, and addresses made from the file's own bytes.
    let mut addresses = vec![
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::from(u128::MAX)),
    ];
    for chunk in data.chunks_exact(16).take(64) {
        let bytes: [u8; 16] = chunk.try_into().unwrap_or_default();
        addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
        addresses.push(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )));
    }
    for address in addresses {
        let _ = db.lookup(address);
    }
});

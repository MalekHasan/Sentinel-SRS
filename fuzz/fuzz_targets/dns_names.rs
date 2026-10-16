// SPDX-License-Identifier: GPL-3.0-or-later
//! The detection rules that read names from the network (DL-05, DL-06): a DNS tunnel's
//! names, encrypted DNS services and sharing sites, on any name an app or server uses.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use sentinel_detect::{DnsWatch, encrypted_dns, sharing_site, sharing_site_upload};

fuzz_target!(|data: &[u8]| {
    let Some((&qtype, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    let mut watch = DnsWatch::new();
    // Many names in one watch, so that a tunnel can be found too.
    for (i, name) in text.split('\n').enumerate() {
        let now = i64::try_from(i).unwrap_or(i64::MAX).saturating_mul(1_000);
        let _ = watch.lookup(now, "org.example.app", name, u16::from(qtype));
        let _ = sharing_site(name);
        let _ = sharing_site_upload(now, "org.example.app", name, 1 << 20);
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let _ = encrypted_dns(ip, u16::from(qtype) << 2, Some(name));
    }
});

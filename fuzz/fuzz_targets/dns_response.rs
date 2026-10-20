// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS answers from the network (CM-02), read to put names on later connections.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_vpn::parse_dns_response;

fuzz_target!(|data: &[u8]| {
    if let Some(answer) = parse_dns_response(data) {
        assert!(!answer.qname.is_empty());
        assert!(!answer.qname.ends_with('.'));
        assert_eq!(answer.qname, answer.qname.to_ascii_lowercase());
        assert!(!answer.ips.is_empty());
    }
});

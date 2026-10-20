// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS queries from apps (ADR-0015): the name and type read from them, and the "no such
//! name" answer to a blocked one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_vpn::{name_error_reply, parse_dns_query, parse_dns_response};

fuzz_target!(|data: &[u8]| {
    let query = parse_dns_query(data);
    let reply = name_error_reply(data);
    if let Some(query) = &query {
        assert!(!query.name.is_empty());
        assert!(!query.name.ends_with('.'));
        assert_eq!(query.name, query.name.to_ascii_lowercase());
        assert!(reply.is_some(), "a query that can be read can be answered");
    }
    if let Some(reply) = reply {
        assert_eq!(parse_dns_query(&reply), None, "the answer is not a query");
        assert_eq!(
            parse_dns_response(&reply),
            None,
            "the answer has no addresses"
        );
    }
});

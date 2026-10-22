// SPDX-License-Identifier: GPL-3.0-or-later
//! An indicator file from the feed (ID-13, audit A-49). Every indicator it accepts is
//! found by the matcher under its own value: one that never could would be read and
//! silently never matched.
#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use sentinel_ioc::{IndicatorFile, Kind, MAX_INDICATORS, Matcher};

fuzz_target!(|data: &[u8]| {
    let Ok(file) = IndicatorFile::parse(data) else {
        return;
    };
    assert!(file.indicators.len() <= MAX_INDICATORS);
    let indicators = file.indicators.clone();
    let matcher = Matcher::new([file]);
    for indicator in &indicators {
        let value = indicator.value.as_str();
        let found = match indicator.kind {
            Kind::Domain => matcher.name(value).is_some(),
            Kind::Address => value
                .parse::<IpAddr>()
                .is_ok_and(|address| matcher.address(address).is_some()),
            Kind::Package => matcher.package(value).is_some(),
            Kind::Certificate => matcher.certificate(value).is_some(),
        };
        assert!(found, "{indicator:?} is never matched");
    }
});

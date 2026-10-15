// SPDX-License-Identifier: GPL-3.0-or-later
//! The IP database: building, loading, lookups, the upstream readers, damaged files,
//! and lookup speed at the size of the real data sets (DT-01: under 1 ms per flow).

#![allow(clippy::unwrap_used)]

use std::net::IpAddr;
use std::time::Instant;

use sentinel_enrich::upstream::{UpstreamError, read_dbip_country, read_iptoasn};
use sentinel_enrich::{BuildError, IpDb, IpDbBuilder, IpInfo, LoadError, Sources};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn sources() -> Sources {
    Sources {
        network: "IPtoASN test".to_owned(),
        country: "DB-IP Lite test".to_owned(),
    }
}

/// IPtoASN's format, with a "Not routed" line and IPv6.
const IPTOASN: &str = "\
1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed
1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AUSTRALIA Gtelecom Pty Ltd
8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE
2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE
2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET
";

/// DB-IP Lite's country format, with "ZZ" (unknown).
const DBIP: &str = "\
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
8.8.8.0,8.8.8.255,US
10.0.0.0,10.255.255.255,ZZ
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
";

fn sample() -> IpDb {
    let mut builder = IpDbBuilder::new(sources());
    assert_eq!(read_iptoasn(IPTOASN.as_bytes(), &mut builder).unwrap(), 6);
    assert_eq!(read_dbip_country(DBIP.as_bytes(), &mut builder).unwrap(), 5);
    IpDb::from_bytes(&builder.build().unwrap()).unwrap()
}

#[test]
fn looks_up_network_owner_and_country() {
    let db = sample();
    assert_eq!(db.sources(), &sources());
    assert_eq!(
        db.lookup(ip("1.0.0.1")),
        IpInfo {
            asn: Some(13335),
            network_owner: Some("CLOUDFLARENET"),
            country: Some("AU"),
        }
    );
    // Not routed, but DB-IP knows the country.
    assert_eq!(
        db.lookup(ip("1.0.2.9")),
        IpInfo {
            asn: None,
            network_owner: None,
            country: Some("CN"),
        }
    );
    let google = db.lookup(ip("2001:4860:4860::8888"));
    assert_eq!(
        (google.asn, google.network_owner),
        (Some(15169), Some("GOOGLE"))
    );
    assert_eq!(google.country, Some("US"));
    // An IPv4 address written as IPv6 is looked up as IPv4.
    assert_eq!(db.lookup(ip("::ffff:8.8.8.8")), db.lookup(ip("8.8.8.8")));
    // Unknown: "ZZ" in DB-IP, and addresses no source lists.
    let empty = IpInfo {
        asn: None,
        network_owner: None,
        country: None,
    };
    assert_eq!(db.lookup(ip("10.1.2.3")), empty);
    assert_eq!(db.lookup(ip("0.0.0.0")), empty);
    assert_eq!(db.lookup(ip("255.255.255.255")), empty);
    assert_eq!(db.lookup(ip("::1")), empty);
    assert_eq!(db.lookup(ip("ffff::1")), empty);
}

#[test]
fn range_edges_are_exact() {
    let db = sample();
    assert_eq!(db.lookup(ip("0.255.255.255")).asn, None);
    assert_eq!(db.lookup(ip("1.0.0.0")).asn, Some(13335));
    assert_eq!(db.lookup(ip("1.0.0.255")).asn, Some(13335));
    assert_eq!(db.lookup(ip("1.0.1.0")).asn, None);
    assert_eq!(db.lookup(ip("1.0.3.255")).asn, None);
    assert_eq!(db.lookup(ip("1.0.4.0")).asn, Some(38803));
    assert_eq!(db.lookup(ip("1.0.7.255")).asn, Some(38803));
    assert_eq!(db.lookup(ip("1.0.8.0")).asn, None);
    assert_eq!(db.lookup(ip("2606:4700::")).asn, Some(13335));
    assert_eq!(
        db.lookup(ip("2606:4700:ffff:ffff:ffff:ffff:ffff:ffff")).asn,
        Some(13335)
    );
    assert_eq!(db.lookup(ip("2606:4701::")).asn, None);
}

#[test]
fn ranges_that_reach_the_end_of_the_address_space() {
    let mut builder = IpDbBuilder::new(sources());
    builder
        .add_network(ip("255.255.255.0"), ip("255.255.255.255"), 7)
        .unwrap();
    builder
        .add_network(ip("0.0.0.0"), ip("0.0.0.255"), 8)
        .unwrap();
    builder
        .add_country(
            ip("ff00::"),
            ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            "DE",
        )
        .unwrap();
    let db = IpDb::from_bytes(&builder.build().unwrap()).unwrap();
    assert_eq!(db.lookup(ip("255.255.255.255")).asn, Some(7));
    assert_eq!(db.lookup(ip("0.0.0.0")).asn, Some(8));
    assert_eq!(db.lookup(ip("0.0.1.0")).asn, None);
    assert_eq!(
        db.lookup(ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
            .country,
        Some("DE")
    );
}

#[test]
fn adjacent_ranges_of_one_network_are_merged() {
    let build = |ranges: &[(&str, &str)]| {
        let mut builder = IpDbBuilder::new(sources());
        for (first, last) in ranges {
            builder.add_network(ip(first), ip(last), 64_500).unwrap();
        }
        builder.build().unwrap()
    };
    let split = build(&[("192.0.2.128", "192.0.2.255"), ("192.0.2.0", "192.0.2.127")]);
    let whole = build(&[("192.0.2.0", "192.0.2.255")]);
    assert_eq!(split, whole, "two halves give the same file as the whole");
}

#[test]
fn rejects_bad_input_while_building() {
    let mut builder = IpDbBuilder::new(sources());
    assert!(matches!(
        builder.add_network(ip("10.0.0.9"), ip("10.0.0.1"), 1),
        Err(BuildError::BadRange { .. })
    ));
    assert!(matches!(
        builder.add_network(ip("10.0.0.1"), ip("::1"), 1),
        Err(BuildError::BadRange { .. })
    ));
    assert_eq!(
        builder.add_country(ip("10.0.0.1"), ip("10.0.0.2"), "usa"),
        Err(BuildError::BadCountry("usa".to_owned()))
    );
    builder
        .add_network(ip("10.0.0.0"), ip("10.0.0.255"), 1)
        .unwrap();
    builder
        .add_network(ip("10.0.0.128"), ip("10.0.1.255"), 2)
        .unwrap();
    assert_eq!(builder.build(), Err(BuildError::Overlap(ip("10.0.0.128"))));
}

#[test]
fn upstream_errors_name_the_line() {
    let mut builder = IpDbBuilder::new(sources());
    let bad = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\nnot an address\t1.0.0.1\t1\tUS\tX\n";
    match read_iptoasn(bad.as_bytes(), &mut builder) {
        Err(UpstreamError::Line { line, reason }) => {
            assert_eq!(line, 2);
            assert!(reason.contains("not an IP address"), "{reason}");
        }
        other => panic!("expected a line error, got {other:?}"),
    }
    match read_dbip_country("1.0.0.0,1.0.0.255\n".as_bytes(), &mut builder) {
        Err(UpstreamError::Line { line: 1, .. }) => {}
        other => panic!("expected a line error, got {other:?}"),
    }
    // Windows line ends and quoted fields are fine.
    assert_eq!(
        read_dbip_country(
            "\"9.9.9.0\",\"9.9.9.255\",\"CH\"\r\n".as_bytes(),
            &mut builder
        )
        .unwrap(),
        1
    );
}

#[test]
fn rejects_files_that_are_not_whole_and_valid() {
    let mut builder = IpDbBuilder::new(sources());
    read_iptoasn(IPTOASN.as_bytes(), &mut builder).unwrap();
    read_dbip_country(DBIP.as_bytes(), &mut builder).unwrap();
    let good = builder.build().unwrap();

    assert_eq!(
        IpDb::from_bytes(b"not a database").unwrap_err(),
        LoadError::NotAnIpDb
    );
    for len in 0..good.len() {
        assert!(
            IpDb::from_bytes(&good[..len]).is_err(),
            "cut at {len} of {}",
            good.len()
        );
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(
        IpDb::from_bytes(&longer).unwrap_err(),
        LoadError::TrailingBytes
    );

    let mut newer = good.clone();
    newer[8] = 2;
    assert_eq!(
        IpDb::from_bytes(&newer).unwrap_err(),
        LoadError::UnsupportedVersion(2)
    );

    // A table that claims billions of entries is refused before anything is allocated.
    let first_table = 8 + 4 + 4 + sources().network.len() + 4 + sources().country.len();
    let mut huge = good.clone();
    huge[first_table..first_table + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(IpDb::from_bytes(&huge).unwrap_err(), LoadError::TooLarge);
}

#[test]
fn damaged_files_never_panic() {
    let mut builder = IpDbBuilder::new(sources());
    read_iptoasn(IPTOASN.as_bytes(), &mut builder).unwrap();
    read_dbip_country(DBIP.as_bytes(), &mut builder).unwrap();
    let good = builder.build().unwrap();
    let probes = [
        "1.0.0.1",
        "8.8.8.8",
        "2001:4860::1",
        "::ffff:1.0.4.1",
        "10.0.0.1",
    ]
    .map(ip);
    for at in 0..good.len() {
        for flip in [0x01, 0x80, 0xff] {
            let mut damaged = good.clone();
            damaged[at] ^= flip;
            // Either refused, or a database whose lookups still work.
            if let Ok(db) = IpDb::from_bytes(&damaged) {
                for probe in probes {
                    db.lookup(probe);
                }
            }
        }
    }
}

/// DT-01: under 1 ms per flow, at the size of the real data sets (a few million ranges
/// in all). Built from evenly spread synthetic ranges; a lookup is a binary search, so
/// its cost depends on the number of ranges, not on their contents.
#[test]
fn lookups_take_well_under_a_millisecond_at_full_size() {
    const V4: u32 = 1_000_000;
    const V6: u128 = 300_000;
    let mut builder = IpDbBuilder::new(sources());
    let v4_step = u32::MAX / V4;
    for i in 0..V4 {
        let first = i * v4_step;
        let last = first + v4_step / 2;
        builder
            .add_network(
                IpAddr::from(first.to_be_bytes()),
                IpAddr::from(last.to_be_bytes()),
                i % 70_000 + 1,
            )
            .unwrap();
        builder
            .add_country(
                IpAddr::from(first.to_be_bytes()),
                IpAddr::from(last.to_be_bytes()),
                ["DE", "US", "JO"][(i % 3) as usize],
            )
            .unwrap();
    }
    let v6_step = u128::MAX / V6;
    for i in 0..V6 {
        let first = i * v6_step;
        let last = first + v6_step / 2;
        builder
            .add_network(
                IpAddr::from(first.to_be_bytes()),
                IpAddr::from(last.to_be_bytes()),
                (i % 70_000) as u32 + 1,
            )
            .unwrap();
    }
    for asn in 1..=70_000 {
        builder
            .name_network(asn, &format!("NETWORK-{asn}"))
            .unwrap();
    }
    let bytes = builder.build().unwrap();
    let db = IpDb::from_bytes(&bytes).unwrap();

    const LOOKUPS: u32 = 100_000;
    let mut found = 0;
    let started = Instant::now();
    for i in 0..LOOKUPS {
        let v4 = IpAddr::from(i.wrapping_mul(2_654_435_761).to_be_bytes());
        let v6 = IpAddr::from(
            u128::from(i)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c834)
                .to_be_bytes(),
        );
        found +=
            usize::from(db.lookup(v4).asn.is_some()) + usize::from(db.lookup(v6).asn.is_some());
    }
    let per_lookup = started.elapsed() / (2 * LOOKUPS);
    println!(
        "{} bytes; {per_lookup:?} per lookup ({found} of {} found)",
        bytes.len(),
        2 * LOOKUPS
    );
    assert!(found > 0, "the probes must hit some ranges");
    assert!(
        per_lookup.as_micros() < 1_000,
        "a lookup took {per_lookup:?}, the budget per flow is 1 ms"
    );
}

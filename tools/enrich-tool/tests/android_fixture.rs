// SPDX-License-Identifier: GPL-3.0-or-later
//! The IP database and tracker list the Android device tests use
//! (`androidTest/assets/test-ip.db` and `test-trackers.db`) must be exactly what the tool
//! builds from the text files next to them, so they cannot drift from them. To rebuild
//! them, from the repository root:
//!
//! ```sh
//! D=apps/android/app/src/androidTest
//! cargo run -p sentinel-enrich-tool -- build --iptoasn $D/ipdb/iptoasn.tsv \
//!     --dbip-country $D/ipdb/dbip-country.csv --network-source "IPtoASN test data" \
//!     --country-source "DB-IP Lite test data" --out $D/assets/test-ip.db
//! cargo run -p sentinel-enrich-tool -- trackers --radar $D/trackers/radar \
//!     --radar-source "Tracker Radar test data" \
//!     --app-trackers $D/trackers/app-trackers.json \
//!     --app-trackers-source "App tracker list test data" --out $D/assets/test-trackers.db
//! ```

#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use sentinel_enrich::upstream::{read_dbip_country, read_iptoasn};
use sentinel_enrich::upstream_trackers::{read_ddg_app_trackers, read_tracker_radar_domain};
use sentinel_enrich::{IpDb, IpDbBuilder, Sources, TrackerDb, TrackerDbBuilder};

fn android_tests() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/android/app/src/androidTest")
}

#[test]
fn android_test_database_matches_its_sources() {
    let dir = android_tests();
    let mut builder = IpDbBuilder::new(Sources {
        network: "IPtoASN test data".to_owned(),
        country: "DB-IP Lite test data".to_owned(),
    });
    let open = |name: &str| BufReader::new(File::open(dir.join(name)).unwrap());
    read_iptoasn(open("ipdb/iptoasn.tsv"), &mut builder).unwrap();
    read_dbip_country(open("ipdb/dbip-country.csv"), &mut builder).unwrap();
    let built = builder.build().unwrap();
    let committed = std::fs::read(dir.join("assets/test-ip.db")).unwrap();
    assert!(
        built == committed,
        "androidTest/assets/test-ip.db is out of date; rebuild it (see this file's header)"
    );
    // What the device test expects of it.
    let db = IpDb::from_bytes(&committed).unwrap();
    let info = db.lookup("10.0.2.2".parse().unwrap());
    assert_eq!(info.asn, Some(64_500));
    assert_eq!(info.network_owner, Some("SENTINEL-TEST-NET"));
    assert_eq!(info.country, Some("JO"));
}

#[test]
fn android_test_tracker_list_matches_its_sources() {
    let dir = android_tests();
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let mut builder = TrackerDbBuilder::new();
    let radar = builder.add_source("Tracker Radar test data").unwrap();
    let apps = builder.add_source("App tracker list test data").unwrap();
    assert!(
        read_tracker_radar_domain(
            &read("trackers/radar/ads.sentinel.test.json"),
            radar,
            &mut builder
        )
        .unwrap()
    );
    assert_eq!(
        read_ddg_app_trackers(&read("trackers/app-trackers.json"), apps, &mut builder).unwrap(),
        1
    );
    let built = builder.build().unwrap();
    let committed = std::fs::read(dir.join("assets/test-trackers.db")).unwrap();
    assert!(
        built == committed,
        "androidTest/assets/test-trackers.db is out of date; rebuild it (see this file's header)"
    );
    // What the device test expects of it.
    let db = TrackerDb::from_bytes(&committed).unwrap();
    let info = db.lookup("pixel.g.ads.sentinel.test").unwrap();
    let company = info.company.unwrap();
    assert_eq!(
        (company.value, company.domain),
        ("Sentinel Test Ads (apps)", "g.ads.sentinel.test")
    );
    assert_eq!(company.sources, ["App tracker list test data"]);
    let categories = info.categories.unwrap();
    assert_eq!(categories.value, ["Advertising", "Analytics"]);
    assert_eq!(categories.domain, "ads.sentinel.test");
    assert_eq!(categories.sources, ["Tracker Radar test data"]);
}

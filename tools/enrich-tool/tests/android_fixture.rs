// SPDX-License-Identifier: GPL-3.0-or-later
//! The IP database the Android device tests use (`androidTest/assets/test-ip.db`) must
//! be exactly what the tool builds from the text files next to it, so it cannot drift
//! from them. To rebuild it, from the repository root:
//!
//! ```sh
//! D=apps/android/app/src/androidTest
//! cargo run -p sentinel-enrich-tool -- build --iptoasn $D/ipdb/iptoasn.tsv \
//!     --dbip-country $D/ipdb/dbip-country.csv --network-source "IPtoASN test data" \
//!     --country-source "DB-IP Lite test data" --out $D/assets/test-ip.db
//! ```

#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use sentinel_enrich::upstream::{read_dbip_country, read_iptoasn};
use sentinel_enrich::{IpDb, IpDbBuilder, Sources};

#[test]
fn android_test_database_matches_its_sources() {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/android/app/src/androidTest");
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

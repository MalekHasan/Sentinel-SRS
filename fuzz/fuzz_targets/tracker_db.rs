// SPDX-License-Identifier: GPL-3.0-or-later
//! The tracker list from the feed (`trackers.db`, DT-06, audit A-49): a file it accepts
//! can be looked up with any name.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_enrich::TrackerDb;

fuzz_target!(|data: &[u8]| {
    let Ok(db) = TrackerDb::from_bytes(data) else {
        return;
    };
    let _ = (db.sources(), db.len());
    // Names made from the file's own text, so that the ones it lists are tried too.
    let text = String::from_utf8_lossy(data);
    for name in text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .filter(|name| !name.is_empty())
        .take(256)
    {
        let _ = db.lookup(name);
        let _ = db.lookup(&format!("www.{name}."));
    }
});

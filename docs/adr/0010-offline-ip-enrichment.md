# ADR-0010: Offline IP enrichment data

- Status: **Accepted** (Sprint 4; `crates/sentinel-enrich`, `tools/enrich-tool`)
- Date: 2026-10-15
- Implements: SRS DT-01; prepares DT-02 and DT-08

## Context

For every flow, Sentinel should say which network received the data, who owns that network, and roughly in which country the server is (DT-01). It must answer without asking anyone on the network, because a lookup service would learn every destination of every app on the phone (SRS §15). The answer must take under 1 ms per flow.

The public data sets that allow this are listed in [LICENCE-REVIEW.md](../LICENCE-REVIEW.md) §1: IPtoASN (network and owner, public domain under PDDL 1.0) and DB-IP Lite (country, CC BY 4.0). Both are published monthly as text files of address ranges, a few million lines in all.

| Option | For | Against |
| --- | --- | --- |
| MaxMind's MMDB format (DB-IP also publishes Lite files in it) | A standard format and existing reader crates | A reader dependency that parses a complex tree format; test files need a separate writer tool; MaxMind's own GeoLite2 data has a restrictive licence, so the format brings no extra data |
| Tables in the history database (SQLite) | No new format | Slower and larger; mixes public data with the user's private history; the history is per device and encrypted, the data set is the same for everyone |
| **Our own sorted range tables** | One small crate, no dependency; a lookup is a binary search; test files are built in tests | A format we must document and maintain |

## Decision

1. **One file, built offline** by `sentinel-enrich-tool build` from IPtoASN's `ip2asn-combined.tsv` and DB-IP Lite's country CSV. The build is deterministic (ranges sorted, adjacent ranges with the same value merged), so anyone can rebuild the file from the same upstream files and compare its SHA-256 with the one in the signed feed manifest.
2. **Format version 1**, described in `crates/sentinel-enrich/src/format.rs`: four sorted range tables (network and country, IPv4 and IPv6) and a table of network owner names. The names of the sources and their dates travel inside the file, so the app can show where each answer comes from (DT-02).
3. **Delivered as a data file in the signed feed** (ADR-0005), not bundled in the app or committed to this repository. The data changes every month; the feed already handles signatures, versions and expiry.
4. **Checked on load even though the feed is signed:** counts are bounded by the bytes present and by a fixed maximum, entries must be in order, country codes must be two capital letters, texts must be UTF-8 and short. A damaged file is refused; it cannot make the app allocate without limit or crash.
5. **Lookups never fail.** An unknown address gives empty answers. An IPv4 address written as IPv6, mapped (`::ffff:a.b.c.d`) or through NAT64 (`64:ff9b::a.b.c.d`, audit A-23), is looked up as IPv4. "Not routed" networks (AS 0) and DB-IP's unknown country ("ZZ") give no answer rather than a wrong one.
6. **Country is approximate:** it says where an address is registered or announced, not where a particular server stands. The app labels it so (DT-08).

## Verification

`crates/sentinel-enrich/tests/ipdb.rs`:

- lookups for IPv4, IPv6 and IPv4-mapped addresses, the first and last address of each range, ranges that reach the end of the address space, and gaps;
- adjacent ranges of one network give the same file as the whole range;
- overlapping ranges, mixed address families and malformed country codes are refused while building; upstream lines that do not parse are reported with their line number;
- every truncation of a valid file is refused; a table claiming billions of entries is refused before allocation; flipping any byte of a valid file never makes loading or lookups panic;
- speed at the size of the real data sets (1.3 million ranges, synthetic): 1.96 µs per lookup in a debug build and 561 ns in a release build on the development machine, against the 1 ms budget.

## Consequences

- The app holds the whole file in memory while monitoring. Its size with the real data sets has not been measured yet: the development sandbox cannot reach iptoasn.com or db-ip.com. It must be measured when the first feed is built, before Sprint 7 ships it; if it is too large, the format can store IPv6 starts as /64 prefixes or compress the tables in a version 2.
- DB-IP Lite requires attribution wherever results are shown: the "About and licences" screen (LICENCE-REVIEW L4) and the "why we believe this" details (DT-02).
- The database arrives in the indicator list ([ADR-0019](0019-indicator-feed-on-android.md)) as `ip.db`. Until a list with one is installed, phones show no network or country.

## Still open

- Company and category per destination come from the tracker list ([ADR-0011](0011-tracker-list.md)), not from this file.
- Measuring size, load time and memory with the real data sets on a phone.

# ADR-0011: Tracker list for company and category

- Status: **Accepted** (Sprint 4; `crates/sentinel-enrich`, `tools/enrich-tool`)
- Date: 2026-10-15
- Implements: SRS DT-06, the company and category part of DT-01, and their "why we believe this" (DT-02)

## Context

For every destination, Sentinel should say which company it belongs to and what kind of service it is: advertising, analytics, a content delivery network, and so on (DT-01, DT-06). As with the IP data ([ADR-0010](0010-offline-ip-enrichment.md)), it must answer offline and in under 1 ms per flow, and it must say where each answer comes from (DT-02).

The usable lists are in [LICENCE-REVIEW.md](../LICENCE-REVIEW.md) §1:

- **DuckDuckGo Tracker Radar**: one JSON file per third-party domain seen on websites, with its owner and categories. The US region has 21,406 files (2026-10-09). Only 9,006 of them name an owner or a category; the rest are domains seen but not described.
- **DuckDuckGo's app tracker list** (`android-tds.json`): 337 tracker domains seen in Android apps, with their owners and no categories. The copy available is dated July 2023.
- **Exodus Privacy**: names of tracker SDKs found inside apps. Its terms of reuse are not known yet (LICENCE-REVIEW L2), so it is not used.

Both DuckDuckGo lists are CC BY-NC-SA 4.0. That is acceptable while Sentinel is non-commercial (AM-08), and anything built from them is shared under the same licence.

Tracker Radar describes `doubleclick.net` (Google; Advertising) but not `g.doubleclick.net`. The app list names `g.doubleclick.net` (Google) but gives no category. A connection to `googleads.g.doubleclick.net` should get both answers, and each must still say which list it comes from.

| Option | For | Against |
| --- | --- | --- |
| Ship the JSON lists and read them on the phone | No new format | Megabytes of JSON for 9,300 useful entries; a JSON parser in the app; slow to load |
| Add the domains to the IP database file | One file | Different sources, licences and update cycles; the IP file is public domain and CC BY, so mixing in NC-SA data would put the whole file under NC-SA |
| **A second file of our own: a sorted domain table** | Small; a lookup is a few binary searches; the same checks as the IP file; its own licence | A second format to document and maintain |

## Decision

1. **A separate file, `trackers.db`**, built offline by `sentinel-enrich-tool trackers` from one Tracker Radar region folder and the app tracker list. The build is deterministic: files are read in name order and domains are sorted.
2. **Format version 1**, described in `crates/sentinel-enrich/src/trackers.rs`: the names of the lists with their dates; tables of company and category names; and the sorted domains. Each domain has a company and the lists that name it, or neither, and its categories and the lists that give them, or neither, and at least one of the two.
3. **What a list says about a domain covers the names below it.** For a hostname, the company comes from the hostname itself or from the nearest domain above it that has a company. The categories are found the same way, on their own. Each answer carries the listed domain it comes from and the lists that say so, and the app shows both ("From DuckDuckGo app tracker list 2023-07-06, entry g.doubleclick.net"). Domains match whole labels only: `notads.example` does not match `ads.example`.
4. **Entries that say nothing are left out.** A Tracker Radar domain with neither owner nor category is skipped, and so is a name that is not a plain domain (the real list has `%2a.googleapis.com`). When two lists name an owner for the same domain, the first list's name is kept, and both lists are given as its source.
5. **Checked on load, as the IP file is.** Counts are bounded, domains must be sorted, lower-case and valid, and every reference must exist. Texts with control characters or text-direction marks are refused, because company and category names are shown as they are.
6. **Only names are looked up.** A destination known only by its address gets no company. An address never matches a listed domain made of digits.
7. **Delivered as a data file in the signed feed** (ADR-0005), like the IP database; not bundled in the app. Its licence (CC BY-NC-SA 4.0) travels with it in the feed manifest.
8. **The history keeps each answer with its source** (schema version 5, [ADR-0009](0009-local-history-store.md)): the destination's company and categories, the listed domain each comes from, and the lists. The app detail screen adds up the companies of all of an app's destinations.

## Verification

- `crates/sentinel-enrich/tests/trackers.rs`: matching a domain and the names below it, case and the trailing dot, the nearest domain winning, company and categories from different domains, look-alike names, addresses, both upstream formats (with the fields the reader ignores), bad input while building, every truncation, every kind of bad reference, flipped bytes, and speed.
- `crates/sentinel-ffi`: a flow with a hostname carries its company and categories once a list is set, a flow without one carries none, and the history keeps both with their sources.
- `TrackerListTest` on the emulator: a connection whose TLS ClientHello names `pixel.g.ads.sentinel.test` is stored with the company from the app list test data and the categories from the Tracker Radar test data, each with its source and entry. `AppDetailTest` and `RtlTest` show both, and the companies, in English and Arabic.
- With the real lists (Tracker Radar US 2026-10-09 and the app list of 2023-07-06): 9,324 domains, a 416 KB file (118 KB gzipped), built in 0.7 s. `googleads.g.doubleclick.net` gets Google from the app list (`g.doubleclick.net`) and Ad Motivated Tracking and Advertising from Tracker Radar (`doubleclick.net`).
- Speed at 300,000 synthetic domains, half of the lookups not listed (the slowest case): 2.6 µs per lookup in a release build and 4.1 µs in a debug build, against the 1 ms budget.

## Consequences

- Tracker Radar is built from websites. App-only tracker domains appear only through the app list, which is three years old. Some app trackers will not be recognised. The app says so next to the companies: destinations the lists do not name may belong to other companies.
- Owners are the lists' "display names" (Google, Facebook, AppLovin), not legal entities. Parent companies are not followed.
- Categories are the lists' own words. The app translates the 25 categories Tracker Radar uses into Arabic and shows any other category as the list writes it.
- The list arrives in the indicator list ([ADR-0019](0019-indicator-feed-on-android.md)) as `trackers.db`. Until a list with one is installed, phones show no company or category.

## Still open

- SDK names per app (Exodus Privacy signatures) once L2 is answered.
- A commercial edition would need a licence from DuckDuckGo or other data (AM-08).

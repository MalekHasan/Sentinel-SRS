# ADR-0019: The indicator feed on Android: indicator files, delivery and installation

- Status: **Accepted** (Sprint 7; `crates/sentinel-ioc`, `crates/sentinel-feed`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS MS-10 ("Signed indicator feed built from public sources, with provenance (source, date, report link) on every indicator; weekly updates and urgent same-day updates"; "Feed signature and provenance checked on load"), SP-04 (rule-bundle signatures checked at start and every hour), §14.3 (HTTPS, signed bundles, rollback protection, no device identifiers, manual update from a file). Builds on [ADR-0005](0005-signed-feed-format.md), which defined the signed manifest and left the data files to this sprint.

## Context

[ADR-0005](0005-signed-feed-format.md) settled how a bundle is signed and checked: a DSSE-signed manifest listing every file with its SHA-256, a version that only goes up, an expiry, and trusted keys compiled into the app. Three things were still open before a phone can use a feed:

- **What an indicator file holds.** MS-10 asks for provenance on every indicator: its source, its date and the report that names it. [LICENCE-REVIEW.md](../LICENCE-REVIEW.md) asks that sources under different licences never mix in one file.
- **How a bundle reaches the phone, and how it comes into force.** It may come over the network or from a file. A download can stop half-way, a phone can lose power during an install, and a bad bundle must never replace a good one.
- **Where the trusted keys come from**, given that the secret keys never touch a networked computer ([FEED-SIGNING.md](../FEED-SIGNING.md)).

## Decision

1. **One indicator file per source**, `indicators-<source>.json` (`crates/sentinel-ioc`, schema 1).
   - The file names its source: a short id, which is also in the file name, its name, a link to its data, and its licence.
   - Each indicator gives what it names, the spyware or stalkerware family, the threat (`spyware` for mercenary spyware, `stalkerware`), the report's date (`YYYY-MM-DD`) and the report's `https` link. What it names is a domain (and every name below it), an IP address, an Android package name, or the SHA-256 of an app's signing certificate.
   - Values are written one way only (lower case, no trailing dot, addresses as Rust writes them), so matching is exact.
   - Local, private and special addresses are refused, so that a mistake in the feed cannot match a home network's own traffic.
   - The file is JSON, so the reviewer of a release reads the diff of indicators directly (FEED-SIGNING step 2).
2. **Every file is checked when it is loaded, although it is signed.** One indicator without its provenance, or with a value that is not what its kind says, refuses the whole bundle. So does an indicator file not named after its source, and an IP database or tracker list that does not load. Kinds and threats this version does not know are skipped and counted, so that a feed that also serves other editions (file hashes, for example) still installs.
3. **A manifest is judged before anything it lists is fetched**: signed by trusted keys, for this feed, newer than the list in force, not expired, created at most an hour ahead of the phone's clock. Each file is then fetched up to its listed size and no further.
4. **A bundle comes into force in one step** (`sentinel_feed::BundleStore`).
   - Each installed version has its own directory, `bundle-<version>`, and a file `current` names the one in force.
   - An update is staged in a separate directory, then moved file by file into a new bundle directory. Only the manifest and the files it lists are moved.
   - There it is checked again, signature, every file's size and SHA-256 and every file's contents, so nothing can change on the way.
   - Only then is `current` replaced, in one rename after its contents reached the disk, and older bundles are removed.
   - A crash at any point leaves either the old list or the new one in force, never a mix. A refused update leaves nothing behind.
5. **The list in force is checked again** when the app first opens it and every hour while monitoring runs (SP-04): signature, every file, every indicator's provenance. A list that fails is removed at once. After that, a good bundle of any version installs. This is how a bundle signed with a leaked key goes away once an app update drops that key (FEED-SIGNING.md).
6. **Delivery on Android** (`IndicatorFeed`):
   - The newest bundle is published as the assets of the GitHub release with the tag `feed`: the manifest and its files side by side, at fixed links.
   - The app fetches them over HTTPS when it opens if the last check is more than six hours old, every six hours from a job that needs a network (whether monitoring runs or not), and when the user taps "Check for a new list". Weekly lists and urgent same-day ones are then picked up within hours.
   - The requests carry nothing about the user or the phone. The `User-Agent` is "Sentinel", because Android's default names the phone's model. No cookies are sent.
   - Plain HTTP is refused by the app's network security configuration. Debug builds also allow the phone's own loopback address, where the device tests serve their lists.
   - A user without access to GitHub can import the list from a folder: the release's files, copied side by side.
7. **The trusted keys are compiled in** from every `keys/feed/*.pub` file (`crates/sentinel-ffi/build.rs`); a file that is not a key fails the build.
   - Adding a key is a reviewed commit of its public key, then an app release.
   - **There are no keys yet.** Until the maintainers make theirs offline, the app says it cannot check indicator lists and uses none.
   - Debug builds also trust the key that signed the device tests' bundles (`apps/android/scripts/make-test-feed.sh`). Its secret key was deleted once they were signed, so nobody can sign with it. Release builds trust `keys/feed` only.
8. **The IP database and tracker list arrive in the same bundle** (`ip.db`, `trackers.db`; [ADR-0010](0010-offline-ip-enrichment.md), [ADR-0011](0011-tracker-list.md)). They are read only from a list that passed its last check. A running monitor loads them again when a new list comes into force.
9. **The main screen shows the list in use**:
   - its date, version and number of indicators, and its sources by name;
   - that it is out of date once it expires, while still using it (an old list is better than none, ADR-0005);
   - what the last check found;
   - "Check for a new list" and "Import from a folder".

   A failed check says only that the list could not be verified; the detail goes to the log.

## Verification

- `sentinel-ioc` (8 tests):
  - the format is fixed by a test;
  - an indicator without a family, a date (or with an impossible one) or an `https` report link refuses the file, and so does a source without its id, name, link or licence;
  - each kind refuses values not written its one way, and local and private addresses;
  - unknown kinds and threats are skipped and counted;
  - another schema, unknown fields and oversized files are refused;
  - indicator files are known by name.
- `sentinel-feed` (`tests/store.rs`, 4 tests):
  - only listed files are installed; an update replaces the old bundle;
  - offers are judged before fetching: up to date, newer, older, unsigned, expired;
  - a tampered, incomplete, wrongly signed or refused bundle changes nothing and leaves nothing behind;
  - a bundle that fails its re-check is removed, after which an older good bundle installs, as after a key is dropped; a pointer to a missing bundle is cleared.
- `sentinel-ffi` (`feed` tests, 5):
  - offer, install, status with sources, licences and counts, files given only from the checked list, re-check after reopening;
  - refused for an indicator without its report, an indicator file named after another source, and a broken IP database or tracker list;
  - a changed file is removed at the re-check;
  - no keys, too few keys or a bad key open nothing, and every compiled-in key is a key;
  - the device tests' bundles install in order.
- On the Android 14 emulator (`FeedTest`), served over HTTP on the phone's loopback address:
  - nothing published, then version 1 installed, then up to date, then version 2 installed;
  - an older list, a list changed after signing, a file larger than listed and a list with a file missing are each refused, and version 2 stays in force;
  - the requests' `User-Agent` is "Sentinel";
  - a list whose file changed on the phone is removed at the next check, and its IP database is no longer used;
  - the main screen shows the list's date, version, count and source, the outcome of the last check, that it is out of date, that a check is running, and that this build has no keys.
- `DestinationFactsTest` and `TrackerListTest` now receive their data through a signed list, the way phones will. `RtlTest` shows the indicator list section in Arabic, right to left.

## Consequences

- **No phone gets a list until two owner tasks are done.** The maintainers must make the signing keys offline and commit their public keys (FEED-SIGNING.md). Each source's licence must be confirmed, and Amnesty Tech and Citizen Lab asked about redistribution (LICENCE-REVIEW.md L1 and L3), before real indicators are published.
- **Building the feed from the sources is not automated yet.** `tools/feed-builder` (converting Amnesty's and Citizen Lab's STIX2 files and Echap's lists into indicator files) is still to come. Until then, files can be written by hand in the format above.
- **The fixed release tag means one list at a time.** Replacing the assets of the `feed` release while a phone is downloading gives it a manifest and files from different versions. The SHA-256 check refuses that, and the next check gets a consistent set. Older versions can be kept as their own releases for the record.
- **A list removed at the re-check stays in memory until monitoring restarts** for the IP database and tracker list, which are enrichment only. Indicator matching (next task) must stop using a removed list at once.
- **Checking a list again hashes all its files**, the IP database included, every hour while monitoring runs. That costs little for the sizes expected, and must be measured with the real IP database (ADR-0010).
- **Folder import reads the files directly in the chosen folder.** A bundle whose files sit in subfolders installs only over HTTPS.

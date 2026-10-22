# ADR-0021: Checking the history against a new indicator list (retro-hunt)

- Status: **Accepted** (Sprint 7; `crates/sentinel-store`, `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS MS-02 ("Retro-hunt: when new indicators arrive, re-check stored DNS and flow history and alert on past matches with dates and device"; acceptance: "Past test record matched after feed update"). Builds on [ADR-0020](0020-indicator-matching.md), which matches traffic as it happens, and the history of [ADR-0009](0009-local-history-store.md).

## Context

Indicators are often published weeks or months after the attack they come from. A phone that reached a spyware server in March learns about it only from a list that arrives in May. [ADR-0020](0020-indicator-matching.md) matches traffic as it happens, so it cannot find that. The history keeps what is needed to look back:

- **Flows from the last 30 days** (SRS §13.2), each with its app, its remote address, its name (from a DNS answer or the TLS server name, if any) and its times.
- **Daily totals for older days**, per app and destination. A day keeps the destination's name, or its address when the connections had no name; it does not keep both.
- **No log of DNS lookups.** The history keeps the names of connections, not every lookup. A lookup that led to no connection is not kept.

Some questions had to be settled:

- **When to look back.** A list can arrive while monitoring is off (the six-hourly job), and the app can be killed during a long check.
- **How not to repeat ourselves.** A newer list repeats most indicators of the one before. A match reported live, or by an earlier check, or that the user dismissed, should not come back with every list.
- **What the alert says.** MS-02 asks for the dates. On Android the device is always this phone.

## Decision

1. **Look back once per list.** The history keeps the list it was last checked against (`meta`, keys `hunted` and `hunted_files`; no schema change): its version, and what its files hold. The latter is the first eight bytes of one SHA-256 over every listed file's path and SHA-256 (`Manifest::files_digest`).
   - A check runs when a list comes into force: right after an install, before the update returns, and again when monitoring starts, should a check have been cut short.
   - Nothing runs when the history was already checked against the version in force with the same files.
   - The files matter because a version can come back with other files (amended after audit A-26). After a bundle signed with a leaked key is dropped, a good bundle of any version installs (ADR-0019 decision 5), its own number included. That bundle must still be looked for.
   - Both are recorded only once the check is complete, so a check cut short runs again. A history checked before the files were kept is checked once more; what was reported is not repeated (decision 4).
2. **Everything the history holds is checked** (`Store::past_destinations`): every app, name and address it holds connections to, with the first and last time and how many connections, from kept flows and from daily totals. A name is matched with the list's domains (the name or a domain above it) and an address with its addresses, each on its own, as live matching does.
3. **One alert per app and indicator**, from the same `known-indicator` rule as a live match.
   - Its evidence adds the past connections: when the first was made, when the last ended, and how many there were. Rolled-up days count from their midnight UTC.
   - What was seen is the name, `connection_name` (the history does not keep whether a DNS answer or the TLS handshake gave it), or the address.
   - It is Critical like a live match (§8.3): the traffic happened, whenever it is found. It offers to block the app, and is shown as "Known traces of spyware found in past traffic", with how many connections there were and on which days.
4. **What was reported once is not reported again.** A match is skipped when any `known-indicator` alert, open or dismissed, already names the same app and indicator (alerts are kept a year, §13.2). This covers a match seen live, one found by an earlier check, and one the user put away. A newer list raises only what its new indicators find.
5. **One check at a time**, under a lock in the history. The core does the work. Kotlin calls it on a background thread (`History.hunt`), because a check reads the whole history.

## Verification

- `sentinel-store`: past destinations cover kept flows (name and address) and rolled-up days (the name, or the address of connections without one), with first, last and count, oldest first. The version and files checked survive reopening and are replaced, not added to.
- `sentinel-feed`: the files digest is the same for two manifests that list the same files, whatever their versions and dates, and differs when a file's SHA-256 or path differs or a file is added.
- `sentinel-detect`: a match found in the history is Critical and offers the same actions as a live one. The stored JSON of its evidence is fixed, and it is the same sighting as a live match of the same app and indicator.
- `sentinel-ffi`:
  - with no list there is no check;
  - a list finds a rolled-up day by name, kept flows by name (two connections, two addresses, one alert with both dates) and a kept flow by address, each with its provenance, and raises nothing for traffic it does not name;
  - checking again against the same version does nothing;
  - the same version with other files is checked again (A-26), and once only;
  - a newer list that adds an indicator raises only the new match, although an earlier alert was dismissed;
  - a match already reported live is not reported again.
- On the Android 14 emulator (`IndicatorAlertTest`):
  - with no list in force, a TLS connection naming a name under the planted indicator raises nothing, and is kept in the history;
  - when the test list is then installed, a Critical alert names the app, the name, the planted indicator and the time of the connection;
  - a newer list reports nothing more.

  `RtlTest` shows the alert in Arabic, right to left, with its count and days.

## Consequences

- **Lookups that led to no connection are not found.** That includes, for example, a spyware domain already taken down at the time, which got no answer. Keeping every lookup would mean a DNS log in the history: more data about the user, kept for a month. That is left until the beta shows such matches are missed in practice.
- **Older days lose the address of named connections**, so an address indicator finds only the last 30 days of named traffic, and older traffic that had no name.
- **A check reads the whole history.** For 30 days of flows of a heavy user, that is some hundred thousand rows grouped in SQLite before matching. It must be measured on the reference phones (NF-03). It runs off the main thread and once per list.
- **The result of a check is shown on the main screen**: "Known traces found", or "No known traces found" with the date of the list and its limits ([ADR-0022](0022-result-wording-and-advice.md)). The app also checks the history when it opens, should a check not have run.
- **A check runs after an install even while the history is being wiped.** It then reads the old database. The wipe still deletes the database and the key, so nothing it found is kept.

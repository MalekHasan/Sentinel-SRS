# ADR-0009: Local history store

- Status: **Accepted and implemented** (Sprint 2; `crates/sentinel-store`, `apps/android/.../History*.kt`)
- Date: 2026-10-14
- Implements: SRS §13 (schema), §13.2 (retention, one-tap wipe), NF-11; THREAT-MODEL-A I3, I4, T4

## Context

Sentinel keeps a detailed record of what every app did: which servers it reached, when, and how much it sent. That record is the product, and it is also surveillance data if anyone else gets it (SRS §15). SRS §13 asks for one schema in an encrypted SQLite database (SQLCipher) in every edition, with the key held by the platform key store.

Two places could own the database on Android:

| Option | For | Against |
| --- | --- | --- |
| Kotlin, with the `sqlcipher-android` library | No native crypto build | Android only; the desktop, gateway and Phone Check editions would each need their own copy of the schema and retention logic |
| Rust core, with `rusqlite` and SQLCipher built in | One schema, one set of tests for every edition (ADR-0001); the engine can write flows without crossing into Kotlin | SQLCipher needs a crypto library: OpenSSL is compiled from source for each Android ABI (about a minute each in CI) |

## Decision

1. **The store is a Rust crate, `sentinel-store`, built on `rusqlite` with SQLCipher (community edition) and a vendored OpenSSL 3.** It is shared by every edition.
2. **The key is 32 random bytes, used as a raw SQLCipher key.** No password stretching is needed for a random key, so opening is fast. On Android the key is generated once, wrapped with an AES-GCM key that lives in the Android Keystore and cannot be exported, and stored wrapped in app-private storage. The key and the database live in no-backup storage. Only the unwrapped key is passed to Rust, which keeps it in zeroizing memory while it builds the `PRAGMA key` text; Kotlin clears its copy right after. If the wrapped key cannot be unwrapped (the Keystore was reset) or the file fails to open, the old history is unreadable for good: the app deletes it and starts a new one rather than stop monitoring.
3. **Schema version 1** has the §13.1 tables Phase A needs now (`app`, `flow`), plus two the SRS does not define: `flow_daily` (the §13.2 roll-up) and `monitoring_gap` (SP-03). Later tables arrive as new versions; `PRAGMA user_version` tracks them, and a database from a newer Sentinel is refused instead of damaged. Version 2 (Sprint 3) adds an index on `flow_daily` by app, for the app detail screen. Version 3 adds the bytes each flow and daily total carried while the user was away (CM-06), and sets the SRS `while_away` flag on flows that carried any. Version 4 adds the SRS `destination` table, keyed by hostname or by address when no name is known, with two columns the SRS does not have: the sources of the network and of the country (DT-02). Version 5 adds where the company and the categories come from (DT-06, [ADR-0011](0011-tracker-list.md)): the listed domain each was found under and the lists that give it. Version 6 adds the SRS `alert` table ([ADR-0012](0012-alerts.md)): rule id, severity, evidence as JSON, creation time and state; its `title` and `body` stay empty, as the app writes an alert's text in the user's language. Version 7 adds when each alert was notified, for the rate limit (AL-03). Version 8 adds the allow-list of rules the user allowed per app (AL-05); the user's answer on each alert is kept in the SRS `alert.user_feedback` column. Version 9 adds when the history began and the names each app has used, for new apps and new destinations (CM-04, [ADR-0013](0013-first-seen.md)). Version 10 adds the network settings last seen, so that a change is found even if it happened while Sentinel was not running (CM-07, [ADR-0014](0014-network-settings.md)). Version 11 adds the SRS `rule` table, holding firewall rules for now (CM-10, [ADR-0015](0015-firewall-rules.md)). Version 12 adds the firewall mode and when it was turned on (CM-08, [ADR-0016](0016-firewall-modes.md)). Version 13 adds network isolation while it is on (RA-03, [ADR-0017](0017-isolation.md)). Version 14 adds the SRS `action_journal` table: every change to the firewall, with the setting before and after (SRS §9, [ADR-0018](0018-action-journal.md)). Version 15 adds the special access each app held at the last check: accessibility, device admin or notification access (ID-12, [ADR-0024](0024-special-access.md)). Version 16 adds the device settings last seen: wireless debugging and the certificate authorities the user added (ID-03, ID-10, [ADR-0025](0025-device-posture.md)). Version 17 adds the SRS `sensor_use` table: each use of the microphone or camera, with the app as found or guessed and whether the user was present (SE-01, SE-04, [ADR-0027](0027-sensor-monitoring.md)).
4. **The engine writes flows straight into the store**, in the same 250 ms batches that go to the app, once when a flow starts and again when it ends. Monitoring still runs if the history cannot be opened; failed writes are counted in the engine's snapshot.
5. **Retention:** flows older than the setting (default 30 days) are summed into daily totals per app, destination and protocol, then deleted (§13.2). Running it twice changes nothing.
6. **One-tap wipe** deletes the database file and its journal files, the wrapped key and the Keystore key. The app allows it only while monitoring is off, because the engine holds the database open.
7. **Write-ahead logging** keeps small frequent writes cheap on flash storage. SQLCipher encrypts the log too.

## Verification

On the Android 14 emulator in CI (since 6318869):

- `HistoryKeyTest`: the key is created once and the same key returns; the raw key never appears in the stored file; wipe removes the database, its journal and the key, and the next history starts empty.
- `GapLogTest`: gaps live in the history, and their text is not readable in the database files.
- `MonitoringTest`: the test's own connection is in the history with its package within 1 s, and is closed after the stop.

In Rust, `sentinel-ffi` checks that the engine stores a flow after its first batch and its end in the same row. `crates/sentinel-store/tests/store.rs` runs against a real SQLCipher database:

- No plaintext (hostnames, package names, the SQLite header) appears in the database file or its write-ahead log; a wrong key is refused. Removing the key makes this test fail, which shows that it really checks the encryption.
- A flow's start and end become one row; the same engine id in another session is another flow; an end whose start was not seen is stored whole.
- Retention rolls up old flows exactly once and adds late flows to existing totals.
- One gap is open at a time; wipe leaves no files behind; reopening keeps the data.

## Consequences

- The Android build compiles OpenSSL for three ABIs. CI caches the result.
- Binary releases must carry the SQLCipher (BSD-3-Clause) and OpenSSL (Apache-2.0) notices ([LICENCE-REVIEW.md](../LICENCE-REVIEW.md)).
- The open-source community edition of SQLCipher has no paid features we need.

## Still open

- When the history is reset (lost key or damaged file), the user is not told yet. That belongs with alerts (Sprint 5).
- Flows that were open when the process died keep no end time. Their start time is still correct, and retention still rolls them up.
- Storage-size checks against the §13.2 target (200 MB on mobile) need a phone-scale data set (Sprint 9).

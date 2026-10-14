# ADR-0009: Local history store

- Status: **Accepted** (Sprint 2; `crates/sentinel-store`)
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
2. **The key is 32 random bytes, used as a raw SQLCipher key.** No password stretching is needed for a random key, so opening is fast. On Android the key is generated once, wrapped with an AES-GCM key that lives in the Android Keystore and cannot be exported, and stored wrapped in app-private storage. Only the unwrapped key is passed to Rust, which keeps it in zeroizing memory while it builds the `PRAGMA key` text. The Kotlin side is Sprint 2 work (S2.2b).
3. **Schema version 1** has the §13.1 tables Phase A needs now (`app`, `flow`), plus two the SRS does not define: `flow_daily` (the §13.2 roll-up) and `monitoring_gap` (SP-03). Later tables arrive as new versions; `PRAGMA user_version` tracks them, and a database from a newer Sentinel is refused instead of damaged.
4. **Flows are written once when they start and updated when they end**, so a flow is in the history within the engine's batch delay (CM-01) and keeps its final byte counts.
5. **Retention:** flows older than the setting (default 30 days) are summed into daily totals per app, destination and protocol, then deleted (§13.2). Running it twice changes nothing.
6. **One-tap wipe** deletes the database file and its journal files; the app deletes the wrapped key and the Keystore key.
7. **Write-ahead logging** keeps small frequent writes cheap on flash storage. SQLCipher encrypts the log too.

## Verification

`crates/sentinel-store/tests/store.rs`, against a real SQLCipher database:

- No plaintext (hostnames, package names, the SQLite header) appears in the database file or its write-ahead log; a wrong key is refused. Removing the key makes this test fail, which shows that it really checks the encryption.
- A flow's start and end become one row; the same engine id in another session is another flow; an end whose start was not seen is stored whole.
- Retention rolls up old flows exactly once and adds late flows to existing totals.
- One gap is open at a time; wipe leaves no files behind; reopening keeps the data.

## Consequences

- The Android build compiles OpenSSL for three ABIs. CI caches the result.
- Binary releases must carry the SQLCipher (BSD-3-Clause) and OpenSSL (Apache-2.0) notices ([LICENCE-REVIEW.md](../LICENCE-REVIEW.md)).
- The open-source community edition of SQLCipher has no paid features we need.

## Still open

- Flows that were open when the process died keep no end time. Their start time is still correct, and retention still rolls them up.
- Storage-size checks against the §13.2 target (200 MB on mobile) need a phone-scale data set (Sprint 9).

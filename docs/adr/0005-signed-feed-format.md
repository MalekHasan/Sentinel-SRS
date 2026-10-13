# ADR-0005: Signed feed format

- Status: Accepted (A0 Spike 4; implemented in `crates/sentinel-feed`)
- Date: 2026-10-13
- Implements: SRS MS-10, §14.3, SP-04

## Context

Every edition downloads an indicator feed: stalkerware and spyware indicators first, later tracker and IP data. If someone can tamper with that feed, they can hide a real infection (by removing indicators) or cause panic (by adding false ones). The SRS requires:

- Ed25519 signatures with keys kept offline;
- version and rollback protection;
- provenance on every indicator;
- manual import from a file;
- re-checking signatures at start and every hour (SP-04).

The A0 plan asked us to choose between [TUF](https://theupdateframework.io/) (through the `tough` crate) and our own small signed manifest.

## Decision

Use a **small signed manifest in a DSSE envelope**, not full TUF, for now.

| Part | Choice |
| --- | --- |
| Bundle | A directory of data files plus `manifest.dsse.json` |
| Manifest | JSON: `schema`, `feed`, `version`, `created`, `expires`, and `files` (path, SHA-256, size). Unknown fields are rejected. |
| Envelope | [DSSE v1](https://github.com/secure-systems-lab/dsse). The signature covers the payload type and the exact manifest bytes, so there is no JSON canonicalisation problem. |
| Signatures | Ed25519 with strict verification; `threshold` distinct trusted keys must sign. Key ID hints are not trusted. |
| Trust root | Public keys compiled into each app. Phase A: two keys, held by two maintainers, threshold 1. |
| Rollback | An update must have a strictly higher `version` than the installed bundle. |
| Freeze | An update must not be expired. An installed bundle that has expired keeps working, but the app shows that the list is out of date (MS-15 shows the list date anyway). |
| Clock | `created` may be at most one hour in the future, to tolerate slightly wrong phone clocks. |
| Paths | Only plain relative paths with safe ASCII characters; no `..`, no absolute paths, no symbolic links. A bundle cannot touch anything outside its folder. |
| Limits | Envelope ≤ 1 MiB, ≤ 1000 files, so a hostile manifest cannot exhaust memory. |
| Tooling | `sentinel-feed-tool`: `keygen`, `manifest`, `sign` (offline), `verify`. |

Provenance (source, date and report link per indicator) lives inside the data files, whose format is defined in Phase A Sprint 7. The manifest guarantees those files are exactly what the maintainers signed.

## Why not TUF now

TUF protects against more: compromise of a single online key, through separate roles (root, targets, snapshot, timestamp) and threshold-signed key rotation. We do not need most of that yet:

- The feed carries data only. App binaries are updated by F-Droid, Google Play or GitHub releases, which have their own signing.
- There is no online signing key: every bundle is signed offline. So there is no timestamp or snapshot key to protect.
- With two maintainers, TUF's separate roles would be held by the same two people anyway.

A small format is easier to audit, has a handful of dependencies, and is easy to port to every edition.

## Consequences

- **Key rotation needs an app update.** If a signing key is lost or leaked, we ship a new app version with a new trust root. This is acceptable while app updates are frequent; it is the main reason to revisit TUF.
- A leaked key lets an attacker sign bundles until the app update arrives. Mitigations: keys only on offline machines, a threshold of 2 once there are three maintainers, and short expiry (14 days) so stale bundles are visible.
- The format is versioned (`schema` and the payload type). Moving to TUF later means a new payload type, and apps can accept both during the switch.

**Revisit when:** there are more than three maintainers, the feed ships to more than one edition, or we want key rotation without an app update.

## Tests

`crates/sentinel-feed/tests/feed.rs` checks:

- accepted when correctly signed;
- rejected for: untrusted key, modified payload, wrong payload type, repeated signatures from the same key, misleading key IDs, rollback, replay, expiry, future creation date, wrong feed name, modified, resized or missing files, symbolic links;
- an installed bundle stays usable after it expires, but reports it.

The DSSE encoding is checked against the example in the DSSE specification.

# Contributing to Sentinel

Thank you for helping. Sentinel is free software under the [GPL-3.0-or-later](LICENSE). By contributing, you agree that your contribution is licensed under the same terms.

## Before you start

- Read [docs/PLAN.md](docs/PLAN.md) to see which phase we are in. We only build what the current phase needs.
- Requirements live in [Sentinel-SRS.md](Sentinel-SRS.md). Every requirement has an ID such as `CM-01` or `MS-10`.
- Big technical decisions are recorded as ADRs in [docs/adr/](docs/adr/). If your change needs a new decision, write an ADR first.
- Security problems go through [SECURITY.md](SECURITY.md), never a public issue.

## Pull requests

- Name the SRS IDs your change implements in the PR title or description, for example `CM-01: record UDP flows`.
- Each requirement needs at least one automated test that checks its acceptance criterion from the SRS.
- Keep PRs small and focused. `main` is protected; every PR needs one review.
- Every new source file starts with an SPDX header:

  ```rust
  // SPDX-License-Identifier: GPL-3.0-or-later
  ```

## Checks CI runs (run them locally first)

Rust:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Android (needs the Android SDK):

```sh
cd apps/android && ./gradlew lint testDebugUnitTest
```

## Rules that are never negotiable

These come from SRS §15.3 and NF-11. A PR that breaks one will not be merged.

- No telemetry, analytics or crash reporting that sends data off the device.
- No capture of content: no audio, video, screenshots, keystrokes or message bodies.
- No hidden mode: the app is always visible while it runs.
- No remote viewing or control, and no monitoring of devices the user does not own.
- Results never say "clean" or "safe"; they say "Known traces found" or "No known traces found".

## Language

Code, comments and docs are in English. User-facing text is in English and Arabic. Arabic strings are reviewed by a native speaker before release.

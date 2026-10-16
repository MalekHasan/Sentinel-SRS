# Working on Sentinel

Read [docs/PLAN.md](docs/PLAN.md) and the current phase plan ([docs/PHASE-A-ANDROID.md](docs/PHASE-A-ANDROID.md)) before starting. Requirements live in [Sentinel-SRS.md](Sentinel-SRS.md); every requirement has an ID (`CM-01`, `MS-10`, …) that commits, tests and docs refer to.

## How every task is done: the engineering loop

The project owner asked that every task follow this loop, from understanding to final report.

1. **Understand.** Read the relevant code, docs and ADRs first. Never guess about code you have not inspected.
2. **Plan.** List the steps, the affected components, and what could regress. Keep the plan proportional to the task.
3. **Implement.** Make focused, minimal changes in the existing style. No unrelated refactors, no unrequested features, no test-specific hacks.
4. **Verify.** Run the real checks (below) and read their output. If one fails, find the root cause, fix it, and rerun. Never claim a check passed unless it did.
5. **Review.** Re-read the diff for correctness, edge cases, security and regressions. Check every acceptance criterion. Delete temporary files.
6. **Iterate** until the acceptance criteria are met or there is a real blocker. Do not repeat a failed approach without new evidence, and never weaken a test to make it pass.

Stop and ask when a requirement is ambiguous, an action is destructive or irreversible, or a blocker cannot be resolved safely.

Finish each task with a report: what was built, which files changed, which checks ran and their actual results, and what remains (limits, assumptions).

## Checks

| Area | Command | Notes |
| --- | --- | --- |
| Rust format | `cargo fmt --all --check` | |
| Rust lint | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | |
| Rust tests | `cargo test --workspace --all-features --locked` | IPv6 tests skip on hosts without IPv6; CI sets `SENTINEL_REQUIRE_IPV6=1` |
| Licences, advisories | `cargo deny check` | |
| Packet engine lab | `sudo crates/sentinel-vpn/lab/run-lab.sh /tmp/lab` | Needs root, `iproute2`, `iperf3`; see the lab README |
| Android | `cd apps/android && ./gradlew assembleDebug lintDebug :app:connectedDebugAndroidTest` | Needs the Android SDK and NDK; see [docs/ANDROID-BUILD.md](docs/ANDROID-BUILD.md) |

CI (`.github/workflows/`) runs all of these on every push.

In the Claude Code cloud sandbox, `dl.google.com` is blocked, so Android builds cannot run there. They are verified in GitHub Actions instead: push, then read the job logs.

## Rules that are never negotiable

These come from SRS §15.3 and NF-11; see [CONTRIBUTING.md](CONTRIBUTING.md).

- No telemetry, no content capture, no hidden mode, no remote features.
- Results never say "clean" or "safe".
- Every source file starts with `SPDX-License-Identifier: GPL-3.0-or-later`.
- `unsafe` is denied workspace-wide; each exception is one reviewed line with a `SAFETY:` comment.
- Third-party code in `third_party/` keeps its licence, and every change to it is listed in its `PATCHES.md`.
- Decisions that change architecture get an ADR in `docs/adr/`.

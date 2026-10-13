# ADR-0001: Rust for the shared core

- Status: Proposed
- Date: 2026-10-13

## Context

The SRS (§3.1) requires one shared core for every edition: event normalisation, correlation, rule engine, destination tracing, indicator matching and encrypted storage. That core runs on Windows, macOS, Linux, Android, iOS and a Raspberry Pi gateway. It processes untrusted input (network metadata, phone backups, indicator files), so memory safety matters. On TVs and phones it must stay small and fast (DV-09, NF-03).

## Decision

Write the shared core in Rust, as a Cargo workspace of small crates (`sentinel-model`, `sentinel-ioc`, `sentinel-feed`, `sentinel-store`, `sentinel-scan`, later `sentinel-enrich` and `sentinel-rules`).

- Bindings: Tauri commands on desktop; UniFFI for Kotlin (Android) and Swift (Apple); cargo-ndk for Android builds.
- Storage: `rusqlite` with SQLCipher; keys in the OS key store.
- Windows APIs: `windows-rs`; ETW through `ferrisetw`.
- Linux eBPF (Phase E): `aya`.
- File scanning (MS-06, Phase D): YARA-X.
- Gateway DNS (Phase B): `hickory-dns`; HTTP API with `axum`.

## Consequences

- One implementation of the detection logic, tested once (NF-13: ≥ 80% coverage on the core).
- No garbage-collector pauses or large runtime on phones and TVs.
- Rust has a learning curve. At least one team member must be fluent, and reviews must enforce `clippy` and `cargo deny`.
- Cross-compiling for Android and ARM64 needs CI setup in A0.

## Alternatives considered

- **Go:** easier to learn, and Portmaster uses it. But it has a garbage collector, larger binaries, and weaker bindings for Android and iOS (gomobile) than UniFFI.
- **C++:** no memory safety, which the SRS explicitly asks for (§15.4).
- **Kotlin Multiplatform:** good on mobile, but weak for Windows services and Linux eBPF.

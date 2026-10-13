# Sentinel — Project Plan

Version 0.1 · Oct 2026 · Status: **Proposed** (merging this into `main` means the team accepts it)

This plan turns the [SRS](../Sentinel-SRS.md) into something a small team can deliver. The SRS describes the full product: seven platforms, a kernel driver, three external audits and 18 months of parallel work. This plan keeps that as the destination. It changes the order and the first steps so that every phase ships something useful on its own.

Related documents:

- [Phase A: Phone Check, detailed plan](PHASE-A-PHONE-CHECK.md): the next thing we build
- [SRS amendments](SRS-AMENDMENTS.md): problems found in the SRS and proposed fixes
- [Sustainability model](SUSTAINABILITY.md): how a free product pays its costs
- [Architecture decision records](adr/): the key technical decisions and why

## 1. Goals

1. Ship a free, Arabic-first tool that lets at-risk people check their phones for known state-grade spyware (SRS §8A). This is the SRS's own top priority.
2. Grow it, one platform at a time, into the full Sentinel product described in the SRS.
3. Stay trustworthy: open source, no telemetry, honest result wording, anti-abuse rules (SRS §15.3) as release blockers.
4. Stay alive: every phase must be fundable and maintainable by a small team (see [SUSTAINABILITY.md](SUSTAINABILITY.md)).

## 2. Assumptions

| Assumption | If it is wrong |
| --- | --- |
| Team of 2–4 people, at least one comfortable with Rust and one with TypeScript/React | With 1–2 people, roughly double every duration below |
| The product is free and non-commercial | Re-check data and engine licences (SRS-AMENDMENTS AM-08, ADR-0004) |
| Durations are estimates for planning, not commitments | Re-plan at every phase gate |

## 3. Phases

Each phase ends with a gate. Only the next phase is planned in detail; later phases are re-planned when their predecessor passes its gate.

| Phase | Rough timing (3 people) | Ships | Main SRS requirements |
| --- | --- | --- | --- |
| **A0 Foundations** | Weeks 1–2 | Repo, CI, licence review, engine spikes, threat model, partner outreach | §20.1 P0 |
| **A Phone Check** | Months 1–4 | Desktop app (Windows, macOS, Linux) that checks an iPhone backup or Android acquisition against a signed indicator feed | MS-04, MS-05, MS-10 to MS-15 |
| **B Network Sentinel, DNS mode** | Months 4–7 | Raspberry Pi / Docker DNS resolver that matches every home device's lookups against indicators, with retro-hunt | MS-01 to MS-03, MS-08, DT-01, DT-02, DT-06 to DT-08, DV-10 |
| **C Android** | Months 6–11 | Android app with per-app connection view, trackers, basic sensor monitoring, blocking | CM, SE, DL, DT, ID and RA subsets (see 3.3) |
| **D Windows, user mode** | Months 10–16 | Full Windows desktop edition without a kernel driver | CM, SE, DL, ID, RA, DV subsets (see 3.4) |
| **E Later** | 16+ | Kernel driver, macOS, Linux, TV, iOS companion, gateway flow mode | Remainder of the SRS |

### 3.1 Phase A: Phone Check

Detailed in [PHASE-A-PHONE-CHECK.md](PHASE-A-PHONE-CHECK.md).

- **Why first:** it is the SRS's top priority, it needs no kernel driver, no VPN and no store approval, and an easy Arabic interface on top of Amnesty's MVT does not exist today.
- **Gate:** detects all public MVT test cases; runs fully offline; decrypted backups are gone after a scan (file-system audit); feed signature and provenance are checked; a helpline partner reviews the flow and wording.

### 3.2 Phase B: Network Sentinel, DNS mode

- **Scope:** a Rust daemon that acts as the home network's DNS resolver (devices get it through DHCP). It stores a minimal DNS history, matches lookups against the same indicator feed as Phase A, re-checks history when the feed updates, identifies devices (DHCP, mDNS) and shows results in the shared web UI. It warns when devices bypass it (DoH, Android Private DNS, iCloud Private Relay; see AM-10).
- **Deferred to E:** inline flow collection (conntrack/NetFlow), TV ACR detection (DL-09), behavioural flags (MS-09), OpenWrt packages.
- **Gate:** a planted test indicator alerts within 5 s (MS-01); a past record matches after a feed update (MS-02); a Raspberry Pi 4 serves 20 devices without dropped queries.

### 3.3 Phase C: Android

- **Scope:** local `VpnService` engine with per-app flows, DNS and SNI (CM-01 to CM-04, CM-06); Monitor and Block-unknown modes (CM-08); basic microphone and camera monitoring (SE-01 basic, SE-03); upload baselines, beacon and DNS anomaly detection (DL-02, DL-04, DL-05, DL-06); destination tracing (DT-01, DT-02, DT-06); posture and IOC checks (ID-03, ID-10, ID-12, ID-13); blocking and isolation (RA-01, RA-03); on-device retro-hunt (MS-02).
- **Distribution:** GitHub releases and F-Droid first; Google Play after the VpnService policy declaration is accepted.
- **Gate:** public beta; NF-03 and NF-04 battery and latency targets; first external audit if funded.

### 3.4 Phase D: Windows, user mode

- **Scope:** Rust service with ETW collectors (network, DNS, process), WFP filters added from user mode for blocking, WFP net events, event-log subscriptions (ID-01, ID-06 to ID-11), sensor history from the capability consent store (SE-01, SE-02, SE-04, SE-05), posture page (MS-07, DV-05), persistence watch (ID-07), response actions with journal and undo (RA-01 to RA-09). Phone Check moves into the same desktop app. See [ADR-0003](adr/0003-windows-user-mode-first.md) for what we give up without a driver.
- **Gate:** beta; NF-01 and NF-06 targets; coexistence with Defender and the top antivirus products (NF-09).

### 3.5 Phase E: later

Kernel driver (true connection prompts, SNI), macOS (Network Extension), Linux (eBPF via `aya`), TV agent and viewer, iOS companion, gateway flow mode, ML inference. Each gets its own plan when we get there.

## 4. Technology summary

Details and reasoning are in the ADRs.

| Area | Choice | ADR |
| --- | --- | --- |
| Shared core | Rust workspace; UniFFI for Kotlin/Swift bindings | [0001](adr/0001-rust-shared-core.md) |
| Desktop, gateway and TV-viewer UI | One web UI: TypeScript + React; Tauri 2 shell on desktop | [0002](adr/0002-tauri-shared-web-ui.md) |
| Windows collectors | User-mode ETW and WFP first; kernel driver deferred | [0003](adr/0003-windows-user-mode-first.md) |
| Android | Kotlin + Jetpack Compose (Compose for TV later), Rust core via cargo-ndk | 0001 |
| Storage | SQLite with SQLCipher (`rusqlite`), key in the OS key store | SRS §13 |
| Signed updates | Ed25519 signatures, version and expiry checks; evaluate TUF (`tough`) in A0 | SRS §14.3 |
| Detection rules | Sigma-compatible YAML subset (SRS §14.4) | SRS §14.4 |
| Licence | **Open decision**: recommendation in ADR-0004 | [0004](adr/0004-open-source-and-licensing.md) |

## 5. Repository layout (target)

One monorepo. Directories are created when the phase that needs them starts, not before.

```text
Sentinel-SRS/
├── Sentinel-SRS.md          # the SRS
├── docs/                    # plan, ADRs, amendments, threat models
├── crates/                  # Rust shared core
│   ├── sentinel-model/      #   common schema (SRS §13)            A
│   ├── sentinel-ioc/        #   indicators, STIX2 parsing           A
│   ├── sentinel-feed/       #   signed bundles, verification        A
│   ├── sentinel-store/      #   encrypted storage                   A
│   ├── sentinel-scan/       #   MVT / AndroidQF orchestration       A
│   ├── sentinel-enrich/     #   ASN, geo, tracker data              B
│   └── sentinel-rules/      #   Sigma-subset rule engine            B+
├── ui/                      # shared web UI (React + TypeScript)    A
├── apps/
│   ├── desktop/             #   Tauri 2 shell                       A
│   ├── gateway/             #   Network Sentinel daemon             B
│   └── android/             #   Kotlin + Compose                    C
├── engines/                 # pinned MVT / AndroidQF builds + packaging scripts   A
├── tools/feed-builder/      # builds the indicator feed from public sources        A
└── .github/workflows/       # CI
```

## 6. Cross-cutting work

These run alongside every phase. Each needs a named owner.

| Track | What it covers |
| --- | --- |
| Indicator feed operations | Weekly feed, same-day urgent updates, provenance on every indicator (MS-10). This is an ongoing service, not a one-off feature. |
| Security | STRIDE threat model per phase (SRS §15.4), dependency audit in CI, signing keys kept offline, vulnerability disclosure policy, external audit when funded |
| Localisation and accessibility | English and Arabic with RTL from day one, WCAG 2.2 AA, screen-reader testing (SRS §12.4) |
| Partners and funding | Helpline partners (MS-13, Phase A gate), grant applications, donations (see SUSTAINABILITY.md) |

## 7. Working agreements

- `main` is protected. All changes go through pull requests with at least one review.
- Every issue and PR that implements a requirement names its SRS ID (for example `MS-04`) in the title or labels, so the traceability in SRS §20.3 stays true.
- Each requirement ID gets at least one automated test (SRS §18). A feature is done when its acceptance criterion from the SRS passes in CI.
- CI on every PR: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny` (licences and advisories), and lint, typecheck and tests for the UI.
- Significant technical decisions are recorded as ADRs in `docs/adr/`.
- No telemetry, ever (NF-11). Success is measured by release download counts, partner feedback and usability sessions instead.
- Anti-abuse rules (SRS §15.3) are release blockers for every phase.

## 8. Decisions needed from the project owners

These block or shape Phase A. Each should be answered before the end of A0.

| # | Decision | Recommendation | Blocks |
| --- | --- | --- | --- |
| D1 | Team size and who owns which track | At least: Rust/core, UI, feed and research | Timeline |
| D2 | Licence | GPL-3.0-or-later (ADR-0004) | First code commit |
| D3 | Legal home | Fiscal host now (for example Open Source Collective), own entity later | Code signing, store accounts, grants |
| D4 | Product name | Run a trademark check: "Sentinel" collides with Microsoft Sentinel and SentinelOne, both security products | Public release |
| D5 | Primary audience for Phase A | At-risk users in Arabic-speaking countries and the helplines that support them | UX and copy |
| D6 | Helpline partner(s) | Approach Access Now Digital Security Helpline and SMEX in A0 | Phase A gate |
| D7 | Missing product spec | Add the product specification the SRS references (§6.4 inference table, TV-FR, DT-FR) to the repo (AM-05) | Phases B–D |

## 9. Top risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope creep back to "all editions at once" | Nothing ships | Phase gates; only the next phase is planned in detail |
| MVT packaging or Windows support is harder than expected | Phase A slips | A0 spike before committing; fallbacks in PHASE-A §6 |
| Licence conflicts (MVT, indicator sources, tracker data, GPL code reuse) | Legal exposure, rework | Licence review in A0; ADR-0004 |
| Trademark conflict on "Sentinel" | Forced rename after launch | Check in A0 (D4) |
| No funding for signing, devices and audits | Unsigned builds, no audit | SUSTAINABILITY.md; free code signing for OSS where eligible |
| Users read "No known traces found" as "safe" | Real harm to at-risk users | MS-15 wording, §8A.3 limits shown on every result, partner review |
| Small team burnout from feed operations | Stale indicators | Named owner, rotation, partner help |

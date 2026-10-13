# Sentinel — Project Plan

Version 0.2 · Oct 2026 · Status: **Proposed** (merging this into `main` means the team accepts it)

This plan turns the [SRS](../Sentinel-SRS.md) into something a small team can deliver. The SRS describes the full product: seven platforms, a kernel driver, three external audits and 18 months of parallel work. This plan keeps that as the destination. It changes the order and the first steps so that every phase ships something useful on its own.

**We start on Android** and move to other devices and systems one at a time.

Related documents:

- [Phase A: Android, detailed plan](PHASE-A-ANDROID.md): the next thing we build
- [Phase B: Phone Check (desktop)](PHASE-B-PHONE-CHECK.md): the outside spyware check that follows
- [SRS amendments](SRS-AMENDMENTS.md): problems found in the SRS and proposed fixes
- [Sustainability model](SUSTAINABILITY.md): how a free product pays its costs
- [Architecture decision records](adr/): the key technical decisions and why

## 1. Goals

1. Ship a free, Arabic-first Android app that shows what every app on the phone sends and where, and flags known stalkerware and spyware traces.
2. Grow it, one platform at a time, into the full Sentinel product described in the SRS. The outside spyware check (SRS §8A, its top priority) comes right after Android.
3. Stay trustworthy: open source, no telemetry, honest result wording, anti-abuse rules (SRS §15.3) as release blockers.
4. Stay alive: every phase must be fundable and maintainable by a small team (see [SUSTAINABILITY.md](SUSTAINABILITY.md)).

## 2. Assumptions

| Assumption | If it is wrong |
| --- | --- |
| Team of 2–4 people: at least one comfortable with Rust, one with Kotlin and Android | With 1–2 people, roughly double every duration below |
| The product is free and non-commercial | Re-check data and engine licences (SRS-AMENDMENTS AM-08, ADR-0004) |
| Durations are estimates for planning, not commitments | Re-plan at every phase gate |

## 3. Phases

Each phase ends with a gate. Only the next phase is planned in detail; later phases are re-planned when their predecessor passes its gate. The order after Phase A is a proposal and is confirmed at each gate.

| Phase | Rough timing (3 people) | Ships | Main SRS requirements |
| --- | --- | --- | --- |
| **A0 Foundations** | Weeks 1–2 | Repo, CI, licence review, engine spikes, threat model, Play policy review | §20.1 P0 |
| **A Android** | Months 1–6 | Android app: per-app connections, where data goes, blocking, basic sensor monitoring, stalkerware and spyware indicator matching | CM, SE, DT, ID, RA, MS subsets (see 3.1) |
| **B Phone Check** | Months 6–9 | Desktop app (Windows, macOS, Linux) that checks a phone from outside with MVT and AndroidQF | MS-04, MS-05, MS-11 to MS-15 |
| **C Network Sentinel, DNS mode** | Months 9–12 | Raspberry Pi / Docker DNS resolver that matches every home device's lookups against indicators, with retro-hunt | MS-01 to MS-03, MS-08, DT-07, DV-10 |
| **D Windows, user mode** | Months 12–18 | Full Windows desktop edition without a kernel driver | CM, SE, DL, ID, RA, DV subsets (see 3.4) |
| **E Later** | 18+ | Android TV agent, macOS, Linux, iOS companion, kernel driver, gateway flow mode | Remainder of the SRS |

### 3.1 Phase A: Android

Detailed in [PHASE-A-ANDROID.md](PHASE-A-ANDROID.md).

- **Why first:** Android is the majority platform in most Arabic-speaking countries; `VpnService` gives per-app visibility without root or a driver; distribution through GitHub and F-Droid is fast and free; and the Rust core built here (storage, indicators, signed feed, enrichment, detection) is reused by every later edition. It is also P1 in the SRS's own delivery plan.
- **Limit:** an app on the phone cannot catch spyware that controls the whole phone. Results never say "safe", and users are pointed to the outside check (Phase B).
- **Gate:** SRS P1 gate (public beta, audit 1 if funded), plus CM-01, CM-03, NF-03, NF-04, a planted indicator alerts within 5 s, retro-hunt works, a stalkerware test package is detected.

### 3.2 Phase B: Phone Check

Detailed in [PHASE-B-PHONE-CHECK.md](PHASE-B-PHONE-CHECK.md).

- **Why next:** it closes Phase A's gap with a check from outside the phone, which is the SRS's top priority. It reuses the Phase A core and feed, so it is short.
- **Gate:** SRS P1b gate: detects all public MVT test cases; runs offline; decrypted backups are gone after a scan; a helpline partner reviews the flow.

### 3.3 Phase C: Network Sentinel, DNS mode

- **Scope:** a Rust daemon that acts as the home network's DNS resolver (devices get it through DHCP). It stores a minimal DNS history, matches lookups against the shared indicator feed, re-checks history when the feed updates, identifies devices (DHCP, mDNS), and shows results in the shared web UI. It warns when devices bypass it (DoH, Android Private DNS, iCloud Private Relay; see AM-10). It also gives phones an out-of-band place for alerts (MS-08).
- **Deferred to E:** inline flow collection (conntrack/NetFlow), TV ACR detection (DL-09), behavioural flags (MS-09), OpenWrt packages.
- **Gate:** a planted test indicator alerts within 5 s (MS-01); a past record matches after a feed update (MS-02); a Raspberry Pi 4 serves 20 devices without dropped queries.

### 3.4 Phase D: Windows, user mode

- **Scope:** Rust service with ETW collectors (network, DNS, process), WFP filters added from user mode for blocking, WFP net events, event-log subscriptions (ID-01, ID-06 to ID-11), sensor history from the capability consent store (SE-01, SE-02, SE-04, SE-05), posture page (MS-07, DV-05), persistence watch (ID-07), desktop self-check (MS-06), response actions with journal and undo (RA-01 to RA-09). Phone Check moves into the same desktop app. See [ADR-0003](adr/0003-windows-user-mode-first.md) for what we give up without a driver.
- **Gate:** beta; NF-01 and NF-06 targets; coexistence with Defender and the top antivirus products (NF-09).

### 3.5 Phase E: later

- **Android TV agent:** mostly reuse of Phase A plus a 10-foot UI. It can move earlier if TV users become a priority.
- **Other editions:** macOS (Network Extension), Linux (eBPF via `aya`), iOS companion, Tizen and webOS viewers.
- **Deeper features:** kernel driver for Windows, gateway flow mode, ML inference.

Each gets its own plan when we get there.

## 4. Technology summary

Details and reasoning are in the ADRs.

| Area | Choice | ADR / SRS |
| --- | --- | --- |
| Android app | Kotlin + Jetpack Compose (Material 3); `VpnService`; minSdk 29 | SRS §3.3 |
| Shared core | Rust workspace; UniFFI bindings for Kotlin (and Swift later); `cargo-ndk` | [0001](adr/0001-rust-shared-core.md) |
| Android packet engine | Rust userspace TCP/IP stack, decided by the A0 spike (fallback: proven GPL C engine) | PHASE-A §6 |
| Desktop, gateway and TV-viewer UI | One web UI: TypeScript + React; Tauri 2 shell on desktop (from Phase B) | [0002](adr/0002-tauri-shared-web-ui.md) |
| Windows collectors | User-mode ETW and WFP first; kernel driver deferred | [0003](adr/0003-windows-user-mode-first.md) |
| Storage | SQLite with SQLCipher (`rusqlite`); key wrapped by the platform key store (Android Keystore first) | SRS §13 |
| Signed updates | Ed25519 signatures, version and expiry checks; evaluate TUF (`tough`) in A0 | SRS §14.3 |
| Detection rules | Built-in detections in Phase A; Sigma-compatible YAML engine when behaviour rules grow | SRS §14.4 |
| Licence | **Open decision**: recommendation in ADR-0004 | [0004](adr/0004-open-source-and-licensing.md) |

## 5. Repository layout (target)

One monorepo. Directories are created when the phase that needs them starts, not before.

```text
Sentinel-SRS/
├── Sentinel-SRS.md          # the SRS
├── docs/                    # plan, ADRs, amendments, threat models
├── crates/                  # Rust shared core
│   ├── sentinel-model/      #   common schema (SRS §13)                 A
│   ├── sentinel-store/      #   encrypted storage                       A
│   ├── sentinel-ioc/        #   indicators, STIX2 parsing               A
│   ├── sentinel-feed/       #   signed bundles, verification            A
│   ├── sentinel-enrich/     #   ASN, geo, company, tracker data         A
│   ├── sentinel-detect/     #   detections and alerts                   A
│   ├── sentinel-vpn/        #   Android packet engine                   A
│   ├── sentinel-ffi/        #   UniFFI bindings                         A
│   └── sentinel-scan/       #   MVT / AndroidQF orchestration           B
├── apps/
│   ├── android/             #   Kotlin + Compose                        A
│   ├── desktop/             #   Tauri 2 shell                           B
│   └── gateway/             #   Network Sentinel daemon                 C
├── ui/                      # shared web UI (React + TypeScript)        B
├── engines/                 # pinned MVT / AndroidQF builds             B
├── tools/feed-builder/      # builds the indicator feed                 A
└── .github/workflows/       # CI
```

## 6. Cross-cutting work

These run alongside every phase. Each needs a named owner.

| Track | What it covers |
| --- | --- |
| Indicator feed operations | Weekly feed, same-day urgent updates, provenance on every indicator (MS-10). This is an ongoing service from the first Android beta, not a one-off feature. |
| Security | STRIDE threat model per phase (SRS §15.4), dependency audit in CI, parser fuzzing, signing keys kept offline, vulnerability disclosure policy, external audit when funded |
| Localisation and accessibility | English and Arabic with RTL from day one, WCAG 2.2 AA, TalkBack and other screen readers (SRS §12.4) |
| Partners and funding | Helpline partners (MS-13 advice, Phase B gate), grant applications, donations (see SUSTAINABILITY.md) |

## 7. Working agreements

- `main` is protected. All changes go through pull requests with at least one review.
- Every issue and PR that implements a requirement names its SRS ID (for example `CM-01`) in the title or labels, so the traceability in SRS §20.3 stays true.
- Each requirement ID gets at least one automated test (SRS §18). A feature is done when its acceptance criterion from the SRS passes in CI.
- CI on every PR:
  - Rust: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny` (licences and advisories).
  - Android: Gradle build, Android lint, ktlint or detekt, unit tests.
  - UI (from Phase B): lint, typecheck and tests.
- Significant technical decisions are recorded as ADRs in `docs/adr/`.
- No telemetry, ever (NF-11). Success is measured by release download counts, F-Droid installs, partner feedback and usability sessions instead.
- Anti-abuse rules (SRS §15.3) are release blockers for every phase.

## 8. Decisions needed from the project owners

These block or shape Phase A. Each should be answered before the end of A0.

| # | Decision | Recommendation | Blocks |
| --- | --- | --- | --- |
| D1 | Team size and who owns which track | At least: Rust engine, Android and UI, feed and detection | Timeline |
| D2 | Licence | GPL-3.0-or-later (ADR-0004); it also allows reusing NetGuard or PCAPdroid code if the engine spike needs it | First code commit |
| D3 | Legal home | Fiscal host now (for example Open Source Collective), own entity later | Store accounts, grants |
| D4 | Product name | Run a trademark check: "Sentinel" collides with Microsoft Sentinel and SentinelOne, both security products | Public release, Android package name |
| D5 | Primary audience for Phase A | At-risk users in Arabic-speaking countries and the helplines that support them; privacy-conscious users second | UX and copy |
| D6 | Helpline partner(s) | Approach Access Now Digital Security Helpline and SMEX in A0 | MS-13 copy, Phase B gate |
| D7 | Missing product spec | Add the product specification the SRS references (§6.4 inference table, TV-FR, DT-FR) to the repo (AM-05) | DL-01 and later phases |
| D8 | Android distribution | GitHub releases and F-Droid first; Google Play after the `VpnService` and `QUERY_ALL_PACKAGES` declarations (AM-14) | Phase A release |

## 9. Top risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope creep back to "all editions at once" | Nothing ships | Phase gates; only the next phase is planned in detail |
| The Android packet engine is harder than expected | Phase A slips | A0 spike before committing; fallback to a proven GPL engine or a DNS-only mode first |
| Battery drain or manufacturers killing the service | Users uninstall | Battery measured every sprint; per-brand guidance; gaps recorded and shown |
| Google Play rejects the VPN or package-visibility use | Smaller reach | GitHub and F-Droid are the primary channels; fix and resubmit |
| Licence conflicts (indicator sources, tracker data, engine code, MVT later) | Legal exposure, rework | Licence review in A0; ADR-0004 |
| Trademark conflict on "Sentinel" | Forced rename after launch, new package name | Check in A0 (D4) |
| No funding for devices, signing and audits | No audit, slow progress | SUSTAINABILITY.md |
| Users read "No known traces found" as "safe" | Real harm to at-risk users | MS-15 wording, §8A.3 limits shown on every such result, partner review, Phase B outside check |
| Small-team burnout from feed operations | Stale indicators | Named owner, rotation, partner help |

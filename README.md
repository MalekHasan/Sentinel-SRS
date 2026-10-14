# Sentinel

See every network connection and sensor access on devices you own, trace where data goes, block suspicious activity, and check phones for known stalkerware and state-grade spyware.

**Status:** Phase A, Sprint 1: the Android tunnel works end to end (monitoring with a visible notification, monitoring gaps recorded). We start with **Sentinel for Android**, then move to other devices and systems one at a time: the desktop Phone Check, then the home-network gateway, then Windows.

## Documents

| Document | What it is |
| --- | --- |
| [Sentinel-SRS.md](Sentinel-SRS.md) | Software requirements for every edition |
| [docs/PLAN.md](docs/PLAN.md) | Project plan: phases, gates, technology, decisions needed |
| [docs/PHASE-A-ANDROID.md](docs/PHASE-A-ANDROID.md) | Detailed plan for the first deliverable, the Android app |
| [docs/PHASE-B-PHONE-CHECK.md](docs/PHASE-B-PHONE-CHECK.md) | Plan for the desktop spyware check that follows |
| [docs/SRS-AMENDMENTS.md](docs/SRS-AMENDMENTS.md) | Problems found in the SRS and proposed fixes |
| [docs/SUSTAINABILITY.md](docs/SUSTAINABILITY.md) | How a free product pays its costs |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [docs/THREAT-MODEL-A.md](docs/THREAT-MODEL-A.md) | Threat model for the Android app |
| [docs/LICENCE-REVIEW.md](docs/LICENCE-REVIEW.md), [docs/PLAY-POLICY.md](docs/PLAY-POLICY.md) | Licences of data and code; Google Play requirements |
| [docs/ANDROID-BUILD.md](docs/ANDROID-BUILD.md), [docs/FEED-SIGNING.md](docs/FEED-SIGNING.md) | How to build the app; how to sign the indicator feed |

## Code

| Path | What |
| --- | --- |
| `apps/android` | Android app (Kotlin, Jetpack Compose) |
| `crates/sentinel-vpn` | Packet engine for the Android tunnel, with its test lab |
| `crates/sentinel-feed`, `tools/feed-tool` | Signed indicator feed and its signing tool |
| `crates/sentinel-ffi` | Kotlin bindings to the Rust core (UniFFI) |
| `third_party/netstack-smoltcp`, `third_party/ipstack` | Vendored userspace TCP/IP stacks with our fixes (smoltcp is the default) |

## نبذة بالعربي

Sentinel تطبيق مجاني ومفتوح المصدر بيورجيك كل اتصال بيعمله كل تطبيق على جهازك، ومين بيستخدم المايك والكاميرا، ووين بتروح بياناتك. وبيفحص إذا في آثار معروفة لبرامج تجسس أو stalkerware.

بنبلّش بتطبيق **Android**، وبعدين بننتقل خطوة خطوة للأجهزة والأنظمة التانية:
1. فحص الموبايل من الكمبيوتر.
2. راوتر البيت.
3. Windows.

التفاصيل بـ [docs/PLAN.md](docs/PLAN.md).

## Principles

- Everything is processed on your own device or your own home gateway. No telemetry.
- Results say "Known traces found" or "No known traces found", never "clean" or "safe".
- Only for devices you own. No remote viewing, no hidden mode, no content capture.

## Licence

Copyright (C) 2026 Malek Al-Sheekh Hasan and the Sentinel contributors.

Sentinel is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE) and [ADR-0004](docs/adr/0004-open-source-and-licensing.md).

Bundled data and engines keep their own licences; see [docs/LICENCE-REVIEW.md](docs/LICENCE-REVIEW.md).

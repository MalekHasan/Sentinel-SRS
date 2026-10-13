# ADR-0004: Open source, and which licence

- Status: Proposed: **needs a decision from the copyright holder**
- Date: 2026-10-13

## Context

Sentinel sees every connection a device makes. Users and partners will ask why they should trust a free tool with that. Open source answers the question, and it also unlocks grants, free audit programmes, F-Droid distribution and free CI.

The repository is currently MIT-licensed. Projects we may want to learn from or reuse code from are mostly GPLv3: NetGuard and PCAPdroid (Android), LuLu (macOS), OpenSnitch (Linux), Portmaster and simplewall (Windows). The engines we bundle in Phase A have their own terms: MVT uses MVT License 1.1 (MPL 2.0 plus a consensual-use restriction), and AndroidQF's licence is to be confirmed in A0.

Today there is a single copyright holder, so changing the licence is easy. Once outside contributions arrive, it becomes hard.

## Options

| | MIT (current) | MPL-2.0 | GPL-3.0-or-later |
| --- | --- | --- | --- |
| Can reuse GPLv3 code (NetGuard, PCAPdroid, LuLu…) | No | No | Yes |
| Others can ship closed-source forks | Yes | Yes, but changes to our files must stay open | No |
| Fit with F-Droid, grants | Yes | Yes | Yes |
| Running MVT and AndroidQF as separate processes | Fine | Fine | Fine |

## Recommendation

**GPL-3.0-or-later** for the whole repository:

- it lets us reuse proven GPLv3 code for the hardest parts (Android VPN engine, macOS and Linux firewalls);
- it stops anyone shipping a closed, possibly data-collecting fork of a privacy tool under a similar name;
- it matches the licences of most comparable tools.

Bundled engines stay separate programs under their own licences, with their licence texts shipped in the app and shown on an "About and licences" screen. Indicator and tracker data keep their own licences and attribution.

## Consequences if accepted

- Replace `LICENSE` with the GPL-3.0 text and add SPDX headers to source files.
- Add `cargo deny` licence rules so incompatible dependencies fail CI.
- A future paid edition (SUSTAINABILITY.md §4) would also be GPL. Charging for support, hardware or hosting is still possible, but a closed-source edition is not.

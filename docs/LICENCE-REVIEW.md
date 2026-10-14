# Licence review (A0)

Version 0.1 · Oct 2026 · Status: **desk review**. Items marked "Confirm" must be checked against the source's own licence file, or with its maintainers, before anything ships.

Sentinel is GPL-3.0-or-later ([ADR-0004](adr/0004-open-source-and-licensing.md)) and free of charge. Data files are not code: each keeps its own licence, which we must follow and show in the app ("About and licences" screen).

## 1. Data the Android app will ship (Phase A)

| Source | Used for | Licence found | Obligations | Status |
| --- | --- | --- | --- | --- |
| Echap `stalkerware-indicators` | ID-13: stalkerware package names, certificates, domains, IPs | Sources disagree: CC BY 4.0 (a Rust parser's docs) or CC BY-NC-SA (SpyGuard's README) | Attribution; if NC-SA, our derived feed files must use the same licence and stay non-commercial | **Confirm** against the repository's LICENSE file |
| Amnesty International `mvt-indicators` / `investigations` | ID-13, MS-02: mercenary-spyware domains | Not found | Unknown | **Confirm**; contact Amnesty Tech, who are also a natural partner (MS-13) |
| Citizen Lab `malware-indicators` | ID-13, MS-02 | Not found; a third-party mirror says CC BY-NC-SA 4.0, but that is the mirror's statement | Unknown | **Confirm** with Citizen Lab |
| DuckDuckGo Tracker Radar | DT-06: tracker companies and categories | CC BY-NC-SA 4.0 (consistent across secondary sources; commercial use needs a licence from DuckDuckGo) | Attribution; non-commercial; share derived data alike | OK while Sentinel is non-commercial (AM-08). Confirm on the primary repository |
| Exodus Privacy tracker signatures | DT-06: tracker SDKs inside apps | No explicit licence found. Exodus says third-party tools reuse its API data | Unknown | **Ask Exodus Privacy** for permission and terms before bundling |
| DB-IP Lite (country, ASN) | DT-01: country and network owner per IP | CC BY 4.0 | Credit DB-IP.com with a link; link back on web pages that show results | OK |
| IPtoASN (iptoasn.com) | DT-01: IP to ASN | PDDL 1.0, per projects that redistribute it | None (public-domain dedication) | OK. Confirm on iptoasn.com |

### What "non-commercial" means for us

Sentinel is free, has no ads, and sells nothing, so NC-licensed data is usable today. Two things would change that, and each needs this review re-run first:

- any income tied to the app (paid tier, hardware sale, paid support);
- an organisation partner redistributing Sentinel as part of a paid service.

Donations and grants are generally not "commercial use" under CC's definition, but have a lawyer confirm before relying on that.

### ShareAlike

If a source is BY-NC-SA, the feed files we derive from it must carry the same licence. The feed format keeps each source's data in its own file with its own provenance (ADR-0005), so different licences never mix inside one file.

## 2. Code we depend on

Checked automatically by `cargo deny` in CI (`deny.toml` allows only GPL-compatible licences).

| Component | Licence | Notes |
| --- | --- | --- |
| netstack-smoltcp 0.2.4 (vendored in `third_party/netstack-smoltcp`) | MIT or Apache-2.0 | Modified (see `PATCHES.md`); keep both licence files and state the changes |
| smoltcp | 0BSD | |
| ipstack 1.0.1 (vendored in `third_party/ipstack`, optional feature) | Apache-2.0 | Modified (see `PATCHES.md`); not shipped in the app |
| simple-dns | MIT | |
| UniFFI | MPL-2.0 | Compatible with GPLv3 |
| ed25519-dalek, sha2, serde, tokio, rustix, socket2 | BSD-3, MIT, Apache-2.0 | |
| JNA (Android) | Apache-2.0 or LGPL-2.1+, at our choice | Use under Apache-2.0 |
| AndroidX, Jetpack Compose | Apache-2.0 | |

## 3. Engines for Phase B (desktop Phone Check)

| Engine | Licence | Status |
| --- | --- | --- |
| MVT | MVT License 1.1: MPL-2.0 plus a consensual-use restriction | Run as a separate program; show its licence; consent wording reviewed in B0 |
| AndroidQF | Not checked yet | **Confirm** in B0 |

## 4. Actions

| # | Action | Owner | When |
| --- | --- | --- | --- |
| L1 | Read the LICENSE files of Echap, Amnesty, Citizen Lab and DuckDuckGo data repositories; record the exact licence and version here | Feed owner | Before Sprint 7 |
| L2 | Ask Exodus Privacy about reuse terms for tracker signatures | Feed owner | Before Sprint 4 |
| L3 | Ask Amnesty Tech and Citizen Lab whether their indicators may be redistributed inside a signed feed | Partner owner | Before Sprint 7 |
| L4 | Add an "About and licences" screen listing every data source and its attribution | Android | Sprint 10 |
| L5 | Re-run this review before any income | Project owners | When it happens |

## Sources

- [stalkerware-indicators-rs documentation (CC BY 4.0 claim)](https://crates-io.ganymede-static.progval.net/crates/stalkerware-indicators/0.2.0)
- [SpyGuard README (CC BY-NC-SA claim)](https://rlp.schule/gitea/c_meyer/SpyGuard/raw/branch/BetterReport/README.md)
- [MVT documentation: indicators of compromise](https://docs.mvt.re/en/stable/iocs/)
- [randorisec/malware-indicators (mirror's own licence statement)](https://github.com/randorisec/malware-indicators)
- [DB-IP Lite downloads and licence](https://db-ip.com/db/lite.php)
- [IPtoASN](https://iptoasn.com) and [ip-location-db IPtoASN package README (PDDL)](https://unpkg.com/@ip-location-db/iptoasn-asn@2.3.2026061719/README.md)
- [Exodus Privacy: derived projects](https://exodus-privacy.eu.org/en/post/derivated_projects)
- [Tracker Radar data mirror (CC BY-NC-SA 4.0)](https://git.nixnet.services/curben/tracking-filter/src/commit/4a47097ea2f350fa131b75c542955f7afa83b38a/README.md)

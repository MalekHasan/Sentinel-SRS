# Sentinel

See every network connection and sensor access on devices you own, trace where data goes, block suspicious activity, and check phones for known state-grade spyware from outside the phone.

**Status:** planning. No code yet. The first deliverable is **Sentinel Phone Check**, a free desktop app that checks an iPhone or Android phone for known spyware traces (Pegasus, Predator, Graphite and others).

## Documents

| Document | What it is |
| --- | --- |
| [Sentinel-SRS.md](Sentinel-SRS.md) | Software requirements for every edition |
| [docs/PLAN.md](docs/PLAN.md) | Project plan: phases, gates, technology, decisions needed |
| [docs/PHASE-A-PHONE-CHECK.md](docs/PHASE-A-PHONE-CHECK.md) | Detailed plan for the first deliverable |
| [docs/SRS-AMENDMENTS.md](docs/SRS-AMENDMENTS.md) | Problems found in the SRS and proposed fixes |
| [docs/SUSTAINABILITY.md](docs/SUSTAINABILITY.md) | How a free product pays its costs |
| [docs/adr/](docs/adr/) | Architecture decision records |

## نبذة بالعربي

Sentinel تطبيق مجاني ومفتوح المصدر بيورجيك كل اتصال بيعمله جهازك، ومين بيستخدم المايك والكاميرا، ووين بتروح بياناتك. وبيفحص الموبايل من برّا، عن طريق الكمبيوتر أو راوتر البيت، بحثاً عن آثار برامج تجسس معروفة زي Pegasus.

أول إصدار: **Sentinel Phone Check**، تطبيق للكمبيوتر بالعربي والإنجليزي لفحص الآيفون والأندرويد. التفاصيل بـ [docs/PLAN.md](docs/PLAN.md).

## Principles

- Everything is processed on your own device or your own home gateway. No telemetry.
- Results say "Known traces found" or "No known traces found", never "clean" or "safe".
- Only for devices you own. No remote viewing, no hidden mode, no content capture.

## Licence

Currently [MIT](LICENSE). A change to GPL-3.0-or-later is proposed in [ADR-0004](docs/adr/0004-open-source-and-licensing.md).

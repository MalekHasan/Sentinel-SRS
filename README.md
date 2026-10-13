# Sentinel

See every network connection and sensor access on devices you own, trace where data goes, block suspicious activity, and check phones for known stalkerware and state-grade spyware.

**Status:** planning. No code yet. We start with **Sentinel for Android**, then move to other devices and systems one at a time: the desktop Phone Check, then the home-network gateway, then Windows.

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

Currently [MIT](LICENSE). A change to GPL-3.0-or-later is proposed in [ADR-0004](docs/adr/0004-open-source-and-licensing.md).

# Sustainability model

Version 0.1 · Oct 2026 · Status: **Proposed**

Sentinel is free. Free does not mean it costs nothing: there are yearly fees, test devices, audits and an indicator feed that someone must update every week. This page says who the product is for, what it costs, and how those costs get paid without breaking the promises below.

## 1. Promises to users

These do not change, whatever the funding situation.

1. Every protection feature is free. The spyware check is never behind a paywall.
2. No ads, no telemetry, no selling or sharing of user data (SRS NF-11).
3. The source code is open, so anyone can verify the promises above.
4. Funding sources are listed publicly.

## 2. Who it is for

| Group | Why Sentinel matters to them | Phase |
| --- | --- | --- |
| Journalists, human-rights defenders, lawyers and activists in Arabic-speaking countries | Pegasus targeting in the region is publicly documented (Citizen Lab, Access Now, Front Line Defenders). MVT exists but is a command-line tool in English. | A |
| Digital-security helplines and trainers | A free, guided, bilingual tool they can hand to the people they support | A |
| Privacy-conscious home users | See what their phones, PCs and TVs send, and to whom | B–D |

## 3. Costs

Rough figures for planning; get real quotes before budgeting.

| Item | Approximate cost | Needed from |
| --- | --- | --- |
| Apple Developer Program (macOS notarization, later iOS) | 99 USD per year | Phase A |
| Windows code signing | A few hundred USD per year from a commercial CA; free programmes exist for open-source projects (for example SignPath Foundation; check eligibility) | Phase A |
| Domain | About 15 USD per year | Phase A |
| Hosting, CI, releases | 0 (GitHub is free for public repositories, including Windows and macOS runners) | Phase A |
| Test devices: an older iPhone, two or three Android phones, a Raspberry Pi | About 1,000–2,000 USD, one-off | Phases A–C |
| Google Play developer account | 25 USD, one-off | Phase C |
| External security audit | Usually tens of thousands of USD per audit; some funders offer free audits to open-source privacy projects | Before 1.0 releases |
| EV certificate for a Windows kernel driver | Several hundred USD per year, and requires a registered organisation | Phase E only |
| Legal entity, accounting | Depends on the country | When needed (see §5) |

The biggest hidden cost is people's time for the indicator feed (MS-10), support and keeping up with yearly OS changes.

## 4. How the costs get paid

| Source | Examples | Notes |
| --- | --- | --- |
| Grants for open-source privacy and digital-rights work | NLnet / NGI Zero, and other internet-freedom funders | Check which calls are open; some funders' budgets changed in 2025. Phase A is a good fit for a first application. |
| Donations | GitHub Sponsors, Open Collective, Liberapay | Covers fixed yearly fees. |
| Partner organisations | Helplines and digital-rights NGOs | Can co-fund features or audits, test with real cases, and distribute the tool. |
| In-kind support | Free code signing for OSS, free CI, free audit programmes | Apply early; approvals take time. |

### Optional income later

None of these may gate a protection feature.

- A ready-made Network Sentinel box (preconfigured Raspberry Pi) sold at a small margin.
- Support and a managed edition for newsrooms and NGOs. This is the "enterprise/fleet" product the SRS lists as a later product (§19.3).
- Training for organisations.

**Licence warning:** any income can make the project "commercial" for licences with a non-commercial clause (DuckDuckGo Tracker Radar is CC BY-NC-SA) and must be checked against the MVT licence. Re-run the licence review before taking any income (SRS-AMENDMENTS AM-08).

## 5. Legal home and governance

| Stage | Setup | What it unlocks |
| --- | --- | --- |
| Now | Join a fiscal host (for example Open Source Collective) | Accept donations and many grants without founding a company |
| Before a kernel driver or org-wide store accounts | Register an organisation (association or company) | EV certificate, organisation accounts on app stores |

Also needed:

- A privacy policy that says what the app collects (nothing) and what the optional feed update reveals (an IP address to the host).
- A trademark check on the name (PLAN.md D4).
- A vulnerability disclosure policy (`SECURITY.md`).
- A public list of maintainers and of who holds the feed-signing keys.

## 6. Decisions needed

- Fiscal host or entity, and in which country.
- Which grant to apply to first, and who writes the application.
- Who receives donations and who approves spending.

# ADR-0039: Every kind of record is kept for its own time, applied each day

- Status: **Accepted** (`crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-22
- Implements SRS §13.2 retention on Android. Closes audit finding A-07 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)). Extends [ADR-0009](0009-local-history-store.md) (decision 5) and [ADR-0018](0018-action-journal.md).

## Context

SRS §13.2 sets how long the history keeps each kind of record:

| Data | Default retention |
| --- | --- |
| Flows | 30 days (1–365), then rolled up to daily totals per app and destination |
| Sensor and device events | 90 days |
| Alerts and action journal | 1 year |
| Raw security events | 14 days |

What was built applied only the first row, and only in part:
- Flows older than 30 days were rolled up, but only when monitoring started. A service that ran for weeks kept every flow.
- The 30 days were fixed in the app; the user could not choose.
- Alerts, the action journal, microphone and camera uses and monitoring gaps were never deleted.

Sentinel keeps no raw security events on Android: detection works on flows, lookups and settings as they happen, and stores only alerts. The fourth row has nothing to apply to.

## Decision

1. **One retention pass applies every period**, in one transaction (`Store::apply_retention`):
   - **Flows** that started before the user's setting are rolled up into daily totals per app, destination and protocol, then deleted, as before.
   - **Sensor uses and monitoring gaps** (the device events Android keeps) that ended more than 90 days before are deleted. One still open is kept: its end is not known yet.
   - **Journal entries** made more than a year before are deleted. The firewall rules, the mode and isolation live in their own tables, so a setting stays in force when the entry that made it goes; that entry can no longer be undone.
   - **Alerts** raised more than a year before are deleted, with two exceptions that stay however old:
     - **an alert still open**: one the user has not dealt with is a finding not yet seen;
     - **an alert about a known indicator** (ID-13, MS-02). These alerts are how the checks against an indicator list know what they already reported: an installed app is reported once while it stays installed, and a past connection once. The daily totals those checks read are kept. Were these alerts deleted, the same app or the same old connection would raise a new Critical alert a year later, and every year after. They are few.
   - A journal entry kept whose alert goes keeps its record without the link (`ON DELETE SET NULL`).
   - Running it twice changes nothing.
2. **How long flows are kept is a setting**, kept in the history's `meta` table (`keep_flows_days`): 30 days until the user chooses. The store refuses any value outside 1 to 365 days, and a pass clamps whatever it is given to that range. The main screen offers 1, 7, 30, 90 and 365 days, and says how long the rest of the history is kept. A choice applies the periods at once, so a shorter one takes effect without waiting a day. As that turns older flows into daily totals for good, a shorter time is asked first: a tap while scrolling must not cost the user their history.
3. **The pass runs when monitoring starts, then once a day while it runs.** Handler time stands still while the phone sleeps (ADR-0029), so the service looks every hour of handler time whether a day has passed on the clock. A clock set back counts as a day passed. Restarts within the same process do not run it again before the day is over.

## Verification

- `crates/sentinel-store/tests/store.rs`:
  - a sensor use and a gap that ended past 90 days go; one that ended within them stays, as does one still open;
  - an alert dismissed past a year goes; one still open, and one about a known indicator, stay however old; a journal entry past a year goes, while its rule stays in force; one kept whose alert went loses only the link;
  - a second pass removes nothing;
  - the setting is 30 days until chosen, refuses 0 and 366, survives reopening, and a pass given more than 365 or less than 1 day keeps to the range.
- `sentinel-ffi`: a pass follows the setting, and counts what it removed.
- On the Android 14 emulator:
  - `RetentionTest`: the main screen offers the choices with the one in force selected; a shorter one is asked first and Cancel keeps the one in force, a longer one is not asked; a choice outside 1 to 365 days is refused; a choice is kept and applies the periods at once, so a gap that ended past 90 days goes and a recent one stays;
  - `RtlTest`: the setting, its explanation and the question in Arabic, right to left.

## Consequences

- **What is deleted cannot be read back.** Rolled-up flows keep their totals per day; nothing else of a deleted record remains. The export (ADR-0033) holds only what the history still has.
- **While monitoring is off nothing runs.** Records past their time stay until monitoring starts again, or until the user changes the setting. Nothing new is written while it is off, so the history does not grow.
- **The pass holds the history's lock** while it runs, as it did at each start before. A large roll-up can delay the engine's writes for that long (audit finding A-14). Once a day, at most.
- **Old alerts no longer count** toward anything that looks back over them. Every other look-back today is shorter than a year: rate limits, repeated gaps and upload surges look back a day.

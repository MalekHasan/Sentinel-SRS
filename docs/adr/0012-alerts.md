# ADR-0012: Alerts carry a rule and evidence, not text

- Status: **Accepted** (Sprint 5; `crates/sentinel-detect`, `crates/sentinel-store`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS AL-01, AL-02, and the alert for monitoring gaps (SP-03); prepares AL-03 to AL-06

## Context

An alert has a severity (Info, Warning, High or Critical, AL-01), a plain-language title, a one-sentence explanation, then its evidence, then the actions the user can take (AL-02). The SRS `alert` table (§13.1) has columns for `title` and `body`, and `evidence` as a JSON array of references.

Sentinel is used in English and Arabic (§12.4), and the user can change the phone's language at any time. The same alert must read correctly in both. Alerts are also exported (§12.3) and will be shown on a second device (MS-08).

| Option | For | Against |
| --- | --- | --- |
| Store the title and explanation as text, written when the alert is raised | Matches the SRS columns; the export needs no rendering | Frozen in the language of that moment; the Rust core would need every translation; fixing a text does not fix old alerts |
| **Store the rule and the evidence; the app writes the text** | Always in the user's language, in Android's own string resources with plurals and right-to-left handling; old alerts get corrected texts | Every rule needs its strings in each app; the export must render them |

## Decision

1. **The core decides, the app words it.** `sentinel-detect` defines the alert model:
   - a **rule**, with a stable id stored in `alert.rule_id` (for example `monitoring-interrupted`). An id never changes or moves to another rule;
   - a **severity**;
   - the **evidence**: typed references such as a monitoring gap or an app, stored as tagged JSON in `alert.evidence`;
   - the creation time and a state (open or dismissed).
2. **The text is not stored.** The `title` and `body` columns stay empty. The app writes the title and the one-sentence explanation from the rule, in the screen's language, and describes each piece of evidence. An export renders them the same way.
3. **Actions come from the rule and the evidence**, computed when an alert is read rather than stored. An app in the evidence can always be opened. Actions that change the device (blocking, isolation) are added with Sprint 6.
4. **Severity has its own look.** Each severity has its own name and its own colour, so that colour is never the only sign. AL-01's distinct sounds come with the notification channels (AL-06, the next task).
5. **Alerts live in the encrypted history** (schema version 6, [ADR-0009](0009-local-history-store.md)), so the one-tap wipe removes them too. A row this version cannot read (an unknown rule, severity, state or evidence) is reported as an error, not skipped silently.
6. **The first rule is "monitoring stopped"** (SP-03). Each new monitoring gap raises one Warning alert, with the gap's start and recorded reason as evidence, offering to start monitoring again. A stop the user asked for is not a gap and raises nothing.

## Verification

- `sentinel-detect` unit tests:
  - severities are ordered, and their names, rule ids and states round-trip;
  - the stored evidence JSON is fixed by a test;
  - the actions per rule are tested.
- `sentinel-store`: alerts survive reopening, newest first, with open-only and limits, dismissing, and unknown ids; `open_gap` says whether it opened a gap.
- `sentinel-ffi`: a new gap raises exactly one alert, a gap that is already open raises none, and dismissing it removes it from the open list.
- On Android:
  - `AlertsTest` checks that a gap recorded by the app raises one Warning alert with its evidence;
  - it checks that the detail screen shows the severity, title, explanation, evidence and actions in that order, and that each action and Dismiss work;
  - it checks that the four severity badges have four different colours and names, and that the main screen lists open alerts;
  - `AlertTextTest` checks the English texts against AL-02's reading grade of 8, using the Flesch-Kincaid formula on each rule's title and explanation and on the screen's other texts;
  - `RtlTest` shows the alert screens in Arabic, right to left.

## Consequences

- Every new rule needs a title and an explanation in each app's strings. `AlertTextTest` finds rules by their `alert_<rule>_title` and `alert_<rule>_text` strings, so a rule with strings in English only, or with hard words, fails the build's device tests.
- A gap's reason is stored as text in the language of the moment it was recorded (the gap log predates this decision); the alert shows it as evidence, as recorded.
- Grouping, rate limits, Do Not Disturb, notification channels and sounds (AL-03, AL-04, AL-06) and feedback (AL-05) build on this model in the rest of Sprint 5.

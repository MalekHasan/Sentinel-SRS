# ADR-0012: Alerts carry a rule and evidence, not text

- Status: **Accepted** (Sprint 5; `crates/sentinel-detect`, `crates/sentinel-store`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS AL-01, AL-02, the alert for monitoring gaps (SP-03), delivery as notifications (AL-03, AL-04, AL-06), and feedback (AL-05)
- Amended 2026-10-22 for audit finding A-08 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decisions 14 and 15, and the list of what was allowed.

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

### Delivery (AL-03, AL-04, AL-06)

7. **The core decides whether an alert is notified now.** The rule lives in `sentinel-detect` (`delivery`), so every edition applies it the same way:
   - Critical alerts are always notified.
   - While Do Not Disturb is on, Info and Warning alerts wait in the app. High and Critical alerts are posted.
   - Otherwise an alert is notified unless the app it is about already had three non-critical notifications in the last hour. Sentinel's own alerts, such as a monitoring gap, count as one app.

   The store records when each alert was notified (schema version 7) and makes the decision and the record in one transaction. That way two alerts raised at once cannot both pass the limit. An alert that is not notified is still kept and shown in the app.
8. **The app hears every new alert** through a listener the core calls after storing it. The app reads the phone's Do Not Disturb state and asks the core for the decision. It posts only if allowed, and only if Android would show the notification (permission granted, channel not turned off), so that a hidden notification does not use up the allowance.
9. **One Android notification channel per severity**, each with its own importance, sound and vibration:

   | Severity | Importance | Sound | Vibration |
   | --- | --- | --- | --- |
   | Info | Low | None | None |
   | Warning | Default | Notification sound | Short |
   | High | High (shown at the top of the screen) | Notification sound | Two pulses |
   | Critical | High | Alarm sound | Three long pulses |

   This completes AL-01's distinct sounds. The user can change each channel in Android's settings.
10. **Repeated alerts share one notification.** Alerts of the same rule about the same app replace each other's notification, which says how many more like it are open (AL-03's grouping).
11. **Nothing on a locked phone.** Alert notifications are secret: on a phone locked with a PIN, pattern or password they make their sound but show nothing until it is unlocked, whatever the lock screen setting. What was found, and about which app, can matter to someone who looks at another person's phone. THREAT-MODEL-A's B5 is that person with the phone unlocked; a locked phone should not show more. A "private" notification with a neutral public version is not enough. Android shows private notifications in full when the user's lock screen setting shows all notification content, which is a common default. Android also ignores lock screen visibility that an app sets on its own channel.
12. Tapping a notification opens the alert in the app, and a notification offers no other action. Every alert also lives in the app, so a notification that imitates Sentinel's leads nowhere new (THREAT-MODEL-A S4).

### Feedback (AL-05)

13. **Every alert asks whether it was useful.** The user can answer:
    - **Not useful.** The alert is dismissed. Later alerts from the same rule about the same app are still kept and shown in the app, but they no longer notify.
    - **Allow.** The alert is dismissed, and its rule and app go on an allow-list. That rule raises no more alerts about that app; what it watches, such as monitoring gaps, is still recorded.
14. **Both can be undone** from the alert. Taking back "allow" removes the allow-list entry. **Everything allowed is also listed** on its own screen ("Alerts you allowed", opened from the main screen): each kind of alert, the app, when, and Take back. Taking one back there brings its alerts again, and the alerts it was allowed from no longer say it is allowed; they stay dismissed.
15. **Only an alert about an app, and not a Critical one, can be allowed; "not useful" never holds a Critical notification.** The core decides (`Feedback::allowed_on`), tells the app on each alert (`can_allow`), and refuses the rest.
    - **A Critical alert:** someone else holding the phone could otherwise silence what it found, such as spyware (THREAT-MODEL-A B5).
    - **An alert about no app:** allowing goes by rule and app, so allowing one of these would silence its rule for the whole phone, for good. One tap would stop every later alert about the microphone used while the screen is off, a monitoring gap, a network setting changed, or a certificate added (audit A-08). These can be dismissed or marked not useful. What an earlier version allowed for no app no longer counts, and is not listed.
16. **Feedback is kept in the encrypted history and changes only this user's alerts.** It is stored in `alert.user_feedback` and, for allowing, in an `allowed` table (schema version 8). It never leaves the phone (NF-11), and it tunes nothing but these two local thresholds.

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

- Delivery:
  - the `delivery` unit tests cover each severity with and without Do Not Disturb, the per-app count, critical alerts never being held, and the one-hour window;
  - AL-03's load test sends one alert per second for two hours and gets exactly three notifications in each hour, with every critical one notified;
  - the store and FFI tests check the atomic claim, that a claim is never counted twice, and that the app's listener can claim from inside the call.
- Feedback:
  - the store test checks that "not useful" holds later alerts like it but not other apps' or Critical ones;
  - it checks that allowing adds to the allow-list and that changing or undoing the feedback removes the entry, as does taking it back from the list, which clears that app's alerts' feedback only;
  - it checks that a Critical alert, and an alert about no app, cannot be allowed, that an older allowance for no app no longer counts and is not listed, and that everything survives reopening;
  - the FFI test shows that an allowed rule raises nothing about that app until undone, or taken back from the list, and that a gap cannot be allowed.
  - `AlertsTest` on the emulator checks that a gap recorded by the app cannot be allowed and that the next gap alerts again, and checks the buttons, their results and Undo (no Allow where the core says so); `AllowedTest` allows an app's special access, finds it on the list, takes it back there, and is alerted again; `RtlTest` checks them in Arabic.
- `AlertNotificationTest` on the emulator checks:
  - the four channels' importance, sounds and vibrations;
  - that a gap posts a secret Warning notification;
  - that five gaps give one notification, three of them notified;
  - that a Warning waits in the app while Do Not Disturb is on.

## Consequences

- Every new rule needs a title and an explanation in each app's strings. `AlertTextTest` finds rules by their `alert_<rule>_title` and `alert_<rule>_text` strings, so a rule with strings in English only, or with hard words, fails the build's device tests.
- A gap's reason is stored as text in the language of the moment it was recorded (the gap log predates this decision); the alert shows it as evidence, as recorded.
- **Do Not Disturb on Android.** Android lets only the user allow an app's channel through Do Not Disturb. Sentinel asks for it on the High and Critical channels, and posts those alerts during Do Not Disturb. Whether they make a sound depends on the user allowing Sentinel in Do Not Disturb. Quiet hours on Android are Do Not Disturb schedules, so Sentinel has no quiet-hours setting of its own. A settings screen that shows the user how to let Critical alerts through comes with the settings work.
- Alerts held for Do Not Disturb or the rate limit are not notified later; they wait in the app's list.
- An alert about the phone itself is never silenced for good. A user who changes a network setting often gets an alert each time; "not useful" keeps those in the app without a notification.
- Someone holding the unlocked phone can still allow an app's Warning and High alerts. That person can also turn Sentinel off, so this adds no new risk (THREAT-MODEL-A B5); the list shows what was allowed, and when.

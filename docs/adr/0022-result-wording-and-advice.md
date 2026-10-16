# ADR-0022: Saying what was found, and what to do about it

- Status: **Accepted** (Sprint 7; `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS MS-15 ("Result wording: 'Known traces found' or 'No known traces found', with the date of the indicator list used; never 'clean' or 'safe'"), MS-13 ("When a match is found: advise the user not to wipe or reset the device yet (evidence is lost), to move sensitive conversations to a different device, and to contact Access Now Digital Security Helpline or Amnesty Tech"; shown on every MS alert), and the limits of §8A.3. Builds on [ADR-0020](0020-indicator-matching.md) and [ADR-0021](0021-retro-hunt.md).

## Context

[ADR-0020](0020-indicator-matching.md) and [ADR-0021](0021-retro-hunt.md) raise an alert for each known trace found, live or in the history. Two things were still missing:

- **A result.** Somebody who fears they are watched wants one answer: was anything found? The answer must not overstate. An app on the phone cannot prove the phone is free of spyware (§8A.3, [PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md)), and a reader takes "nothing found" for "safe" unless told otherwise (Phase A risk table).
- **Advice.** The first thing many people do on hearing "spyware" is reset the phone. That deletes what an expert would need to see. Someone who installed stalkerware may also still read what the phone shows.

## Decision

1. **The result is shown under the indicator list on the main screen**, only while a list is in force:
   - **"Known traces found"** as soon as the history keeps any known-indicator alert, open or dismissed. It says how many alerts, the date of the list in use, and to open them. Dismissing an alert does not make the result go back to "not found". Someone else holding the phone could otherwise hide a finding in two taps, as with Critical alerts that cannot be allowed (ADR-0012).
   - **"No known traces found"** only once the history has been checked against the version in force (ADR-0021). It says since when the history holds traffic and the date of the list. It is followed every time by the limits: this is not proof that the phone has no spyware; Sentinel finds only traces that were published, in traffic it saw; spyware that controls a phone can hide from every app on it.
   - **"Not checked against this list yet"** otherwise, for example in the moment between an install and the end of the check.
2. **The core gives what the result needs** (`HistoryStore.known_traces`): how many known-indicator alerts the history keeps, which list version it was last checked against, and since when it holds traffic. Alerts are kept a year (§13.2). A wipe starts over.
3. **The main screen follows the checks.** `History.hunts` counts finished checks, so the result changes as soon as one ends. The app also checks the history when it opens, should a check not have run (ADR-0021).
4. **Every known-indicator alert gives the MS-13 advice**, between its evidence and its actions:
   - do not reset or wipe the phone yet, because that deletes the traces an expert needs;
   - move sensitive conversations to another device you trust;
   - ask a digital security helpline, which is free for people at risk.

   The two helplines MS-13 names each get a button that opens their page in the browser: Access Now's Digital Security Helpline (`https://www.accessnow.org/help/`) and Amnesty International's Security Lab (`https://securitylab.amnesty.org/get-help/`). Their addresses are also written out, to type on another device. Sentinel sends nothing anywhere itself.
5. **"Clean" and "safe" are banned words.** A device test fails if any English text uses either word, or any Arabic text uses "نظيف" or "آمن".

## Verification

- `sentinel-store`: alerts are counted per rule, open and dismissed.
- `sentinel-ffi`: the known traces before any list, after a check (three alerts, version 1), and after a newer list and a dismissal (four alerts, version 2: a dismissed alert still counts).
- On the Android 14 emulator:
  - `FeedTest`: no result without a check or without a list; "not checked yet" for an older version; "No known traces found" with the history's start, the list's date and the limits; "Known traces found" with the count and the list's date, even when the last check found nothing new.
  - `AlertsTest`: a known-indicator alert shows the advice before the actions, and each helpline's button opens its page and shows its address; other alerts give no advice.
  - `RtlTest`: the result, its limits and the advice in Arabic, right to left.
  - `StringsTest`: no text in either language says "clean" or "safe".
  - `AlertTextTest`: the advice reads at grade 8 or lower.

## Consequences

- **The helplines serve people at risk because of their work:** journalists, activists, human rights defenders. Someone watched by a partner may be better helped by a local domestic-violence service, which differs by country. Adding such services, and an Arabic-language helpline such as SMEX (PLAN D6), waits for the helpline partners' review of this text (PLAN gate, Phase B).
- **The helpline pages open on the suspected phone.** That is the quickest way to reach them, but someone watching the phone could see it. The written-out addresses let the user go to another device instead, and the advice says to move sensitive conversations there.
- **The result counts alerts, not apps or indicators.** Two alerts about the same app and indicator, one live and one dismissed and seen again in a later run, count as two traces. It reads "2 alerts name known spyware or stalkerware", which stays true.
- **The result cannot be reset without a wipe.** After the user has dealt with a finding (for example removed an app), the main screen still says "Known traces found" for as long as the alert is kept. That is deliberate (point 1). A way to mark a finding as dealt with, without hiding it, can come with the helpline review.
- **The wording still needs the copy review MS-15 asks for**, by the helpline partners, in both languages (PHASE-A-ANDROID.md exit criteria).

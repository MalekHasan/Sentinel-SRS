# ADR-0040: What other apps can do with Sentinel's screens

- Status: **Accepted** (`apps/android`)
- Date: 2026-10-22
- Closes audit findings A-40, A-41, A-42 and A-43 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)). Extends the window guard of [ADR-0037](0037-accessibility.md) (A-17) and THREAT-MODEL-A E7.

## Context

Sentinel is used on phones where spyware may already run. That spyware is an ordinary app: it can claim the name of a screen, open another app's screens, choose its own name, and, with the access ID-12 reports, record the screen. The audit found four ways it could use Sentinel's own screens against the user:

- **A-40.** Sentinel sends the user to Android's screens to take access away, by name: accessibility, notification access, security, trusted certificates and others. Any app can claim a name. Two of them, the Settings app's trusted certificates and system updates, are not published by Android, so on a phone whose Settings lacks them, the claimer's screen opened as if it were Android's. For the published names, Android offered the claimer beside its own.
- **A-41.** Any app could open Sentinel at an alert of its choosing, since the main screen is open to all and took the alert to show from whoever opened it.
- **A-42.** Sentinel's screens appeared in screenshots, screen recordings and the recent apps' pictures, with every app and place they name.
- **A-43.** The names Sentinel shows inside its sentences are kept apart from the sentence's direction by Unicode isolates. Any app chooses its name, and one holding an isolate's end (U+2069) and an override (U+202E) left the isolate and turned the rest of the sentence around.

## Decision

1. **Android's screens open in apps that came with the phone, and in no other** (A-40). Every Settings screen Sentinel opens, from alerts, the hardening checklist, "Keep monitoring running" and usage access, is looked up among the apps on the system image (`MATCH_SYSTEM_ONLY`) and opened by its exact name (`systemScreen`). If none has it, Sentinel tries the next screen as before, ending at Android's settings.
2. **Only Sentinel's own notifications open an alert** (A-41). They open the main screen under a second name that no other app may open (an activity alias, `OpenAlert`, not exported). The main screen shows the alert asked for only when opened under that name; opened any other way, it shows itself.
3. **Sentinel's screens are kept out of screenshots, screen recordings and the recent apps** (`FLAG_SECURE`, A-42). The window guard of ADR-0037 sets it on every window and dialog. The recent apps show a blank picture of Sentinel.
4. **A name loses its own direction controls before it goes into a sentence** (A-43). `isolate` drops the marks, embeddings, overrides and isolates (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) from what it wraps. No package name, label, hostname or address needs them.

## Verification

On the Android 14 emulator:

- `SystemScreenTest`: debug builds claim the Settings app's trusted certificates, as spyware could. Android lists Sentinel among the apps that answer that name, and Sentinel opens it, security settings and Android's settings in apps that came with the phone only. A name no app of the phone's answers opens nothing.
- `AlertNotificationTest`: opened the way any app can open it, with an alert asked for, Sentinel shows its main screen and no alert. Opened the way its notification opens it, it shows the alert.
- `WindowGuardTest`: the main screen and the dialog of the notification's Stop are kept out of screenshots.
- `RtlTest`: a name holding an isolate's end and an override loses both, and the Arabic sentence it starts stays right to left.

## Consequences

- **The user cannot take a screenshot of Sentinel, or share its screen in a call.** Someone helping the user from afar sees a blank screen. The export (ADR-0033) is the way to share what Sentinel found.
- **A phone whose maker moved a Settings screen into an app that did not come with the phone** gets the next screen instead, ending at Android's settings. No such phone is known.
- **Spyware that is part of the system image** is trusted as the phone's own apps are (ADR-0024).
- **Not looked up this way:** the VPN consent and the notification permission, which Android itself opens for Sentinel, and the file picker for the export and the import (`ACTION_CREATE_DOCUMENT`, `ACTION_OPEN_DOCUMENT_TREE`), opened by name. Android answers those names with its own documents screen; whether another app can stand in for it was not checked.

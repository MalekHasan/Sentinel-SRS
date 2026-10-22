# ADR-0024: Apps that gain accessibility, device admin or notification access

- Status: **Accepted** (Sprint 8; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS ID-12 ("Accessibility, device-admin or notification-listener permission granted to a non-allow-listed app"; signal: package and policy state). Uses the alerts of [ADR-0012](0012-alerts.md), including "allow" (AL-05).

## Context

Stalkerware needs more than an installed app. To read messages it asks for **notification access** or an **accessibility service**, which can read the screen and tap for the user. To survive removal it asks to be a **device admin**: Android will not uninstall a device admin app until it is turned off. Android grants none of these unless someone turns them on in the settings, with the phone unlocked. That is exactly what a person with brief access to the phone does.

Many honest apps hold the same access: password managers and screen readers use accessibility, watches and car apps read notifications, and work apps can be device admins. So this access is a reason to look, not proof of anything.

How each one can be read without root:

| Access | How to read it | Change announced? |
| --- | --- | --- |
| Accessibility | the secure setting `enabled_accessibility_services` (public API) | yes, to an observer of the setting |
| Notification access | the secure setting `enabled_notification_listeners`; androidx's `NotificationManagerCompat` reads the same setting | yes, to an observer of the setting |
| Device admin | `DevicePolicyManager.getActiveAdmins()` | no |

Sentinel itself uses none of them. SRS §2.4 forbids it any accessibility service, and reading which apps hold one is not using one.

## Decision

1. **One rule, `special-access`, High.** An app that holds one of the three, and did not hold it at the last check, raises a High alert: like a new admin account (SRS §8.3), serious but often explained. The alert names the app and the access. Its title and explanation are written for each kind ("An app can read your notifications"). It says that some apps need this, and that if the user did not turn it on, someone else may have.
2. **The allow list.**
   - **Apps that came with the phone are never reported.** These are apps on its system image, such as the screen reader or the launcher. Someone who can change the system image needs no special access.
   - **The user can allow any other app** from its alert (AL-05): the rule raises nothing more about that app. A High alert can be allowed; a Critical one cannot.
3. **Reported once per grant.** The history keeps the access each app held at the last check (table `app_access`, schema 15). A check reports what is held now and was not then. What is held is kept only once its alerts are: an alert that cannot be kept leaves the last check as it was, so the next check reports the access again (audit A-35).
   - The first check reports everything already held, since stalkerware may predate Sentinel.
   - Access turned off and on again is reported again, unless its alert is still open.
   - The table is written only when something changed.
4. **When to check.**
   - While monitoring runs, at once when either setting changes, and every minute for device admins, which Android announces to no other app (`DeviceWatch`).
   - When monitoring starts, and when Sentinel opens.
   - Access gained while monitoring was off is found at the next of these.
5. **What the alert offers**, in order:
   - Android's settings for that access, where it can be turned off. This is the accessibility or notification access screen. For device admins it is the security settings, because Android has no public link to their list.
   - Blocking the app's network (RA-01).
   - Seeing what the app did.

   Nothing is turned off for the user.
6. **The core decides; Kotlin reads.** Kotlin lists what is held, and whether each app is preinstalled (`FLAG_SYSTEM`). The core filters, compares, stores and raises (`HistoryStore.check_access`).

## Verification

- `sentinel-detect`: the rule's id; the alert's severity, actions and stored evidence.
- `sentinel-store`:
  - the first check returns everything held;
  - access gained since is returned, also after reopening;
  - access turned off and on is returned again;
  - a wipe forgets it all.
- `sentinel-ffi`:
  - preinstalled apps are never reported, and duplicates count once;
  - access held stays reported once, even after its alert is dismissed;
  - a new device admin is reported;
  - access turned off and on again after a dismissal is reported again, but not while its alert is open;
  - an app the user allowed raises nothing more.
- On the Android 14 emulator (`SpecialAccessTest`), with the probe app's inert components turned on as Android's shell user would:
  - notification access raises the alert within 5 s while monitoring runs, with its three actions, and only once;
  - an accessibility service raises it within 5 s;
  - a device admin is found at the next check.

  `RtlTest` shows the alert in Arabic, right to left.

## Consequences

- **Honest apps are reported once.** A password manager or a watch app raises one alert; the user allows it, and is not asked again.
- **Device admins are found within a minute while monitoring runs**, not at once. With monitoring off, everything waits until Sentinel opens or monitoring starts. A grant that is turned off again before then is never seen.
- **Preinstalled apps are trusted.** Spyware built into the system image by a vendor or a reseller is out of reach here; it needs the checks from outside the phone (SRS §8A).
- **Other powerful access is not covered yet**: usage access, "display over other apps", installing unknown apps, VPN, and a device or profile owner. These are for the hardening checklist (MS-12) or later.
- **Android may stop exposing `enabled_notification_listeners`.** It is a hidden setting that androidx still relies on. If it is closed, notification access would go unseen. The device test would then fail, rather than the check failing silently.

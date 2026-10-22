# ADR-0023: Checking installed apps against the indicator list

- Status: **Accepted** (Sprint 8; `crates/sentinel-ioc`, `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS ID-13 ("Known stalkerware and remote-access-tool signatures", from the signed IOC list) for apps on the phone. Builds on [ADR-0020](0020-indicator-matching.md), which matches traffic against the same list, and [ADR-0022](0022-result-wording-and-advice.md), whose result and advice every match shares.

## Context

Stalkerware on Android is an app. It may stay quiet on the network for days, or send its data to a cloud host that many other apps also use, so matching traffic ([ADR-0020](0020-indicator-matching.md)) can miss it. Public reports name such apps in two ways:

- by **package name**, which the app keeps on every phone; and
- by the **SHA-256 of its signing certificate**, which finds it under any package name its maker signs it as.

The indicator file format already carries both kinds, `package` and `certificate`. Until now nothing matched them. Seeing every installed app needs `QUERY_ALL_PACKAGES`, which the app declares already for naming the app behind each connection (AM-14, [PLAY-POLICY.md](../PLAY-POLICY.md)).

Some questions had to be settled:

- **When to check.** A list can arrive while monitoring is off. An app can be installed at any time.
- **Which certificates.** An app can have several signers. Since APK Signature Scheme v3, it can also rotate its key, keeping a history of the keys it was signed with.
- **How not to repeat ourselves.** The installed apps are checked again and again. An app that stays installed should not raise a new alert each time, including after the user dismissed it.
- **What the alert offers.** Removing stalkerware can tell whoever installed it that it was found, and removes what a helpline would want to look at.

## Decision

1. **Match package names exactly and certificates by their SHA-256.** A package name is compared as written (Android package names are case-sensitive). A certificate is compared as lower-case hex, whatever case it comes in. The certificates of an app are all of its signers when it has several. Otherwise they are its current certificate and the ones it rotated from, so an app that moved away from a listed key is still found.
2. **Check whenever the list or the apps may have changed.**
   - When a list comes into force, before the update returns.
   - When monitoring starts (apps installed while it was off).
   - When Sentinel opens.
   - While monitoring runs, as soon as an app is installed or updated. Android announces this only to receivers registered while running, so the monitoring service holds one (`InstallWatch`). It listens only to the system.

   Unlike the history ([ADR-0021](0021-retro-hunt.md)), this is not once per list version, because the apps change. A check reads the package list, a few hundred entries, and runs off the main thread.
3. **One alert per app and indicator**, from the same `known-indicator` rule as a traffic match. It is Critical (§8.3).
   - Its evidence is the app and the indicator, with how it was seen: `installed_package` (the package name) or `signing_certificate` (the certificate's SHA-256). It carries the indicator's family, threat, source, report date and link.
   - It is shown as "Known stalkerware or spyware app found", with "Installed as …" or "Signed with the certificate …".
   - It counts in the main screen's result ("Known traces found") and carries the MS-13 advice like every match ([ADR-0022](0022-result-wording-and-advice.md)).
   - An app that matches both by package and by certificate raises one alert for each indicator.
4. **Reported once while the app stays installed.** A match is skipped when a `known-indicator` alert about the same app and indicator, open or dismissed, was raised at or after the app was installed or last updated (Android's `lastUpdateTime`). An app removed and installed again, or updated, is reported again.
5. **No uninstall button.** The alert offers what every match offers: block the app's network, and see what it did. Uninstalling is left to Android's settings, after the advice not to reset the phone yet and to ask a helpline. Removing stalkerware can warn the person behind it, and removes evidence.
6. **One check at a time**, under the lock the history check uses. The core does the matching and the deduplication. Kotlin lists the apps and their certificates (`InstalledApps`).
7. **The device tests use the probe app**, signed with a fixed test key (`apps/android/probe/test-signing.p12`, SHA-256 `be9200574eb6aa1083aa108b7e50625edc2c86787593ad5b35a68c110284b64f`) so that its certificate is the same on every build. Test list 4 names its package, list 5 its certificate. The key signs nothing else, and its password is no secret.

## Verification

- `sentinel-ioc`: an app is matched by its package name, or by its certificate in either case. Package, certificate, domain and address indicators never match each other.
- `sentinel-detect`: the two new sightings are stored by name.
- `sentinel-ffi`:
  - with no list there is no check;
  - a list finds an app by package, one by certificate (given in upper case), and one by both (two alerts), and nothing for an app it does not name;
  - checking again raises nothing, although one alert was dismissed;
  - an app installed anew is reported again;
  - with the clock two days before the install time, a listed app is reported once, not at every check;
  - the result counts every alert.

  The device tests' lists 4 and 5 name the probe's package and certificate, and only those lists do.
- On the Android 14 emulator (`InstalledAppTest`):
  - the probe installed before list 4 arrives raises a Critical alert about it, with the package as seen, its threat and source, and the offer to block it; checking again raises nothing, and the result counts one alert;
  - list 5 finds it by its signing certificate;
  - with list 4 in force and monitoring on, installing the probe raises the alert at once.

  `RtlTest` shows the alert in Arabic, right to left, with the package name written left to right.

## Consequences

- **The list knows only what was reported.** An app under a new package name and a new key is not found until a list names it. Neither is a stalkerware feature hidden inside an app that is not on the list. ID-12 (apps holding accessibility, device-admin or notification-listener access) is the check for those.
- **Hidden apps are found.** The check reads the package manager, not the launcher, so an app without an icon is listed like any other. Apps in a work profile or another user on the phone are not seen.
- **Updating a listed app reports it again.** That is rare, and the app is still there.
- **The device clock decides "since installed".** If the clock is set back after an alert, a reinstall made before the alert's time is not reported again until the app is updated. An install time more than a day past the clock means the clock was set back since the install. Then any earlier alert counts, so that each check does not report the app again (audit A-52). A reinstall then goes unreported, and the app is reported once more when the clock passes its install time.
- **Google Play.** The check needs `QUERY_ALL_PACKAGES`. If Google refuses the declaration, the Play build falls back to checking only the packages the list names ([PLAY-POLICY.md](../PLAY-POLICY.md)), and loses the certificate check.
- **Which public lists are imported, and under which licences, is the feed builder's task.** It is done offline, with the real signing keys (ADR-0019).

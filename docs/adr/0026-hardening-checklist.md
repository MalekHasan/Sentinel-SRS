# ADR-0026: The hardening checklist on Android

- Status: **Accepted** (Sprint 8; `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS MS-12 ("Hardening checklist with guided steps: … Android Advanced Protection, automatic updates, … disabling unused messaging apps"; acceptance: "Each item shows current status where readable, else a manual check") on Android.

## Context

Detection finds traces of spyware, and some of it cannot be found at all (§8A.3). The steps that make spying harder matter as much, and most users do not know them. MS-12 asks for a checklist that shows where each step stands when the phone lets Sentinel read it, and asks the user to check it otherwise.

What Android lets an ordinary app read:

| Step | Readable? | How |
| --- | --- | --- |
| Advanced Protection (Android 16+) | yes, with a permission granted at install | `AdvancedProtectionManager.isAdvancedProtectionEnabled()`, permission `QUERY_ADVANCED_PROTECTION_MODE` |
| Security update | yes | `Build.VERSION.SECURITY_PATCH`, the date of the update installed |
| Automatic system updates | no | the setting belongs to each maker |
| Screen lock | yes | `KeyguardManager.isDeviceSecure()` |
| USB debugging | yes | the global setting `adb_enabled` |
| Apps allowed to install other apps | no | an app may read only its own permission |
| Unused messaging apps | no | only the user knows what they use |

## Decision

1. **Six steps, in order of protection:**
   - turn on Advanced Protection;
   - install the latest security update;
   - lock the screen with a PIN or password;
   - turn off USB debugging;
   - check which apps may install other apps;
   - remove messaging apps no longer used.

   The screen lock and USB debugging are not in MS-12's list, but they guard against what stalkerware needs most: a few minutes with the phone. [ADR-0025](0025-device-posture.md) left USB debugging to this checklist.
2. **Four statuses:**
   - **Done**, as far as the phone shows.
   - **To do.**
   - **Check this yourself**, when Android does not let Sentinel see it.
   - **Not on this version of Android**: Advanced Protection before Android 16, with nothing to open.
3. **"Recent" means at most 90 days old.** A security update older than that is a step to take. Android's security bulletins are monthly, and makers often ship them a month or two late. The update's date is shown. Automatic updates cannot be read, so the date stands for them. A date more than 31 days past the phone's clock is left for the user to check (audit A-52): some makers ship a month's update before the month begins, but further ahead the clock or the date is wrong, and the update's age cannot be told.
4. **The core works out the statuses** (`sentinel_detect::checklist`, exported as `hardening_checklist`) from facts Kotlin reads, as of today. That way the rules are tested on the host and shared with the other editions later. Nothing is stored: the checklist is read again each time it is shown, including when the user comes back from Android's settings.
5. **Each step opens Android's settings for it** where Android names a screen:
   - security settings, for Advanced Protection;
   - system updates, else "About phone";
   - the screen lock picker;
   - developer options;
   - "Install unknown apps";
   - the list of apps.

   Sentinel changes none of these itself.
6. **The checklist never says the phone is safe.** It says each step makes spying harder, and that none of them can show the phone is not watched (§8A.3, NF-11). It is reached from the main screen ("Make this phone harder to spy on").

## Verification

- `sentinel-detect`:
  - dates count days from 1970 and malformed ones are refused;
  - a hardened phone has every readable step done, in order;
  - each readable step can be left to do, and 90 days is still recent while 91 is not;
  - an update dated 31 days ahead is done, and one dated 32 days ahead is for the user to check;
  - what cannot be read is the user's to check;
  - Advanced Protection is not available before Android 16.
- `sentinel-ffi`: the checklist is worked out as of today.
- On the Android 14 emulator (`HardeningTest`):
  - the security update matches `getprop`, and USB debugging matches `settings`;
  - each status follows what was read;
  - the screen shows each step's status and the update's date, and opens settings only for steps that exist;
  - the main screen opens the checklist.

  `RtlTest` shows the checklist in Arabic, right to left.

## Consequences

- **Advanced Protection is tested only where it is missing.** The CI emulator runs Android 14, where it is "not on this version". Reading it on Android 16 is a single platform call; it should be checked by hand on an Android 16 phone before release.
- **"Done" is only what the phone reports.** A recent security update does not mean the phone has no unpatched holes, and a screen lock does not stop someone who knows the PIN. The wording says "Done", never "safe".
- **Two steps always ask the user.** Installing unknown apps could be partly read by listing the apps that ask for that permission, but not whether it was granted, which is the part that matters.
- **The 90-day threshold is a judgement.** It may need tuning for makers whose updates are quarterly by design.

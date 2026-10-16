# ADR-0027: Microphone and camera monitoring on Android (basic mode)

- Status: **Accepted** (Sprint 8; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements, on Android:
  - SE-01 in basic mode: record the start and stop of microphone and camera access, logged within 2 s;
  - SE-03: a persistent "in use now" notification, visible within 1 s;
  - SE-04: flag use while the screen is off or locked, as a High alert.
- Follows AM-15 and [PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md) §3. It stands in for the ADR-0007 that [Spike 3](../SPIKE-3-SENSORS.md) was to produce: the spike's real-phone matrix has not run.

## Context

An ordinary Android app learns little about the microphone and camera:

| Signal | API | Permission | What it tells |
| --- | --- | --- | --- |
| Microphone in use | `AudioManager` recording callback | none | Some app records, or stops. Which app is hidden from non-system apps. |
| Camera in use | `CameraManager` availability callback | none | Camera N is taken, or free again. No app. |
| App on screen | `UsageStatsManager.queryEvents` | usage access, granted by the user in Settings | Which app was last shown: a guess at who uses the sensor. |

Android 12 and later show their own privacy indicator and dashboard. The dashboard names the app, but no other app can read it. The exact attribution SE-01 asks for "with ADB grant" needs privileged AppOps calls; Spike 3 was to test it on real phones, and it is a Should item (PHASE-A §2).

## Decision

1. **Every use is recorded** in the SRS `sensor_use` table (schema 17): the sensor (`mic` or `camera`), start, end, `user_present`, and `source`.
   - `source` says how the app was found: `unknown`, `foreground` (the guess) or `exact`. `app_id` is the app when known or guessed.
   - A recording the system silences still counts. An app recording in the background is the case to see.
   - When monitoring stops, open uses end then.
2. **The guess is labelled as one, everywhere.**
   - With usage access, the app last on screen when the use began is kept as the guess. Sentinel itself and the home screen are not guessed: they record nothing.
   - The main screen says "On screen when it began: … This is only a guess."
   - Without usage access it says the app is not known, and offers to open the usage access settings. Usage access is asked for there, never at first run (PLAY-POLICY.md).
3. **SE-03:**
   - While any sensor is in use, an ongoing notification on a quiet channel of its own says "Microphone in use now", "Camera in use now" or both.
   - It adds that Android does not tell Sentinel which app it is.
   - It is posted on the callback's thread, before the history is written, and removed when the last use ends.
4. **SE-04: use while away raises a High alert, `sensor-while-away`, once per use.** Away means the screen is off or the lock screen shows, the same test as for traffic while away (CM-06).
   - A use that begins while away raises it at once. A use that is still going when the screen goes off raises it then.
   - The alert names no app, because a guess is not proof. Its evidence holds the guess, labelled as such.
   - It offers Android's privacy settings: on Android 12 and later their dashboard shows which app it was.
5. **Off the main thread.** The callbacks run on the main thread. The history is written in order on a thread of its own, holding the open use of each sensor.

## Verification

- `sentinel-detect`: names round-trip; the alert is High, names no app, offers the privacy settings, and its stored JSON is fixed.
- `sentinel-store`:
  - uses keep their start, end, guess and attribution;
  - the screen going off is noted once, and never after the end or for a use that began away;
  - stopping monitoring ends open uses.
- `sentinel-ffi`:
  - a use with the user there raises nothing;
  - the screen going off raises one alert however often it is reported;
  - a camera use begun away raises one.
- On the Android 14 emulator (`SensorTest`), with the probe app given the permissions by `pm grant` and Sentinel given usage access by `appops`:
  - the probe's recording is recorded within 2 s with the probe as the guess; the notification shows within 1 s and goes when the use ends; no alert;
  - with the screen turned off during a recording, a High alert names the microphone, the start and the guess;
  - opening the emulated back camera is recorded and shown.

  The CI emulator runs with sound and an emulated back camera. `RtlTest` shows the record and the alert in Arabic, right to left.

## Consequences

- **Attribution is a guess.** A recorder in the background while the user reads the news is reported with the news app as the guess. The wording says so everywhere.
- **Calls do not count as away.** During a call the proximity sensor turns the screen off but the phone stays interactive, so this is not flagged. A voice memo recorded in a pocket is flagged. Its alert can be dismissed or allowed.
- **Allowing this alert stops it for good.** It is about no app, so allowing it (AL-05) stops `sensor-while-away` entirely, as for other alerts about the phone itself.
- **Hotword detection is not seen**, as Android runs it outside normal recordings, and neither is anything on a phone without monitoring on.
- **Spike 3 still has to run on real phones** (Samsung, Xiaomi, a recent Pixel). It must confirm the callbacks, the 2 s timing, the guess, and whether the ADB path gives exact attribution (the Should item).

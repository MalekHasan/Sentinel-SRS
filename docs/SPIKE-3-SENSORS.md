# Spike 3: microphone and camera monitoring on Android

Version 0.1 · Oct 2026 · Status: **test plan**. Needs real phones, so it runs in Sprint 1 alongside the phone part of Spike 1. Results go into ADR-0007.

## Question

What can a normal, non-system app learn about microphone and camera use by other apps on Android 10 to the latest version (SRS SE-01, SE-03, SE-04)? And does an ADB-granted permission give exact per-app history, as SRS §4.2 assumes?

## Candidate signals

| Signal | API | Permission | What we expect (to verify) |
| --- | --- | --- | --- |
| Mic in use | `AudioManager.registerAudioRecordingCallback` | none | Start and stop events; the app's identity is hidden from non-system apps |
| Camera in use | `CameraManager.AvailabilityCallback` | none | Camera N became unavailable or available; no app identity |
| Foreground app | `UsageStatsManager.queryEvents` | Usage access (user grants it in Settings) | The app on screen when the sensor started: a best guess for basic mode |
| Exact app, live | `AppOpsManager.startWatchingActive` (ops `RECORD_AUDIO`, `CAMERA`) | `GET_APP_OPS_STATS` via ADB, maybe more | Unknown: may need a privileged permission |
| Exact app, history | `AppOpsManager` historical ops | `GET_APP_OPS_STATS` via ADB | Unknown: some of these APIs are system-only |
| Location use | AppOps `FINE_LOCATION`, `COARSE_LOCATION` | same as above | SE-02 |

## Test matrix

| Device | Android | Why |
| --- | --- | --- |
| Emulator or Pixel | 10 (API 29) | minSdk |
| Any | 12 (API 31) | Privacy indicators and the mic and camera toggles were added |
| Samsung | 14 (API 34) | Most common vendor skin in our region |
| Xiaomi or Redmi | 14 or 15 | Aggressive background limits |
| Pixel | Latest | Newest restrictions |

## Procedure

For each device, with a small debug screen that logs every callback with a timestamp:

1. **Baseline:** no permissions granted. Record the voice recorder app for 10 s, then open the camera app for 10 s. Note which events arrive, how fast (SE-01: within 2 s), and with what identity.
2. **Usage access:** grant it in Settings and repeat. Check whether the foreground-app guess names the right app.
3. **Screen off:** start a recording app that keeps recording with the screen off. Check whether events still arrive (SE-04).
4. **Background recorder:** a test app records from a foreground service while another app is on screen. This is the case where the foreground-app guess is wrong. Record how wrong.
5. **ADB grant:** `adb shell pm grant io.github.malekhasan.sentinel android.permission.GET_APP_OPS_STATS`, then try both AppOps approaches. Record which calls work and which throw `SecurityException`.
6. **Camera and mic toggles (Android 12+):** turn the system toggles off, then try to record. Check what is reported.

## Recording results

For each device, record:

| Field | What to write |
| --- | --- |
| Device | Model |
| Android version | e.g. 14 |
| Signal | Which API |
| Works | Yes, partial or no |
| Latency | Time from event to callback |
| Identity | Which app, if any |
| Notes | Anything else |

Then decide in ADR-0007:

- **Basic mode:** which signals, and the exact wording for "approximate" attribution (AM-15).
- **Exact mode:** whether the ADB path works on each version. If it does not, remove "exact with ADB grant" from SRS §2.2 and SE-01.

## Out of scope

- Accessibility services: banned by the SRS (§2.4).
- Root or Shizuku-style privileged helpers: possible later, not in Phase A.

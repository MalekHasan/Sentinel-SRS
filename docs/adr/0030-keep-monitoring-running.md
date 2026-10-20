# ADR-0030: Battery steps that keep monitoring running

- Status: **Accepted** (Sprint 9; `apps/android`)
- Date: 2026-10-16
- Implements the "guided battery-optimisation steps per brand" of [PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md) §2 (risks) and §6 (Sprint 9), and the "always-on VPN instructions" of its release risks. Goes with the heartbeat ([ADR-0029](0029-heartbeat.md)) under SP-03.

## Context

Monitoring needs Sentinel's VPN service to keep running. Android stops background work to save battery:
- Doze and App Standby;
- background restrictions the user sets.

Several phone makers add their own layer, which stops apps more often and more harshly. That layer is the "don't kill my app" problem documented at dontkillmyapp.com. Each stop is a gap, and many gaps make a monitor worth little.

What Sentinel can read:

| Setting | API | Readable |
| --- | --- | --- |
| Battery optimisation | `PowerManager.isIgnoringBatteryOptimizations` | Yes, no permission |
| Background restriction | `ActivityManager.isBackgroundRestricted` | Yes, no permission |
| Always-on VPN | `VpnService.isAlwaysOn` | Only by the running VPN service |
| Maker settings (autostart, app launch, sleeping apps) | none | No |

Android offers a dialog that exempts an app from battery optimisation in one tap: `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`. It needs the `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` permission, which Google Play allows only for a few kinds of app, and lint flags it as a policy risk.

## Decision

1. **A "Keep monitoring running" screen**, opened from the main screen. It has three of Android's steps, each with:
   - where it stands, when Sentinel can read it ("Done", "To do");
   - what to do;
   - a button to Android's screen for it.
2. The steps:
   - **Battery optimisation.** Opens Android's list of apps and their optimisation, which needs no permission.
     - The one-tap dialog is not used, nor its permission.
   - **Background restriction.** Opens Sentinel's page in Android's settings.
   - **Always-on VPN.** Opens Android's VPN settings.
     - Read by the service when it starts. While monitoring is off, it says Sentinel can see this only while monitoring runs.
     - The text says to leave "Block connections without VPN" off. Sentinel fails open by design (NF-07): with that setting on, a stopped Sentinel would cut the phone off.
3. **The phone maker's own steps**, chosen by `Build.MANUFACTURER`.
   - Makers with their own steps:
     - Samsung;
     - Xiaomi (with Redmi and POCO);
     - Huawei (with Honor);
     - OnePlus;
     - OPPO (with realme);
     - vivo (with iQOO);
     - Google Pixel.
   - Any other maker gets general steps.
   - Each set is written for Sentinel, in both languages; no text is copied from elsewhere. The menu paths are the ones these makers' recent versions are known to use. They were not checked against dontkillmyapp.com or on a phone while this was written.
   - A line says that menu names change between versions, and a button opens Sentinel's page in Android's settings, where most makers put these switches.
4. **Nothing is changed for the user.** Every step is theirs to take in Android's settings.

## Verification

On the Android 14 emulator:
- `KeepRunningTest`:
  - battery optimisation reads as Android reports it, both ways, set with `cmd deviceidle whitelist`;
  - the app under test is not restricted in the background;
  - always-on cannot be read while monitoring is off;
  - each maker name, with its other brands, finds its steps;
  - the screen shows where each step stands; each step opens its settings; the maker's steps for this device are shown and open Sentinel's settings;
  - the main screen opens it.
- `RtlTest.keepRunning`: the screen in Arabic, right to left, with a maker's steps.

## Consequences

- **The maker steps cannot be checked by Sentinel, and may be wrong or out of date.** Makers rename and move these menus with each version. Before release, each set must be checked:
  - on the reference phones (Samsung, Xiaomi, Pixel; the Sprint 9 performance work);
  - for the other makers, against dontkillmyapp.com.

  After that, they must be kept up to date.
- **Background restriction is not toggled in a test.** Restricting the app under test could stop its process mid-run. It is read from Android only.
- **No reminder is shown.** The screen is there for the user to open; a gap does not yet point to it.

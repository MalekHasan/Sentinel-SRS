# ADR-0038: Monitoring starts again after a crash, and repeated stops are Critical

- Status: **Accepted** (Sprint 10; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-20
- Implements SP-02 on Android: "Service recovery restarts Sentinel after a crash; repeated stops raise a Critical alert". Closes THREAT-MODEL-A D7, found by the Sprint 10 review (finding F3).

## Context

Monitoring runs in Sentinel's VPN service. Its process can die while monitoring runs:
- Android kills it to free memory, or the phone maker's battery management does;
- Sentinel crashes.

Android then sends traffic outside the tunnel (NF-07). The gap is recorded when Sentinel's process next starts (ADR-0008, ADR-0029).

The service returned `START_NOT_STICKY`, so Android did not start it again:
- Monitoring stayed off until the user opened Sentinel, or until always-on VPN, if set, started it.
- The phone could go unwatched for days without anyone knowing.

The heartbeat (ADR-0029) replaces an engine that hangs, but only while the process lives.

## Decision

1. **While monitoring runs, the service is sticky** (`START_STICKY`). When its process dies, Android starts the service again, without an intent.
   - **Restart without an intent:** monitoring starts only if the user still wants it. Their own Stop clears that.
   - **The gap:** it opens as the new process starts, from when Android recorded the exit or the engine was last heard from, and closes once monitoring runs.
   - **Never restarted:** a Stop, a VPN taken over by another app or switched off in Android's settings, and a start that fails all end the service.
   - **A Stop refused on a locked phone** (THREAT-MODEL-A T5) keeps the service sticky.
2. **Repeated stops raise a Critical alert**, "Monitoring keeps stopping":
   - **When:** at the third gap within 24 hours (`REPEATED_GAPS`, `REPEATED_GAPS_HOURS`). Every gap counts, whatever stopped monitoring, from when it began.
   - **Evidence:** the count and the hours.
   - **Action:** it offers "Keep monitoring running" (ADR-0030).
   - **Its text:** the phone maker's battery settings often cause this; so can an app that takes over the VPN, or a fault in Sentinel.
   - **Once:** a single alert while it is open. Each gap still raises its own Warning (SP-03).

## Verification

- `sentinel-detect`: the alert is Critical from the third gap, about no app, offering "Keep monitoring running", and its stored form is fixed.
- `sentinel-store`: gaps are counted from their start, from their end when the start is unknown, and an open one with no known start counts as now.
- `sentinel-ffi`:
  - two gaps a day ago and two now raise nothing;
  - the third raises one Critical alert with its evidence and action;
  - a fourth while it is open raises no second one.
- On the Android 14 emulator:
  - `GapLogTest`: three stops raise one Critical alert, with its evidence and action;
  - `RtlTest`: the alert in Arabic, right to left, with its count.
- **Restart:** `apps/android/scripts/restart-after-kill.sh`, in CI after the instrumented tests. Those tests cannot check this, as they die with the app's process.
  - The script installs the app, taps "Start monitoring", and kills the process with SIGKILL, as the low-memory killer does.
  - It then waits for the service to run in the foreground in a new process, and to stay running.

## Consequences

- **A crash loop:** Android spaces out the restarts of a service whose process keeps dying. The Critical alert says the phone is not watched meanwhile.
- **"Force stop"** in Android's settings stops an app for good until it is opened again: Android restarts nothing. The gap is recorded when Sentinel next starts, with the exit Android recorded.
- **Not covered: a phone maker that blocks restarts.** Some makers stop an app from starting again in the background whatever it asks. "Keep monitoring running" and always-on VPN are the answer there.

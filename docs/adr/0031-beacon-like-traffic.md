# ADR-0031: Beacon-like traffic

- Status: **Accepted** (Sprint 9; `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements DL-04 on Android: "Detect regular beacon-like traffic (fixed interval, low jitter, small payloads) from non-system apps".
  - Its acceptance has two parts:
    - detected in the beacon simulation test;
    - under 5% false positives on reference apps.
  - The first is met here. The second needs the reference phones.

## Context

Spyware that has nothing to send still checks in with its server, to say it is alive and to ask for orders. It does so at a fixed interval, with a small request and a small answer. Seen from the network, that looks like:
- the same app;
- the same server;
- the same gap between connections, again and again;
- little data each time.

Many ordinary apps poll too: mail, weather, news and chat apps without push. So this pattern on its own does not mean spyware.

The engine already reports every flow's app, destination name (DNS or TLS server name, else address), start time and bytes when it ends.

## Decision

1. **The detector is in the core** (`sentinel_detect::Beacons`), fed each flow as it ends: its app, its destination, when it began, and the bytes it carried both ways.
   - **One check-in** is one connection, or several begun within 2 s of each other.
   - **A beacon** is 8 check-ins in a row from one app to one destination (seven intervals) where:
     - the typical (median) interval is between 10 s and an hour;
     - every interval is within a tenth of the typical one;
     - each check-in carried at most 16 KiB both ways.
   - A larger check-in breaks the pattern, and the count starts again.
   - Connections that end out of order are put in order of start.
   - Memory is bounded: at most 4096 app and destination pairs are followed, and the one seen least recently is forgotten first. Each pair keeps its last 8 check-ins.
2. **What is not counted:**
   - system apps (`FLAG_SYSTEM`, or one of Android's own UIDs), which the app now tells the core with each flow's owner;
   - DNS, which DL-05 is for;
   - blocked connections, which carried nothing;
   - connections of no known app.
3. **The alert** (`beacon-like`) is **Info**:
   - Its evidence is the app, the destination, the typical interval, the number of check-ins and the most data one carried.
   - It offers to block the app or to look at it.
   - Its text says that spyware can check in like this, and so do many apps that just look for news.
   - Each pattern is reported once per monitoring run. Like other alerts about an app, a new one is raised only once the earlier one is put away (AL-05 "allow" and "not useful" apply as usual).

## Verification

- `sentinel-detect`, the beacon simulation:
  - check-ins every minute, up to 2 s off, with half a kilobyte each: found once, at the eighth;
  - found when they end out of order, and when each check-in is two connections;
  - not found for:
    - intervals a fifth off;
    - someone browsing;
    - every 5 s;
    - every 2 hours;
    - 64 KiB each;
  - a large transfer starts the count again;
  - apps and destinations are followed apart;
  - memory stays bounded;
  - the alert is Info, offers to block and to look, and its stored JSON is fixed.
- `sentinel-ffi`: through the flow observer and the history, an app checking in every minute raises one Info alert naming the server and the interval. The same pattern from a system app, or over DNS, raises none. Removing either exclusion makes the test fail.
- On the Android 14 emulator:
  - `BeaconTest`: Android itself and Settings are system apps; Sentinel and an unknown owner are not.
  - `RtlTest.beaconAlert`: the alert in Arabic, right to left, with the server, the interval and the size.

## Consequences

- **The false-positive rate is not measured.** DL-04 asks for under 5% on reference apps. That needs a day of ordinary use on the reference phones with their common apps, counted by hand. Until then, the thresholds above are a first guess.
- **Apps that poll will be flagged**, which is why the alert is Info and says so. "Not useful" keeps later ones about that app quiet.
- **A beacon with more than a tenth of jitter, or longer than an hour between check-ins, is not found.** Nor is one that keeps a single connection open and talks over it: that is one flow.
- **Patterns are not kept across runs.** A restart of monitoring starts every count again, so a beacon every hour needs seven hours of one run.

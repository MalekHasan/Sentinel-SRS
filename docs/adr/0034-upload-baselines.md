# ADR-0034: Upload baselines per app

- Status: **Accepted** (Sprint 9; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements the upload volume part of DL-02 on Android: "Baseline each app's normal upload volume, destinations and hours; alert on large deviations". Acceptance: "Alert on 10× upload over a 14-day baseline".

## Context

Spyware that collects photos, recordings or messages has to send them somewhere. An app that usually sends a few megabytes a day and suddenly sends hundreds stands out. That holds whatever server it uses, and even if the server is new or hidden behind a large cloud.

The history keeps every connection's bytes sent, per app (SRS §13): in full for 30 days, then rolled into daily totals.

## Decision

1. **An app's usual day** is what it sent in the 14 days before the last day, divided by 14 (`sentinel_detect::upload_windows`). Rolled-up days count. Days with nothing sent count as nothing.
2. **A surge** is the app sending, in the last 24 hours, at least ten times its usual day. The usual day is taken as at least 1 MiB, so an app that usually sends almost nothing must still send 10 MiB in a day.
   - Only apps the history has known for the whole 15 days are judged; before that their usual day is not known.
3. **The check** is one query over the last 15 days of flows (by the index on start time) and the rolled-up days. It returns only apps that sent at least 10 MiB in the last day.
   - The flow observer runs it with the first batch of each monitoring run and then at most every 15 minutes.
4. **The alert** (`upload-surge`) is a **Warning**.
   - Its evidence is the app, what it sent in the last day, its usual day and the number of days measured.
   - It offers to block the app or to look at it.
   - Its text says that backups and big uploads do this, and so does spyware that sends files out.
   - At most one a day per app: none while its last one is open, nor within a day of it.
5. **Not yet:** the baseline of an app's usual destinations and hours. New destinations are already flagged (CM-04, ADR-0013). Unusual hours are left for later: on a phone, when an app is used depends on its user more than on the app.

## Verification

- `sentinel-detect`:
  - ten times the usual day is a surge, one byte less is not;
  - an app that usually sends nothing needs 10 MiB;
  - an app known for 14 days is not judged, one known for 15 is;
  - the windows are right;
  - the stored JSON is fixed.
- `sentinel-store` (against a real encrypted database): three apps with the same usual days and 25, 15 and 5 MiB in the last day.
  - The first two are returned with the right totals, the third sent too little to look at.
  - The totals are the same after the older days are rolled up.
  - Only the first is a surge.
- `sentinel-ffi`:
  - a surge raises one Warning with its evidence;
  - nothing again while it is open, or within a day after it is dismissed;
  - the next day, yesterday's surge counts in the usual days. 12 MiB is then no longer a surge, and 20 MiB is.
- `RtlTest.uploadSurgeAlert`: the alert in Arabic, right to left, with sizes in Arabic.

## Consequences

- **An upload in progress counts when its connection ends**, as bytes are stored then. A single connection that streams for hours is judged after it closes.
- **An app's first two weeks are not judged.** Spyware installed recently and sending at once is not caught by this rule. It is caught as new to the network (CM-04) and, if listed, by the indicators.
- **Backups, video calls and uploads the user chose will raise it** when they are ten times the usual day. "Not useful" keeps later ones about that app quiet.
- **The thresholds are a first guess**, to be checked on the reference phones.

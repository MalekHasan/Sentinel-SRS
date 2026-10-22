# ADR-0013: New apps and new destinations

- Status: **Accepted** (Sprint 5; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS CM-04 ("flag first-ever network use by an app and first-seen destinations per app"), with the Info severity §8.3 gives a first-seen destination

## Context

CM-04's acceptance test is an alert on the first run of a new program. Its second half, first-seen destinations, is listed as Info in §8.3. Both need the history to know what is new, and both can be very noisy:

- **On the first day, everything is new.** Sentinel has never seen any app. An alert for every app's "first" connection would be dozens of false alerts, and most of those apps used the network long before Sentinel was installed.
- **Some apps reach new names all the time.** A browser reaches new sites every day. A video app reaches numbered servers such as `rr3---sn-4g5e.googlevideo.com`. One alert per new name would bury everything else.
- **Addresses change.** Large services answer from many addresses that change often. Connections known only by their address (QUIC, or DNS that Sentinel does not see, such as Private DNS) would be "new" all the time.
- **Names can change while a connection is open.** A connection can start with a name from a DNS answer, and the TLS handshake can then give the name the app asked for.

The alert model, delivery and feedback are [ADR-0012](0012-alerts.md)'s.

## Decision

1. **Two rules, both Info.** `first-network-use`: an app used the network for the first time. `new-destination`: an app connected to names it had not used before. Info alerts are silent (ADR-0012's channel table) and wait during Do Not Disturb. The rate limit, "not useful" and "allow" apply as to every rule, so the user can silence one app that is often flagged, such as a browser.
2. **The history knows when it began** (schema version 9, `meta`). That is when it was created: the first start, or the last wipe. A database upgraded from version 8 begins at the upgrade.
3. **An app is new only if it was installed after the history began.** Kotlin gives each connection's owner its install time (`PackageInfo.firstInstallTime`, which updates keep). The core raises `first-network-use` when the history sees the app for the first time and that time is at or after the history's start. An app that was already installed when Sentinel started may have used the network before, so it raises nothing. Android's own system identities (for example `android.uid.system:1000`) have no install time, so they raise nothing either. Packages that share a Linux user (`sharedUserId`) are one app on the network, named by the user; it is new when one of its packages is, by the newest of their install times (audit A-09). Before, such a user had no install time, so spyware made of two packages never raised this alert.
4. **The alert names where the app first went**: the connection's name, or its address if no name was known when it started. It is raised when that connection starts, so it comes within the one-second batch of CM-01.
5. **Each app's destinations are learned for a week before new ones are flagged** (`LEARNING_MS`). A week also covers apps used only on some days. During those seven days every name is recorded, but none raises an alert.
6. **Only names count as destinations.** A connection known only by its address is recorded, but it is never a "new destination", because addresses change too often to mean anything. Bad addresses are the job of the signed indicator list (ID-13, MS-10).
7. **A destination is judged when the connection ends**, by the name it ended with. A TLS server name replaces a DNS name, so a connection is not first flagged under a name that its handshake then corrects. A long connection is flagged late, which is acceptable for Info.
8. **One alert per app per day.** New names join the app's open `new-destination` alert if it was raised in the last 24 hours (`GROUP_WINDOW_MS`). The listener is not called again, so nothing is notified twice. An alert lists up to 20 names (`MAX_LISTED`) and counts the rest. Once the user dismisses it, the next new name raises a new alert.
9. **The history keeps the names each app has used** in an `app_destination` table (schema 9), so a check takes one indexed lookup. The table is first filled from the flows and daily totals already kept. It is not rolled up or trimmed by retention, so a name an app used a year ago is still not new. A wipe clears it with the rest.

## Verification

- `sentinel-detect`:
  - an app installed at or after the history's start is new; one installed before, or at an unknown time, is not;
  - the learning week holds back new destinations;
  - destinations are listed up to 20, then counted; a newer alert joins an open one;
  - the rule ids and the stored evidence format are fixed by tests.
- `sentinel-store`:
  - the history's start survives reopening, and a wipe starts a new one;
  - an app's first connection is reported when it starts, with its name or address;
  - a name is reported once per app, when its connection ends, by its final name. Unnamed and unowned connections report nothing, and a name is still known after reopening and the roll-up;
  - the version 9 upgrade fills the table from flows and daily totals and leaves out addresses;
  - joining picks only an open alert of the same rule and app within the window.
- `sentinel-ffi`:
  - through the real packet engine (`writes_flows_to_the_history`), an app installed after the history began raises one Info alert naming where it went;
  - with flows fed directly: only the app installed after the start raises an alert, once;
  - after the learning week, new names share one alert, and the listener hears it once; names already used and a new app's names raise nothing;
  - after dismissing, the next name raises a new alert, and allowing the rule for the app stops them.
- On the Android 14 emulator:
  - `FirstSeenTest` checks that install times come from the package manager and that shared identities have none, and that the owner of Android's own shared user lists its packages without an install time;
  - it checks that, right after a wipe, Sentinel's own connections through the tunnel raise no "new app" alert, because it was installed before the history began;
  - `AlertsTest` and `RtlTest` show both rules with their listed and counted destinations, in English and in Arabic, right to left;
  - `AlertTextTest` grades the new texts.

## Consequences

- **The positive case is tested on a device since Sprint 6.** An app installed after the history began needs a second app, installed during the test, that then uses the network. `FirewallModeTest` installs one, the probe ([ADR-0016](0016-firewall-modes.md)), and its first connection raises the alert. Before that, the core's engine test covered the path with a real packet.
- If monitoring was off when a new app first used the network, its first connection seen later is still reported as its first. The alert says what Sentinel saw.
- Names come from DNS answers that Sentinel sees and from TLS handshakes. A DNS name for a shared address can belong to another app's query, which can flag a name the app did not ask for. QUIC connections without a DNS answer Sentinel saw have no name, so they are never flagged.
- New names are compared exactly. Without a public suffix list, `rr3---sn-4g5e.googlevideo.com` and `rr5---sn-4g5e.googlevideo.com` are different names. A video app can therefore raise its one alert most days until the user marks it "not useful" or allows it. Grouping by registrable domain (the `destination.etld1` column) would need the Public Suffix List as a new data source; it is left until noise measured in the beta shows the need.
- `app_destination` grows by one row per new name per app. For a heavily used browser that can be tens of thousands of rows a year, a few megabytes.

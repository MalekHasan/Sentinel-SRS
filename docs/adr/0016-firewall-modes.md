# ADR-0016: Firewall modes on Android: Watch only and Block new apps

- Status: **Accepted** (Sprint 6; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS CM-08 for Android, the Phase A subset: Monitor and Block unknown ("Mode switch takes effect within 1 s"). Prompt mode (CM-09) is for Windows and macOS; Lockdown is a Phase A "should".
- Amended 2026-10-22 for audit finding A-09 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decision 2, connections without a known owner, and apps that share a Linux user.

## Context

CM-08 lists four firewall modes: Monitor (log only), Prompt (ask for unknown apps), Block unknown, and Lockdown (only allow-listed apps). SRS §9 allows one kind of automatic action by default: "firewall decisions in Block-unknown or Lockdown mode". Every other block is the user's own rule ([ADR-0015](0015-firewall-rules.md)).

The SRS does not say what makes an app "unknown". On Windows (§17.1), a learning period decides: known-good signed apps are allowed and recorded, and unknown apps prompt. A phone has no prompt for a connection that is waiting. It also has no learning period that a user would sit through. And every app on it comes from a store or was installed on purpose, signed by its maker.

The choices for "unknown" on Android were:

| Unknown means | Problem |
| --- | --- |
| Never seen using the network by Sentinel | On the first day every app is unknown, including the browser. Switching the mode on would break the phone |
| Installed after Sentinel's history began (the CM-04 "new app") | An app installed last month and used every day since would be blocked the moment the mode is switched on |
| Installed after the mode was switched on | None of the above. An app the user installs later is stopped until they allow it, which is what "block new apps" means to a user |

Android gives every app its first install time (`PackageInfo.firstInstallTime`), which updates keep. Sentinel already reads it for each connection's owner (CM-04, [ADR-0013](0013-first-seen.md)).

## Decision

1. **Two modes on Android: Watch only (Monitor) and Block new apps (Block unknown).** Watch only is the default. In it, nothing is blocked but what the user's rules block.
2. **Block new apps blocks the apps installed since it was turned on, until a rule allows them.** The history keeps when the mode was turned on (schema version 12, `firewall_mode`). A connection whose app was installed at or after that time is blocked, unless a rule decides otherwise. The decision uses the same three moments as the rules: when a connection starts, at its TLS server name, and at a DNS lookup through the tunnel.
   - Apps installed before, and Sentinel itself, are never stopped by the mode.
   - Connections whose app has no install time (Android's own system identities, such as `android.uid.system:1000`) are never stopped by the mode. Blocking them could break the phone, and Sentinel cannot tell new from old there.
   - **Connections Android cannot name an owner for are stopped by the mode**, unless a rule that names no app allows where they go. Such a connection may be a new app's: an app can make its owner unknown by closing its socket before Sentinel asks Android, which works for a UDP datagram sent and forgotten (audit A-09). Ordinary traffic comes from sockets still open, whose owner Android finds, and the system resolver makes DNS lookups as the app that asked. How much traffic on real phones has no known owner is not measured yet: a connection the mode stops is stored as blocked, with no app. Before, these connections were never stopped, and a new app could get past the mode this way.
   - **An app made of several packages that share a Linux user is new when one of them is**, by the newest of their install times, so a package added since the switch makes it new (audit A-09). A rule about any of its packages decides for it ([ADR-0015](0015-firewall-rules.md)).
   - Turning the mode on again while it is on changes nothing. Turning it off and on again counts from the new time: apps installed in between, and used while it was off, are no longer new.
3. **Rules come first; the mode decides only where no rule matches** (`RuleSet::verdict`). A rule allowing the app as a whole lets a new app through. A rule blocking a destination still applies to it.
4. **The new app's first connection raises the CM-04 alert, saying it was blocked.** The evidence then carries `new_app_blocked`, and the alert offers "Let this app use the internet", which keeps a rule allowing the app. The alert says it only when the mode blocked the app: when a rule about a destination stopped a new app's first connection, allowing the app would change nothing, so the alert does not offer it. The alert stays Info, as CM-04 is: the user chose the mode, and the notification is there to say why a new app has no internet.
5. **A switch takes effect at the next connection.** The mode is held in memory next to the rules. Setting it writes one row and swaps the value the engine reads, so the next decision uses it, well within CM-08's second. Open connections are decided again too, as after any rule change ([ADR-0015](0015-firewall-rules.md)), though a switch cuts none in practice: an app installed after the switch has none open, and Watch only blocks nothing that was allowed.
6. **The mode lives in the encrypted history**, like the rules, and a wipe returns it to Watch only. A mode this version cannot read counts as Watch only, which blocks nothing on its own (NF-07, fail open).
7. **The main screen offers both modes**, each with one sentence on what it does, and works while monitoring is off.

## Verification

- `sentinel-detect`:
  - Watch only lets through what no rule blocks, whatever the install time;
  - Block new apps blocks an app installed at or after the switch, at every moment the engine asks, and lets through apps installed before and connections without an install time;
  - Block new apps blocks a connection without a known owner, unless a rule that names no app allows its destination; Watch only lets it through;
  - rules come before the mode: allowing an app lets it through except where a rule blocks, and a domain allow for a new app applies only once the name is known;
  - an app is "blocked as new" only when no rule is about the app as a whole;
  - the stored mode names and the `new_app_blocked` evidence are fixed by tests; the blocked new app's alert offers to allow it first.
- `sentinel-store`: the mode is Watch only until set, survives reopening, keeps when it was turned on if set again, and a wipe forgets it. A blocked first connection is reported as blocked.
- `sentinel-ffi`:
  - switching applies to the very next connection, measured well under a second;
  - the new app is blocked when it starts, at its server name and at its DNS lookup, and stored as blocked;
  - older apps and connections without an install time get through;
  - spyware made of two packages that share a Linux user is blocked by a rule about either package, is new when one package is, raises the new-app alert under the user's name, and gets through once one package is allowed; a connection without a known owner gets through Watch only, not Block new apps;
  - turning the mode on again keeps its time; allowing the app lets it through, removing the rule blocks it again, and Watch only lets it through;
  - the alert says the app was blocked and offers to allow it; a rule about a destination does not make it say so;
  - through the real packet engine, a new app's datagram never reaches the server, and its alert says it was blocked.
- On the Android 14 emulator (`FirewallModeTest`), with a second app (the probe, `apps/android/probe`) installed during the test:
  - with Block new apps turned on, Sentinel's own request still gets through. The probe, installed after the switch, has its connection stopped, stored as blocked, and its first connection raises the alert offering to allow it;
  - allowing it, as the alert's action does, lets its next connection through; removing that rule stops it again;
  - Watch only lets it through at once; turning Block new apps on again counts from then, so the probe gets through;
  - each switch returns in well under a second with the new mode in force.
- `AlertsTest` and `RtlTest` show the blocked new app's alert and its action, and the mode choice, in English and in Arabic right to left; `AlertTextTest` grades the new alert text.

## Consequences

- **This also tests CM-04's positive case on a device.** The probe is an app installed after the history began, so its first connection raises the "new app" alert ([ADR-0013](0013-first-seen.md) had left that to the core's tests).
- **Reinstalling an app makes it new again**, because Android gives it a new first install time. A rule allowing it is kept by package name, so an app the user allowed stays allowed.
- **A clock moved back** makes apps installed afterwards look older than the switch, so the mode lets them through. A clock moved forward does the opposite. Android sets the clock from the network, so this needs a deliberate change.
- **Within one monitoring run, an app's install time is read once.** An app uninstalled and installed again while monitoring runs keeps its first install time until monitoring restarts.
- **The probe is a test fixture only.** It is a separate Gradle module that ships nowhere; the device tests install it from the test APK's assets with `pm install`, and the CI and local test command runs the app module's tests only (`:app:connectedDebugAndroidTest`).
- **A switch can be undone** from the action journal ([ADR-0018](0018-action-journal.md)), which puts back the mode with the time Block new apps counted from.
- **Not yet:** Lockdown (only allow-listed apps), and the list of allowed apps on a settings screen.

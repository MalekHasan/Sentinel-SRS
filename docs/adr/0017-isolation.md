# ADR-0017: One-tap network isolation on Android

- Status: **Accepted** (Sprint 6; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS RA-03 for Android ("Network isolation: block all traffic except Sentinel updates, DNS and allow-listed apps"; reversible with one click; started by the user)

## Context

RA-03 is for the moment a user believes something on the phone is sending their data away and wants it to stop now, without hunting for the app. Isolation must therefore:
- cut what is already flowing, not only new connections;
- leave the phone usable for what the user trusts (Sentinel, and the apps they allowed);
- be easy to end;
- not end by itself on a restart: a phone that is being spied on should not reconnect because it rebooted.

The firewall already decides every connection with what it knows for sure, and decides open connections again when the rules or the mode change ([ADR-0015](0015-firewall-rules.md), [ADR-0016](0016-firewall-modes.md)).

"Allow-listed apps" needs a meaning on Android. The rules already have one: an app the user allowed as a whole has an allow rule with no destination. Allowing a new app from its alert, or from its detail screen, makes exactly that rule. Taking a block back removes the block rule instead of adding an allow (ADR-0015), so unblocking an app does not allow-list it.

## Decision

1. **Isolation is a switch above the rules and the mode.** While it is on, a connection or lookup is blocked unless it is:
   - DNS (port 53), so that the apps that keep the internet can still find their servers;
   - Sentinel itself, for its updates;
   - by an app that a rule allows as a whole.

   What isolation lets through is then decided by the rules and the mode as usual: an allowed app's blocked destinations stay blocked, and a blocked lookup still gets "no such name". Connections whose app is not known, and Android's shared system identities, are blocked.
2. **It takes effect at once, open connections included.** Turning it on signals the running engine like any rule change, and every open connection is decided again.
3. **It is kept in the encrypted history** (schema version 13, `isolation`): when it began, and Sentinel's own package. It survives a restart of monitoring and of the phone, until the user ends it. Isolating while isolated keeps when it began. A wipe ends it with the rest of the history.
4. **One tap each way, and impossible to miss.** While monitoring runs, the main screen offers "Isolate this phone" with one sentence on what it does. While isolated, a banner at the top of the main screen says since when, what still works, and has the button that ends it. Isolation works only while monitoring runs; the banner says so when monitoring is off.

## Verification

- `sentinel-detect`: isolation lets through DNS, Sentinel itself and an app allowed as a whole, and nothing else: not another app, an app allowed only some places, an app blocked as a whole, a shared system identity, or a connection whose app is unknown.
- `sentinel-store`: isolation is kept until turned off, keeps when it began if turned on again, survives reopening, and a wipe forgets it.
- `sentinel-ffi`:
  - isolated, another app is blocked, Sentinel itself and DNS are not, rules still apply to what gets through, and an app allowed as a whole gets through; isolation survives reopening the history and ends when asked;
  - through the real packet engine, isolating ends an app's open connection within a second; an allow rule lets it through, and removing the rule or ending isolation acts on the next connection.
- On the Android 14 emulator (`IsolationTest`), with the probe as the other app:
  - isolating takes under a second; Sentinel's own request and a DNS lookup still get through, the probe's connection does not, and the same holds after monitoring restarts;
  - allowing the probe lets it through, removing the rule stops it again, and ending isolation lets it through;
  - the main screen isolates with one tap, then shows the banner, which ends isolation with one tap;
  - `RtlTest` shows the banner in Arabic, right to left.

## Consequences

- **Isolation cannot outlast monitoring.** When the VPN is off, nothing is filtered. Android's "Always-on VPN" and "Block connections without VPN" settings would close that gap; Sentinel cannot set them, so the onboarding guide should explain them (AM-15).
- **Some of Android's own traffic stops.** System services, time sync, push notifications for non-allowed apps and app updates stop while isolated, as RA-03 intends. Sentinel's own notifications are local and keep working.
- **Traffic that never enters the tunnel is not isolated**: the moment Android takes to route apps into a new tunnel, and system traffic Android exempts from VPNs (SRS §2.2).
- **Sentinel updates mean Sentinel's own connections.** Until the signed feed (Sprint 7) exists, that is all of Sentinel's traffic through the tunnel.
- **Undo is the End button for now.** The action journal (SRS §9, next task) will record isolation like every other action.

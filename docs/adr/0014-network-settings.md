# ADR-0014: Network setting changes on Android

- Status: **Accepted** (Sprint 5; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS CM-07 on Android ("alert on changes to DNS servers, proxy settings, VPN state, hosts file and network profile; change detected within 5 s")

## Context

CM-07 lists five things to watch, written with Windows in mind. On a phone without root they mean different things:

| CM-07 item | On Android | What an app can see |
| --- | --- | --- |
| DNS servers | Each network has its own, given by the router or the carrier. Joining another network changes them, which is normal | `LinkProperties.getDnsServers()` of a network, with a callback on change |
| Private DNS (DNS over TLS) | One setting for the whole phone: off, automatic, or a named provider. A named provider sees every name the phone looks up | `LinkProperties.getPrivateDnsServerName()` gives the named provider on every network. "Off" and "automatic" look the same to an app |
| Proxy settings | A proxy for the whole phone (set with `adb`, by a device policy, or by an app that was given a system permission), or one set on a Wi-Fi network | `ConnectivityManager.getDefaultProxy()` (the whole phone's proxy, or else the one apps get from their network), `LinkProperties.getHttpProxy()` (the network's own), and Android's proxy-change broadcast |
| VPN state | Sentinel is the VPN. Another VPN app can take over, or the user can switch it off | `VpnService.onRevoke()`, which already records a monitoring gap and raises "monitoring stopped" (SP-03, [ADR-0012](0012-alerts.md)) |
| Hosts file | `/system/etc/hosts` is on the read-only system partition: changing it needs root | Readable, but nothing announces a change |
| Network profile | Windows' public or private network. Android has no such setting | — |

The attacks behind CM-07 are a DNS or proxy setting that sends the phone's traffic somewhere it can be watched or changed. Examples are stalkerware that sets a proxy through `adb`, a router whose DNS was taken over, and a Private DNS provider someone else named.

## Decision

1. **Three rules, each a Warning**, one per setting:
   - `dns-servers-changed`;
   - `private-dns-changed`;
   - `proxy-changed`.

   Each alert's evidence is the value before and after. Its action opens Android's network settings, where all three are changed back. They are Warnings, not High, because users change these settings themselves. They count as Sentinel's own alerts for the rate limit (ADR-0012), and each can be allowed on its own.
2. **The app reports, the core decides.** Whenever the network the phone would use without the VPN changes or its settings change, Kotlin reports a `NetworkState`, and also when Android announces a proxy change. A state holds that network's id, its DNS servers, the named Private DNS provider, the network's own proxy, and the proxy in effect. `sentinel-detect` compares it with the state before (`network_changes`), and the alerts go through the usual raising path.
3. **The last state is kept in the history** (schema version 10, `network_state`). A change made while Sentinel was not running is therefore found when it runs again. The first state a history sees raises nothing; after a wipe the history starts again.
4. **What counts as a change:**
   - **DNS servers** are compared only on the same network, and only when both states list servers. A network is the same while the phone stays on it. Its id is Android's network id with the boot count, because network ids start again after a restart. Joining a network again counts as another network.
   - **Private DNS** is a setting of the whole phone, so it is compared on any network: any change of the named provider counts, including naming one or removing it.
   - **The proxy in effect** is compared on the same network. Across networks it is compared only when neither network has its own proxy, because it is then the proxy set for the whole phone. Joining a Wi-Fi network that has its own proxy is not a change; editing that proxy while on the network is.
5. **VPN state is covered by monitoring gaps.** Another VPN taking over, or the user switching Sentinel's VPN off, already stops monitoring at once and raises "monitoring stopped". Always-on and lockdown settings are not watched, because Android announces no change to them.
6. **The hosts file and network profile are not watched on Android.** Without root, nothing but a system update can change the hosts file, and Android has no network profile. The root and integrity checks of later sprints are the place for a changed hosts file.
7. **Within 5 seconds.** Android calls the network callback and the proxy broadcast as soon as a setting changes, and the report is written and compared on a thread of its own at once.

## Verification

- `sentinel-detect`:
  - no change raises nothing, and reordered servers are no change;
  - DNS servers on the same network raise an alert; another network, or a network listing no servers yet, does not;
  - Private DNS is compared across networks, and so is a proxy for the whole phone;
  - a network's own proxy counts on that network only;
  - three changes at once raise three alerts;
  - the stored state, the evidence format and the rule ids are fixed by tests.
- `sentinel-store`: the last state survives reopening, and a wipe forgets it.
- `sentinel-ffi`:
  - the first state raises nothing, and an unchanged state raises nothing;
  - a proxy change raises one Warning alert offering the network settings, and once that rule is allowed it raises nothing more;
  - a Private DNS change made while the history was closed raises an alert when it next sees the network.
- On the Android 14 emulator (`NetworkSettingsTest`), with monitoring running:
  - setting a proxy for the whole phone (`settings put global http_proxy`) raises a Warning alert within 5 s, with no proxy before and the new one after;
  - naming a Private DNS provider does the same. Both settings are put back afterwards;
  - `AlertsTest` shows a proxy change and its action, and `RtlTest` shows a Private DNS change in Arabic, right to left;
  - `AlertTextTest` grades the new texts.

## Consequences

- **DNS server changes are tested in the core only.** The emulator's network cannot change its DNS servers while connected.
- **Some router attacks are missed.** If a router's DNS is changed, a phone usually gets the new servers when it joins again, which counts as another network. Without the network's name (which Android shows only to apps with location access) Sentinel cannot tell that it is the same Wi-Fi. A list of known-bad resolvers in the signed feed could cover this later.
- **Carrier changes.** A carrier that changes DNS servers during a connection raises a Warning. How often this happens is to be measured in the beta.
- **Private DNS "off" and "automatic" are not told apart**, so switching between them raises nothing. Only a named provider decides where every lookup goes.
- **Taking back a change is manual for now.** Restoring the last good settings (RA-09) needs the permission to write them, which apps do not have. The alert opens the settings instead. The stored state is the "last known good" RA-09 will need.

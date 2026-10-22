# ADR-0008: Android tunnel setup and DNS forwarding

- Status: **Accepted** (Sprint 1; implemented in `apps/android` and `crates/sentinel-vpn`)
- Date: 2026-10-14
- Implements: SRS CM-01, CM-02, NF-07, SP-03, §15.3. Builds on [ADR-0006](0006-android-packet-engine.md).
- ADR-0007 is reserved for the sensor spike ([SPIKE-3-SENSORS.md](../SPIKE-3-SENSORS.md)).

## Context

ADR-0006 chose the packet engine. Sprint 1 connects it to Android's `VpnService`. Several choices there decide whether the phone stays online, what Sentinel can see, and how a stop is reported:

1. Which DNS servers the tunnel gives to apps.
2. Whether Sentinel's own app is inside its tunnel.
3. Which address families are routed.
4. How the service runs and how stops are recorded.

## Decisions

### 1. DNS goes to a resolver address inside the tunnel, and the engine forwards it

The tunnel advertises one resolver, `10.215.173.53`. The engine (`DnsForward`) sends queries for that address to the current network's real resolvers. The app reads those from the best network that is not a VPN, and updates the engine whenever they change.

Rejected alternative: advertise the real network's resolvers directly. A VPN's DNS servers are fixed when the tunnel is built. After a switch from Wi-Fi (resolver `192.168.1.1`) to mobile data, every lookup would go to an address that no longer answers, and the phone would look offline until the tunnel was rebuilt.

Consequences:

- DNS keeps working across network changes without rebuilding the tunnel.
- Every lookup passes through the engine, which uses the answers to name later connections (CM-02). Only this resolver's answers name connections (audit A-05): an app that asks a server of its own choosing could have it answer anything, and so rename every other app's traffic. Its lookups are still watched (ID-13, DL-05). When the name cache is full, it drops the names closest to expiring, never all of them.
- Other ports at the resolver address are refused at once. Android's opportunistic DNS-over-TLS probe to port 853 fails immediately and falls back, instead of waiting for a connect timeout.
- **With Private DNS on "automatic", lookups go unencrypted while Sentinel runs** (audit A-52). Without Sentinel, Android would use DNS-over-TLS with the network's resolvers where they offer it. Through the tunnel its probe to port 853 is refused, so it sends plain DNS, which the engine forwards in plain DNS to the network's resolvers. On such networks, the network sees the names looked up while Sentinel runs, as it would with Private DNS off. Forwarding over TLS where the resolver offers it is not built. A user who wants encrypted lookups names a provider, as below.
- With Private DNS set to a named provider, Android sends DNS-over-TLS through the tunnel to that provider. Sentinel then sees the provider's name (SNI) but not the questions. That is the user's choice, and it is shown as such in a later sprint.
- Only the first resolver is used. If it stops answering, lookups fail until the network reports a change. Failover is Sprint 9 work.

### 2. Sentinel's own app stays inside the tunnel

Sentinel does not exclude itself with `addDisallowedApplication`. Its own connections, such as feed downloads, appear in its own connection list like any other app's. A user can check there that Sentinel sends nothing anywhere else ("no telemetry", SRS §2.5).

The engine's upstream sockets are protected with `VpnService.protect()`, so they never loop back into the tunnel.

Consequence: Sentinel's default network is its own VPN. To find the real resolvers it asks for the best network with `NET_CAPABILITY_NOT_VPN` (`registerBestMatchingNetworkCallback` on Android 12+). On Android 10 and 11 it watches every such network and prefers one that is not mobile data, as Android does.

### 3. IPv4 and IPv6 are both routed into the tunnel

The tunnel routes `0.0.0.0/0` and `::/0`, with addresses `10.215.173.1/32` and `fd00:5e17:173::1/128` (a unique local address).

- If IPv6 were not routed, Android would block it for every app while the VPN is up. Leaving IPv6 out of the tunnel is not an option either: monitoring would miss it.
- On a network without IPv6, an app's IPv6 connection is accepted by the engine and then reset when the upstream connect fails. Apps that try IPv6 first fall back to IPv4. Android's address selection prefers IPv4 here anyway: the tunnel's IPv6 address is a unique local address, and its RFC 6724 label does not match global destinations, while IPv4 source and destination labels do.
- The `10.215.173.0/24` range was picked to make clashes with home and office networks unlikely. A real host at `10.215.173.53` would be unreachable while monitoring.

### 4. A visible foreground service that records every stop it did not ask for

- `SentinelVpnService` runs in the foreground with a notification that stays as long as the tunnel does (SRS §15.3), with a Stop action. On Android 14+ its type is `systemExempted`, which Android allows for VPN apps (see [PLAY-POLICY.md](../PLAY-POLICY.md)).
- The service is not exported. Only Android, which holds `BIND_VPN_SERVICE`, can bind it, and only Sentinel can start or stop it.
- Android routes traffic outside the tunnel whenever the engine is gone, so the phone stays online (fail-open, NF-07). Every stop the user did not ask for is recorded as a gap with its reason (SP-03):
  - the engine stopped (the tunnel failed);
  - the VPN was revoked (switched off in Settings, or another VPN app took over);
  - Android did not open the tunnel;
  - the process ended while monitoring was on. On Android 11+ the time and reason come from `ApplicationExitInfo`.
- A gap closes when monitoring starts again. Until the encrypted store exists (Sprint 2), gaps live in a small private file.
- **The engine stops on a thread of its own** (audit A-44). Before it stops, it writes its last batch and ends the flows still open. That may wait on a busy history, and an engine that stopped answering may not stop at all. Waiting for it on the main thread froze every screen meanwhile, and could freeze them for good when the heartbeat replaced a silent engine. Monitoring reads as off once the engine has stopped, unless a newer engine started meanwhile.
- **A stop ends only itself** (audit A-53). It ends the service only if no start came after it (`stopSelf(startId)`). Before, a start sent right after a stop was ended with it. If the start had not yet put the service in the foreground, Android ended the app (`ForegroundServiceDidNotStartInTimeException`). Every start sent with `startForegroundService` puts the service in the foreground, also when monitoring already runs.

## Verification

- Rust: `DnsForward` unit tests, and a socket-pair test in which DNS follows a resolver change and port 853 is refused.
- Android: `MonitoringTest` on an Android 14 emulator in CI (passing since commit 4e2b551; CI lists each device test and its result). It starts the VPN with the consent app op, sends TCP through the engine to a server on the CI host, sends DNS through the tunnel resolver to the emulator's real resolver, checks the notification, and stops without recording a gap. `GapLogTest` covers the gap file.
- Android: `MonitoringTest` sends a start right after a stop, without waiting, and monitoring still runs three seconds later (A-53). Every device test that stops monitoring waits for it to read as off, so each one also checks that the engine stopped off the main thread has written its last flows (A-44).
- Not yet covered by a test: the revoke path (another VPN taking over) and the process-exit path (`ApplicationExitInfo`). Both need a device-level harness; planned with the Sprint 9 hardening.

## Still open

- Rebuild the tunnel when the network changes, if phone tests show it is needed (for example, MTU changes).
- Multicast and local discovery (casting, printers) inside the tunnel: check on phones; exclude routes on Android 13+ if needed.
- Resolver failover (Sprint 9).

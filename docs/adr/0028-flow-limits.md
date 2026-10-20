# ADR-0028: Limits on open flows, in total and per app

- Status: **Accepted** (Sprint 9; `crates/sentinel-vpn`, `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: THREAT-MODEL-A D2 ("An app opens thousands of flows … to exhaust memory"), whose other mitigations were already in place: a bounded DNS cache, idle timeouts, fixed TCP buffers with flow control, and bounded UDP queues.

## Context

Every flow the engine relays costs memory and a socket.
- A TCP flow holds two 32 KiB smoltcp buffers and two 16 KiB relay buffers: about 96 KiB ([ADR-0006](0006-android-packet-engine.md)).
- It holds one upstream file descriptor.
- It holds a row in the history.

Nothing bounded how many flows an app could open. An app opening ten thousand connections could make the engine use a gigabyte. Android would then kill Sentinel, and the tunnel with it, so traffic flows unmonitored (NF-07). It could also fill the history with rows.

A phone normally has a few hundred flows open; browsers limit themselves to about 256 connections. SRS CM-03 requires the live view to work with 500 concurrent flows, and its device test opens all 500 from one app.

## Decision

1. **The engine refuses flows beyond `EngineConfig::max_flows`**, 1024 by default, TCP and UDP together. That bounds the engine's flow memory near 100 MB in the worst case.
   - A refused flow is turned away before it is a flow. No observer call, no history row, no upstream socket.
   - A TCP connection is reset, and a UDP datagram is dropped.
   - Each refusal counts in `EngineStats::flows_refused`, shown in the engine snapshot.
   - The check is in the relays, so both stacks (smoltcp and ipstack) have it.
2. **Each app may have 512 flows open** (`MAX_FLOWS_PER_APP`). That is half the engine's limit, so one app cannot take every slot, and above the 500 the CM-03 test opens.
   - Android's flow observer knows each flow's app, and counts each app's open flows.
   - A flow beyond the per-app limit is blocked, and neither its start nor its end is recorded, so an app flooding the network cannot flood the history.
   - Flows of no known app count only towards the engine's limit.
3. **The first refusal in a monitoring run raises a Warning about the app** (`flow-limit`). Its evidence is the app and the limit. It offers to block the app or look at what it did.
   - A busy app can do this, and so can one that floods the network. The text says both.
   - Like other alerts about an app, it is raised again only once its earlier alert is put away.
4. **Open flows are never ended** to make room. Existing connections keep working; only new ones wait for a slot.

## Verification

- `sentinel-vpn` (socketpair test): with `max_flows` 2, two UDP flows are relayed and a third is refused. The refusal is counted, no observer hears of it, and the open flows go on.
- `sentinel-detect`: the alert is a Warning about the app, offers to block it and to look at it, and its stored JSON is fixed.
- `sentinel-ffi`:
  - an app may open 512 flows, and the next two are blocked and not recorded;
  - one Warning names the app and the limit;
  - a flow of no known app is not counted;
  - when one flow ends, another may open, and no second alert comes in that run.
- `RtlTest` shows the alert in Arabic, right to left.

## Consequences

- **An app that legitimately needs more than 512 connections at once** will see some fail while it is over the limit. Download managers with many parallel segments and some peer-to-peer apps can. The alert says which app it was; the limit is not yet configurable.
- **The engine's limit applies to all apps together.** Two apps at their limit, or many busy apps, could reach 1024 and have new connections refused without an alert. The snapshot counts them.
- **Memory per flow is an estimate.** The real figures belong to the performance work on the reference phones (Sprint 9, NF-03), which may tune both limits.

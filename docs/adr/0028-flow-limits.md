# ADR-0028: Limits on open flows, in total and per app

- Status: **Accepted** (Sprint 9; `crates/sentinel-vpn`, `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: THREAT-MODEL-A D2 ("An app opens thousands of flows … to exhaust memory"), whose other mitigations were already in place: a bounded DNS cache, idle timeouts, fixed TCP buffers with flow control, and bounded UDP queues.
- Amended 2026-10-22 for audit findings A-04 and A-18 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decision 5, and the memory per flow.
- Amended 2026-10-22 for audit finding A-13: a full UDP queue drops the datagram.

## Context

Every flow the engine relays costs memory and a socket.
- A TCP flow holds, in the stack, two 32 KiB smoltcp buffers and two 32 KiB buffers between smoltcp and the relay, and in the relay two 16 KiB copy buffers and a 16 KiB ClientHello buffer: about 176 KiB allocated ([ADR-0006](0006-android-packet-engine.md)). Pages never written are not resident: the lab measures about 100 KB per open connection. This ADR first said 96 KiB, counting only the smoltcp and copy buffers (audit A-18).
- It holds one upstream file descriptor.
- It holds a row in the history.

Nothing bounded how many flows an app could open. An app opening ten thousand connections could make the engine use a gigabyte. Android would then kill Sentinel, and the tunnel with it, so traffic flows unmonitored (NF-07). It could also fill the history with rows.

A phone normally has a few hundred flows open; browsers limit themselves to about 256 connections. SRS CM-03 requires the live view to work with 500 concurrent flows, and its device test opens all 500 from one app.

## Decision

1. **The engine refuses flows beyond `EngineConfig::max_flows`**, 1024 by default, TCP and UDP together. With decision 5, that bounds the engine's flow memory near 180 MB in the worst case: 1024 TCP sockets in the stack, and a relay for each that is still open.
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
5. **The stack's TCP sockets are bounded too** (audit A-04, A-18; patch 3 to `netstack-smoltcp`):
   - **At most `max_flows` sockets**, those still closing after their flow ended included. A connection beyond them is reset before it is a flow, and counted in `flows_refused`. A SYN sent again makes no second socket.
   - **Refused, blocked or failed connections are reset**, not closed: a close waits for the app to acknowledge the engine's FIN, and an app need never do so. A flow that ends cleanly still closes with a FIN.
   - **A socket has `tcp_linger`, 60 s, to close** once its flow ended. Then it is reset. Linux gives orphaned sockets about as long (`tcp_fin_timeout`).
   - **A TCP flow with no byte either way for `tcp_idle_timeout`, 2 hours, is reset.** On smoltcp nothing else ended a connection that both sides keep open; only ipstack had this. Push connections send heartbeats far more often.

**A full UDP queue drops the datagram** (audit finding A-13). Each UDP flow takes the app's datagrams through a queue of 256. When a flow does not keep up, as while it is still being decided, a datagram that finds its queue full is dropped, as a full network queue would drop it. Before, it started a second flow to the same place, which reached the server from a new source port that many protocols do not survive, and was decided and stored again. A datagram whose flow has ended still starts a new one.

## Verification

- `sentinel-vpn` (socketpair test): with `max_flows` 2, two UDP flows are relayed and a third is refused. The refusal is counted, no observer hears of it, and the open flows go on.
- `sentinel-vpn` (socketpair test): 600 datagrams sent while the flow takes 500 ms to be decided make one flow, not two.
- `sentinel-vpn` (socketpair tests over TCP, an app's side written packet by packet): a blocked connection is reset and never closed; an app that never acknowledges the FIN is reset after `tcp_linger`; with `max_flows` 1, a second connection is reset and counted while the first still closes, and a third opens once it is freed; a SYN sent twice makes one flow; an idle connection is reset after `tcp_idle_timeout`. Each test fails with its part of the fix taken out. The lab's checks (throughput, backpressure, half-close, server close, SNI and DNS) still pass.
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
- **Memory per flow is measured on a Linux host only.** The real figures belong to the performance work on the reference phones (Sprint 9, NF-03), which may tune both limits.
- **Sockets still closing take slots.** A connection closed normally waits up to 10 s in TIME-WAIT, and one whose app does not answer up to `tcp_linger`. At a few new connections a second, that is tens of sockets; an app that abandons connections on purpose holds at most `max_flows` of them for 60 s, and its new connections are refused meanwhile, like everyone's.
- **An idle timeout frees forgotten connections only.** An app that sends a byte now and then keeps its connections; the per-app limit is what bounds it.

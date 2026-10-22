# ADR-0029: The engine's heartbeat on Android

- Status: **Accepted** (Sprint 9; `crates/sentinel-vpn`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements SP-03 on Android: "each collector reports every 10 s; a missing heartbeat is logged as a monitoring gap and alerted". Builds on the gap log of Sprint 1 (NF-07) and the gap alert of Sprint 5 ([ADR-0012](0012-alerts.md)).
- Amended 2026-10-22 for audit finding A-14 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decision 1, the report passes through the loop that takes new connections, and batches are written apart from it.

## Context

Sentinel already records a gap whenever monitoring stops while the user wants it on:
- the engine ends with an error;
- the VPN is revoked or taken over;
- the tunnel does not open;
- the process dies. For this one, the next start reads Android's record of the exit (`ApplicationExitInfo`).

Each gap raises a Warning.

Two cases were not covered:

1. **An engine that hangs without ending.** For example, both of the engine's worker threads could be stuck in a call to Android that never returns, such as looking up a connection's owner. The tunnel stays up and Android keeps sending traffic into it, but nothing is relayed or recorded, and no gap is logged. This is the one way the network fails closed instead of open (NF-07): the phone is cut off.
2. **A process that dies without a record.** Android does not always record an exit. The last record may then be an earlier exit, so the gap seems to start before monitoring did, or it starts at "an unknown time".

On Android the collector that matters is the packet engine: the other watchers are Android callbacks into the same process.

## Decision

1. **The engine reports every 10 s** (`EngineConfig::heartbeat`).
   - Its heartbeat is a task on the engine's runtime, beside the flows, in both stacks (smoltcp and ipstack). It runs only while the runtime can run tasks.
   - On smoltcp, the default stack, a report counts only once the loop that takes new TCP connections has received it (audit A-14). That loop runs on the engine's own thread, not a worker: had it been held up, new connections would go unrelayed while the heartbeat beat on. Now either a stuck worker or a held-up loop stops the reports.
   - **Writing batches to the history, and handing them to the app, runs as a task of its own on a worker thread**, no longer on the engine's own thread beside that loop (audit A-14). A batch waiting on a history held by a long export, retention pass or hunt, or on a slow app, held up every new TCP connection for that long. When the engine stops, the last batch is written before the flows still open are written as ended.
   - **Asking Android who owns a new flow lets the engine's other tasks move to another thread while it waits** (`block_in_place`, audit A-52). The question is a binder call, which waits while the system is busy. The engine has two workers, so two slow answers held up every flow, the reading of the tunnel included. Now a slow answer holds up its own flow only.
   - `EngineStats::since_heartbeat` says how long ago it last reported. The snapshot carries this as `heartbeat_age_ms`.
   - It is measured on the monotonic clock, which stands still while the phone sleeps. A phone asleep is not an engine gone silent.
2. **The service checks every 10 s while monitoring runs.**
   - The check runs on a `Handler`, whose time also stands still in sleep, so it never wakes the phone.
   - **Silent for 30 s** (three reports missed): a gap opens from the engine's last report, with the reason "The monitoring engine stopped answering", and raises the usual Warning.
   - **The service then replaces the engine**, so that the phone is not left cut off (NF-07). The service stays in the foreground meanwhile, as Android may not let it return from the background. The gap closes when the new engine runs.
3. **Each report heard is written down**, as the time it was made, in a small file beside the history.
   - It is not synced to storage. The kernel keeps the write when the process dies, which is all it is for, and a sync every 10 s would cost battery (NF-03).
   - Wiping the history deletes it.
4. **After the process dies, the gap begins:**
   - when Android recorded the exit, if it did; or
   - when the engine was last heard from, if there is no record, or the record is older than the last report (so it is an earlier exit's).
5. **Gaps are shown with how long they lasted**, in the user's language, under a line saying that Sentinel did not see the phone's traffic at these times.

## Verification

- `sentinel-vpn` (socketpair test): with a 100 ms heartbeat, the engine has reported within 500 ms after 1.5 s. Once it stops, the time since its last report grows. Without the heartbeat task the test fails.
- `sentinel-ffi`: the snapshot of a running engine reports a recent heartbeat.
- `sentinel-ffi` (`slow_owners_do_not_hold_up_other_flows`): while Android takes 4 s to name the owners of two flows, one for each worker, a third flow through the real engine is echoed within 2 s. Before the change it waited for them.
- `sentinel-ffi` (`a_slow_batch_does_not_hold_up_new_connections`): while the app takes 4 s over a batch, a new TCP connection through the real engine is relayed and echoed at once. Before the change it waited for the batch.
- On the Android 14 emulator:
  - `MonitoringTest`: while monitoring runs, the engine reported within 10 s and the service has written down a report made since the start.
  - `GapLogTest`:
    - each report heard is written down;
    - an engine silent for 30 s opens a gap from its last report, with one alert;
    - the written-down report goes with the history.
  - `GapLogTest`: the start of a gap after death is the exit Android recorded, else the last report, also when the record is an earlier exit's.
  - `RtlTest`: a gap with its length, and the line saying what a gap means, read right to left in Arabic.

Nothing can make the engine hang on demand, so replacing a silent engine is not tested on a device. It uses the same stop and start as the user's Stop and Start, which are tested.

## Consequences

- **A hang is caught only if it stops the runtime.** A single flow stuck forever is not a silent engine, and other flows go on. A deadlock that leaves the heartbeat task free to run is not caught.
- **An owner question that never returns keeps its thread.** Each such flow then holds one more thread, until the runtime can start no more (tokio's limit is 512); the engine then stops answering, and is replaced as above.
- **The gap's start counts only time awake.** If the engine stopped answering just before the phone slept, the gap seems to begin after that sleep.
- **Replacing a silent engine ends every open connection**, as apps' connections went through it. Apps reconnect.
- **An engine that keeps hanging is replaced every 30 s or so**, each time with a gap. The gap alerts follow the usual limits (AL-03).
- **Replacing a silent engine may wait.** It stops the old engine first, which gives stuck worker threads up to 2 s. If the engine's own thread is stuck too, the stop waits for it, and Android may report Sentinel as not responding. The same is true of the user's Stop.
- **The other watchers have no heartbeat of their own.** They are Android callbacks on the main thread: if it hangs, the service's checks hang with it, and Android reports the app as not responding.
- **The written-down report is lost** if the phone loses power before the kernel writes it out. The gap then begins at the exit Android recorded, or at an unknown time.

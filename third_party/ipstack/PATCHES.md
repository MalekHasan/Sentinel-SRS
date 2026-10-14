# Sentinel patches to ipstack 1.0.1

Upstream: https://github.com/narrowlink/ipstack, version 1.0.1, Apache-2.0 (see LICENSE).
Vendored for the A0 packet-engine spike; see `docs/adr/0006-android-packet-engine.md`.

## Patch 1: wake the reader when a connection closes

`src/stream/tcp.rs`, stream task loop, `exit_monitor` branch.

When the app closes a connection, ipstack completes the close (LAST_ACK, then Closed) and
its stream task exits through the `exit_monitor` branch. That branch did not wake the
stream's pending reader. A relay blocked in `read()` therefore never saw end-of-stream
and kept the upstream connection open until the idle timeout (2 hours in Sentinel).

Fix: wake `read_notify` and `write_notify` before leaving the loop, as the existing
"pipe broken" exit path already does. `poll_read` then sees `Closed` and returns EOF.

Found by `crates/sentinel-vpn/lab/run-lab.sh` (657 of 660 flows stayed "active").
Should be offered upstream.

## Patch 2: TCP half-close

`src/stream/tcp.rs` and `src/stream/tcb.rs`.

Before: when the app sent FIN, ipstack immediately sent its own FIN and closed both
directions (or forced it 5 s later if data was in flight). The reader never saw
end-of-stream. An app that half-closed and waited for the reply lost the reply.

Now:

- **App's FIN in Established:** data carried with the FIN (or sent just before it) is
  delivered first; the FIN is accepted only in order. The state moves to CloseWait,
  and the reader sees end-of-stream once the data is drained (`poll_read` returns 0
  bytes in CloseWait, LastAck, TimeWait or Closed).
- **Our FIN:** sent only when the relay shuts down its side (`poll_shutdown`), from
  Established (to FinWait1) or CloseWait (to LastAck).
- **Close requested while data is in flight:** remembered in the TCB (`fin_wanted`);
  the packet task sends the FIN as soon as the in-flight data is acknowledged.
  Previously the FIN could be lost, because nothing polled `poll_shutdown` again.
- The 5 s "force FIN in CloseWait" task is removed; `task_last_ack` moved to module
  level so `poll_shutdown` can start it.

Checked by the lab's `half_close_ok` check (now gating) on both stacks, together with
all other lab checks (flows end, SNI, DNS, blocking).

## Known, not patched

- **Unbounded internal channels.** Received data is acknowledged as soon as it is
  queued for the reader, so a fast app can make memory grow without limit when the
  upstream is slower. Under investigation (ADR-0006).

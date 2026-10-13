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

## Known, not patched

- **No TCP half-close.** When the app sends FIN, ipstack immediately sends its own FIN
  and closes both directions. An app that half-closes and then waits for the server's
  reply loses that reply.
- **Unbounded internal channels.** A fast sender can make memory grow without limit.

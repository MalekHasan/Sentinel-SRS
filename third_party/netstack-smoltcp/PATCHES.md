# Sentinel patches to netstack-smoltcp 0.2.4

Upstream: https://github.com/cavivie/netstack-smoltcp, version 0.2.4, MIT OR Apache-2.0
(see LICENSE-MIT and LICENSE-APACHE). Vendored for the packet engine; see
`docs/adr/0006-android-packet-engine.md`.

## Patch 1: no polling while idle

`src/tcp.rs`, end of the runner loop.

When smoltcp had no timer pending (`poll_delay` returned `None`), the runner still woke
every 5 ms: about 1,750 wake-ups in 10 s on an idle engine, which drains a phone's battery
all day. Every event that needs a poll already notifies the runner (incoming packets,
and reads, writes, shutdowns and drops on a `TcpStream`), so with no timer pending the
runner now waits for a notification only. Timers smoltcp does report (retransmission,
delayed ACK, keep-alive, TIME-WAIT) are still honoured.

Checked by the lab's idle measurement and its correctness checks.

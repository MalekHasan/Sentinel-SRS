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

## Patch 2: a shutdown is done once the FIN is queued

`src/tcp.rs`: `TcpStream::poll_shutdown`, and the runner's write-half close.

`poll_shutdown` stayed pending until the whole connection was `Closed`. When the
server closed first, the relay shut down its side towards the app, the app read to the
end and closed too, and smoltcp then held the socket in TIME-WAIT for 10 s
(`CLOSE_DELAY`). The relay waited all that time in `shutdown()`, so every such
connection (HTTP/1.0, many API calls) was reported as open 10 s too long, and the
firewall decided it again if a rule changed meanwhile.

Fix: the write half is shut down once the runner has called `socket.close()`, that is
once the FIN is queued behind all sent data (`Closing`), and the runner wakes the
pending shutdown at that moment. smoltcp still sends the data and the FIN, retransmits
them and finishes TIME-WAIT after the stream is dropped, because the socket stays in
the set until it is `Closed`.

Found by the Android device tests (a probe app's answered connections ended only when
monitoring stopped) and reproduced in the lab: with the server closing first, five of
five flows ended after 10 002 ms before the fix. Checked by the lab's
`server_close_ok` check (gating).

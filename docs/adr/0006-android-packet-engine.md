# ADR-0006: Android packet engine

- Status: **Accepted for Sprint 1**, with phone measurements still required (see "Still open")
- Date: 2026-10-13
- A0 Spike 1. Implements the base for SRS CM-01, CM-02, NF-03, NF-04, NF-07

## Context

On Android, Sentinel sees traffic through `VpnService`: the system hands us a TUN file descriptor carrying every app's IP packets. To keep the phone online we must terminate each TCP and UDP flow in our own process and relay it to the real destination over a *protected* socket. The engine runs all the time, so it decides battery use (NF-03 ≤ 3% per day) and added latency (NF-04 ≤ 5 ms p95).

The A0 plan asked: can a Rust userspace TCP/IP stack do this well enough, or should we fall back to a proven GPLv3 C engine (NetGuard, PCAPdroid)?

## What we built

`crates/sentinel-vpn`: a stack-agnostic relay layer with two interchangeable stacks.

| Part | What it does |
| --- | --- |
| `TunDevice` | The TUN descriptor as an async packet device (one read or write per packet). |
| Relays | Per flow: ask the `Observer` (block or allow), connect a protected upstream socket, copy both ways, count bytes. |
| `Protect` | `VpnService.protect()` on Android; a socket mark plus policy routing in the lab. |
| Metadata | Hostname from DNS answers (cache) or from the TLS ClientHello (SNI), including ClientHellos split across two segments. Payloads are never stored. |
| Blocking | Before any upstream connection (by app or address), or by server name before the ClientHello is forwarded. |
| Stacks | `ipstack` 1.0.1 (default) and `netstack-smoltcp` 0.2.4 on smoltcp (`--features smoltcp`). |

The lab (`crates/sentinel-vpn/lab/`, run in CI) builds two network namespaces on Linux and runs real traffic through the engine, with the same TUN-and-protect mechanics as Android. Each benchmark runs once over direct routing and once through the engine.

## Results on the host

Cloud x86-64 VM, 4 vCPU, Linux 6.18, release build, 2 worker threads. These numbers show the engine's own overhead. Phones have slower cores, and their radio latency is far larger than anything below.

### Latency (p95, added by the engine)

| Measure | ipstack | smoltcp |
| --- | --- | --- |
| New TCP connection until first byte echoed | +0.13 ms | +0.88 ms |
| TCP round trip on an open connection | +0.08 ms | +0.08 ms |
| UDP round trip | +0.06 ms | +0.04 ms |
| DNS lookup | +0.24 ms | +0.20 ms |
| Server-first protocol (SSH-like banner) | +0.33 ms | +1.14 ms |

Both are far below NF-04's 5 ms on this machine.

### Throughput and CPU (iperf3, one flow, 5 s)

| | ipstack | smoltcp |
| --- | --- | --- |
| Upload (app to internet) | 0.58 Gbit/s, 3.3 core-s per Gbit | 3.5 Gbit/s, 0.36 core-s per Gbit |
| Download (internet to app) | 1.44 Gbit/s, 0.71 core-s per Gbit | 0.71 Gbit/s, 1.8 core-s per Gbit |

### What matters most on a phone: idle cost and memory

| | ipstack | smoltcp |
| --- | --- | --- |
| Wake-ups in 10 s with no traffic | **6** | **1,759** (a 5 ms polling timer) |
| Memory with 500 open connections (CM-03) | 37 MB, about 22 KB per connection | 79 MB, about 121 KB per connection |
| Larger TCP buffers (256 KiB) | No faster; peak memory rose to 158 MB | 64 KiB buffers: still about 109 KB per connection |

### Correctness (all checks run in CI)

| Check | ipstack (patched) | smoltcp |
| --- | --- | --- |
| Hostname from SNI, ClientHello split over 2 segments | ✓ | ✓ |
| Block by server name before the ClientHello is forwarded | ✓ | ✓ |
| Hostname from an earlier DNS answer | ✓ | ✓ |
| Flows end when the app closes them | ✓ only with our patch | ✓ |
| TCP half-close (app shuts its sending side, then reads the reply) | ✗ reply lost | ✓ |

## Findings

1. **ipstack 1.0.1 never ended flows closed by the app.** Its stream task exits without waking the reader, so every relay waited for the 2-hour idle timeout: 657 of 660 lab flows stayed open. Fixed with a two-line patch in a vendored copy (`third_party/ipstack/PATCHES.md`). We should offer the fix upstream.
2. **ipstack does not support TCP half-close.** When the app sends FIN, ipstack closes both directions. Few phone apps half-close (HTTP/1.1, HTTP/2 and TLS do not), but the ones that do lose the server's reply.
3. **ipstack's upload path is CPU-heavy** (about 4.7 times the per-byte cost of download), and its internal channels are unbounded.
4. **netstack-smoltcp wakes every 5 ms even when idle** (its runner falls back to a 5 ms timer), and smoltcp allocates each connection's buffers up front. On a phone, the first costs battery all day and the second costs memory.
5. **ipstack's default idle timeout (60 s) is too short for phones.** Push-notification connections stay idle for minutes, so we use 2 hours.
6. DNS flows are one question and one answer. We end them after 5 s idle instead of holding a socket for 2 minutes; phones make hundreds of lookups a minute.
7. Both stacks complete the TCP handshake with the app before the upstream connection exists. If the upstream connect fails, the app sees a reset rather than a refused connection.

## Decision

1. **Use a Rust userspace engine.** The spike shows it is viable: sub-millisecond overhead on the host, and all metadata and blocking behaviour works. The GPL C engines stay as a fallback if phone measurements fail.
2. **Start Phase A on ipstack, vendored and patched.** Phones are idle most of the day, so idle wake-ups and memory per connection outweigh peak throughput, and ipstack wins both clearly.
3. **Keep the relay layer stack-agnostic.** The smoltcp backend stays in the tree behind a feature flag, so the comparison can be re-run whenever either stack changes.
4. **Fix ipstack's gaps in Phase A:**

   | Gap | When |
   | --- | --- |
   | Half-close | Sprint 1 |
   | Bounded channels | Sprint 9 |
   | Profile the upload path | Sprint 9 |

   Fixes are offered upstream. If upstream does not take them, the vendored copy is maintained, or we move to smoltcp with a patched runner.

## Still open: phone measurements

The host cannot answer NF-03 (battery) or NF-04 (latency on a real radio). In Sprint 1, once the Android app can start the tunnel (Spike 2), measure on at least one mid-range phone:

- added latency p95 for DNS and new HTTPS connections, on Wi-Fi and mobile data (NF-04 ≤ 5 ms);
- battery drain over 24 hours of normal use, with and without the tunnel (NF-03 ≤ 3%);
- throughput on a fast Wi-Fi link, upload and download, to see whether ipstack's upload CPU cost is a real limit;
- memory with a browser and 10 to 20 typical apps open.

If the battery or latency target fails and profiling cannot fix it in one sprint, re-run this decision with the C engine as the third candidate.

## Reproduce

```sh
sudo STACK=ipstack crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-ipstack
sudo STACK=smoltcp crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-smoltcp
```

Needs Linux, root, `iproute2`, `iperf3` and `python3`. CI runs the ipstack lab on every push.

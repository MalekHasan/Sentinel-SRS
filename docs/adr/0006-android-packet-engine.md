# ADR-0006: Android packet engine

- Status: **Accepted, revised in Sprint 1.** A0 chose ipstack; Sprint 1 found it has no backpressure and moved the default to smoltcp (see "Sprint 1 revision"). Phone measurements are still required (see "Still open").
- Date: 2026-10-13, revised 2026-10-14
- A0 Spike 1. Implements the base for SRS CM-01, CM-02, NF-03, NF-04, NF-07

## Context

On Android, Sentinel sees traffic through `VpnService`: the system hands us a TUN file descriptor carrying every app's IP packets. To keep the phone online we must terminate each TCP and UDP flow in our own process and relay it to the real destination over a *protected* socket. The engine runs all the time, so it decides battery use (NF-03 ≤ 3% per day) and added latency (NF-04 ≤ 5 ms p95).

The A0 plan asked: can a Rust userspace TCP/IP stack do this well enough, or should we fall back to a proven GPLv3 C engine (NetGuard, PCAPdroid)?

## What we built

`crates/sentinel-vpn`: a stack-agnostic relay layer with two interchangeable stacks.

| Part | What it does |
| --- | --- |
| `TunDevice` | The TUN descriptor as an async packet device (one read or write per packet). Reports when the tunnel closes. |
| Relays | Per flow: ask the `Observer` (block or allow), connect a protected upstream socket, copy both ways, count bytes. |
| `Protect` | `VpnService.protect()` on Android; a socket mark plus policy routing in the lab. |
| Metadata | Hostname from DNS answers (cache) or from the TLS ClientHello (SNI), including ClientHellos split across two segments. Payloads are never stored. A name from DNS is kept in DNS presentation format: any byte but a letter, a digit, `-` and `_` is written `\DDD`, so a name holds no line break, comma or direction mark, and a dot inside a label does not make two labels (audit A-31). A server name from TLS is refused unless it is a host name. |
| Blocking | Before any upstream connection (by app or address), or by server name before the ClientHello is forwarded. |
| Stacks | `netstack-smoltcp` 0.2.4 on smoltcp 0.12 (default since Sprint 1) and `ipstack` 1.0.1 (`--features ipstack`). Both vendored and patched in `third_party/`. |
| DNS forwarding | Queries to the tunnel's own resolver address go to the current network's resolvers (Sprint 1, [ADR-0008](0008-android-tunnel-setup.md)). |

The lab (`crates/sentinel-vpn/lab/`, run in CI) builds two network namespaces on Linux and runs real traffic through the engine, with the same TUN-and-protect mechanics as Android. Each benchmark runs once over direct routing and once through the engine.

## A0 results on the host

Cloud x86-64 VM, 4 vCPU, Linux 6.18, release build, 2 worker threads. These numbers show the engine's own overhead. Phones have slower cores, and their radio latency is far larger than anything below. The smoltcp column is **before** our patch and with smoltcp's default buffers; see "Sprint 1 revision" for the current numbers.

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

### Idle cost and memory

| | ipstack | smoltcp (unpatched) |
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
| TCP half-close (app shuts its sending side, then reads the reply) | ✗ reply lost; ✓ after patch 2 (Sprint 1) | ✓ |

## Findings

1. **ipstack 1.0.1 never ended flows closed by the app.** Its stream task exits without waking the reader, so every relay waited for the 2-hour idle timeout: 657 of 660 lab flows stayed open. Fixed with a two-line patch in a vendored copy (`third_party/ipstack/PATCHES.md`). We should offer the fix upstream.
2. **ipstack did not support TCP half-close.** When the app sent FIN, ipstack closed both directions, and an app that half-closed lost the server's reply. Fixed in Sprint 1 by patch 2 (`third_party/ipstack/PATCHES.md`); the lab now gates on it.
3. **ipstack's upload path is CPU-heavy** (about 4.7 times the per-byte cost of download), and its internal channels are unbounded.
4. **netstack-smoltcp woke every 5 ms even when idle** (its runner fell back to a 5 ms timer), and smoltcp allocates each connection's buffers up front. On a phone, the first costs battery all day and the second costs memory. The first is fixed by our patch (Sprint 1); the second is set by the buffer size we choose.
5. **ipstack's default idle timeout (60 s) is too short for phones.** Push-notification connections stay idle for minutes, so we use 2 hours.
6. DNS flows are one question and one answer. We end them after 5 s idle instead of holding a socket for 2 minutes; phones make hundreds of lookups a minute.
7. Both stacks complete the TCP handshake with the app before the upstream connection exists. If the upstream connect fails, the app sees a reset rather than a refused connection.
8. **ipstack has no receive flow control** (Sprint 1). It acknowledges app data as soon as it is queued for the reader, and its queues are unbounded, so the app never slows down when the upstream is slow. In the lab's slow-upstream test (upstream limited to 20 Mbit/s), the app sent at 587 to 679 Mbit/s for 6 s while the server received 19 Mbit/s, and the engine grew by 383 to 462 MB (two runs). On a phone, one large upload over a slow mobile link could exhaust memory and get the engine killed. Bounding the channels alone would not fix this: ipstack would have to stop acknowledging data it cannot forward, which means rewriting its receive path.

## Sprint 1 revision

Finding 8 is a correctness problem, not a tuning one, and it is exactly what a real TCP stack already does: smoltcp advertises a receive window equal to the free space in the socket buffer, so a slow upstream slows the app down. With finding 4's polling fixed by a small patch (`third_party/netstack-smoltcp/PATCHES.md`), smoltcp's remaining cost is memory, which the buffer size controls.

Same host and method as A0. Lab run with each buffer size; ipstack includes patches 1 and 2.

| | ipstack | smoltcp, default buffers | smoltcp, 32 KiB | smoltcp, 16 KiB |
| --- | --- | --- | --- | --- |
| Wake-ups in 10 s idle | 6 | 6 | 6 | 6 |
| 500 open connections | 26–27 KB each | 128 KB each | 100 KB each (about 60 MB) | 79 KB each (48 MB) |
| Upload / download | 0.52 / 1.20 Gbit/s | 3.23 / 0.69 Gbit/s | 1.52–1.73 / 0.56–0.62 Gbit/s | 1.19 / 0.57 Gbit/s |
| Slow upstream: app sent vs server got | 587–679 vs 19 Mbit/s | 25 vs 19 Mbit/s | 23 vs 19 Mbit/s | not run |
| Slow upstream: engine memory growth | **+383 to +462 MB** | +0.3 MB | +0.1 MB | not run |
| All correctness checks, including half-close | ✓ | ✓ | ✓ | ✓ |

Latency with smoltcp at 32 KiB (p95 added, two runs): new connection +0.19 to +0.27 ms, open-connection round trip +0.11 to +0.14 ms, UDP +0.07 to +0.10 ms, DNS +0.23 to +0.65 ms, server-first banner +0.26 to +0.78 ms. All far below 5 ms, and within run-to-run noise of the A0 numbers.

Small buffers cost little throughput here because the window faces a local tunnel with a round trip well under a millisecond: 32 KiB per 0.2 ms is over 1 Gbit/s. Phones' mobile links are far slower than the lab's numbers.

## Decision

1. **Use a Rust userspace engine.** The spike shows it is viable: sub-millisecond overhead on the host, and all metadata and blocking behaviour works. The GPL C engines stay as a fallback if phone measurements fail.
2. **Use smoltcp (through netstack-smoltcp) as the default stack, vendored and patched, with 32 KiB send and receive buffers per TCP connection** (`EngineConfig::tcp_buffer`). It is the only candidate with real flow control, and after the patch its idle cost equals ipstack's. 32 KiB keeps 500 connections near 60 MB.
3. **Keep the relay layer stack-agnostic.** ipstack stays in the tree behind the `ipstack` feature, so the comparison can be re-run whenever either stack changes. It is not built into the app.
4. **CI gates on the default stack.** The lab runs smoltcp on every push and fails on any correctness check, including half-close and slow-upstream backpressure (app send rate at most 3 times the server's, engine growth under 50 MB).
5. **Offer both stacks' fixes upstream.** If upstream does not take them, we maintain the vendored copies.

Download throughput (0.56–0.69 Gbit/s on the host) is smoltcp's weak point. The phone measurements below decide whether it matters; if it does, profile the download path before changing stacks again.

## Still open: phone measurements

The host cannot answer NF-03 (battery) or NF-04 (latency on a real radio). In Sprint 1, once the Android app can start the tunnel, measure on at least one mid-range phone:

- added latency p95 for DNS and new HTTPS connections, on Wi-Fi and mobile data (NF-04 ≤ 5 ms);
- battery drain over 24 hours of normal use, with and without the tunnel (NF-03 ≤ 3%);
- throughput on a fast Wi-Fi link, upload and download, to see whether smoltcp's download CPU cost is a real limit;
- memory with a browser and 10 to 20 typical apps open.

If the battery or latency target fails and profiling cannot fix it in one sprint, re-run this decision with the C engine as the third candidate.

## Reproduce

```sh
sudo crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-smoltcp                       # default stack, 32 KiB
sudo TCP_BUFFER=16384 crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-smoltcp-16k
sudo STACK=ipstack crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-ipstack          # fails the backpressure check
```

Needs Linux, root, `iproute2` (with `tc`), `iperf3` and `python3`. CI runs the smoltcp lab on every push.

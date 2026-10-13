# Packet engine lab

Runs real traffic through `sentinel-vpn` on one Linux machine, the same way Android would, and compares it with direct routing. Results and the decision they led to: [ADR-0006](../../../docs/adr/0006-android-packet-engine.md).

```text
 snscli namespace                                   snsrv namespace
 apps ──► sntun0 ──► engine ──(socket mark 1)──► vcli 10.99.0.2 ═══ vsrv 10.99.0.1 ──► echo, DNS, iperf3
                                                                                        10.88.0.1 / .2 / .53
```

The socket mark stands in for `VpnService.protect()`: a policy-routing rule sends marked sockets around the tunnel.

## Run

```sh
sudo STACK=ipstack crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-out
sudo STACK=smoltcp TCP_BUFFER=65536 crates/sentinel-vpn/lab/run-lab.sh /tmp/lab-out-2
```

Needs root, `iproute2`, `iperf3` and `python3`. Set `SKIP_BUILD=1` if `linux_lab` is already built (CI builds it first, without root).

## What it measures

| Step | File |
| --- | --- |
| Latency: new connections, round trips, DNS, server-first protocols | `bench.py` |
| Throughput and engine CPU, upload and download | `iperf3` |
| Idle cost: wake-ups and CPU over 10 s without traffic | `run-lab.sh` |
| Memory with 500 open connections (SRS CM-03) | `hold.py` |
| Correctness: SNI and DNS hostnames, blocking by name, flows that end, half-close | `bench.py`, `report.py` |

`report.py` prints Markdown tables and exits non-zero if a correctness check fails.

## Files

| File | Role |
| --- | --- |
| `run-lab.sh` | Builds the namespaces, runs everything, cleans up |
| `servers.py` | TCP and UDP echo, a server-first "banner" service, a tiny DNS server |
| `bench.py` | Latency benchmarks and correctness probes |
| `hold.py` | Holds N connections open |
| `report.py` | Summary tables and pass or fail |
| `../examples/linux_lab.rs` | Runs the engine on a TUN device and logs flows as JSON lines |

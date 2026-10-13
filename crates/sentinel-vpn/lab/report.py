#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Turn a lab output directory into a Markdown table, and check the metadata log."""
import json
import os
import sys

out = sys.argv[1]
load = lambda name: json.load(open(os.path.join(out, name)))
direct, engine = load("bench-direct.json"), load("bench-engine.json")


def gbps(name):
    d = load(name)["end"]
    key = "sum_received" if "sum_received" in d else "sum"
    return d[key]["bits_per_second"] / 1e9


print("| Measure | Direct p50 / p95 (ms) | Through engine p50 / p95 (ms) | Added p95 (ms) |")
print("| --- | --- | --- | --- |")
for key, label in [
    ("tcp_connect_first_byte", "New TCP connection + first byte echoed"),
    ("tcp_round_trip_64B", "TCP round trip, 64 B, open connection"),
    ("udp_round_trip_64B", "UDP round trip, 64 B"),
    ("dns_lookup", "DNS lookup"),
    ("server_first_banner", "Server-first banner (SSH-like)"),
]:
    a, b = direct[key], engine[key]
    added = "n/a" if a["n"] == 0 or b["n"] == 0 else f"{b['p95_ms'] - a['p95_ms']:.3f}"
    print(f"| {label} | {a['p50_ms']} / {a['p95_ms']} | {b['p50_ms']} / {b['p95_ms']} | {added} |")

cpu = load("engine-cpu.json")
up_d, up_e = gbps("iperf-direct-up.json"), gbps("iperf-engine-up.json")
dn_d, dn_e = gbps("iperf-direct-down.json"), gbps("iperf-engine-down.json")
print()
print("| Throughput (iperf3, 5 s) | Direct | Through engine | Engine CPU (core-seconds) |")
print("| --- | --- | --- | --- |")
print(f"| Upload | {up_d:.2f} Gbit/s | {up_e:.2f} Gbit/s | {cpu['up_cpu_ticks'] / cpu['clk_tck']:.2f} |")
print(f"| Download | {dn_d:.2f} Gbit/s | {dn_e:.2f} Gbit/s | {cpu['down_cpu_ticks'] / cpu['clk_tck']:.2f} |")
print()
print(f"Idle, 10 s without traffic: {cpu['idle_wakeups_10s']} wake-ups, {cpu['idle_cpu_ticks_10s'] / cpu['clk_tck']:.2f} CPU seconds")
per_conn = (cpu['rss_kb_with_500'] - cpu['rss_kb_before_500']) / 500
print(f"500 open connections: RSS {cpu['rss_kb_before_500'] / 1024:.1f} MB -> {cpu['rss_kb_with_500'] / 1024:.1f} MB ({per_conn:.0f} KB per connection)")
print("Engine memory:", " ".join(open(os.path.join(out, "engine-memory.txt")).read().split()))
print("UDP lost (direct / engine):", direct["udp_round_trip_64B"]["lost"], "/", engine["udp_round_trip_64B"]["lost"])

flows = [json.loads(l) for l in open(os.path.join(out, "flows.jsonl")) if l.strip()]
checks = dict(engine["checks"])
checks["flows_logged"] = len(flows)
checks["sni_attributed"] = any(f.get("host") == "sni-check.lab.test" and f.get("host_src") == "sni" for f in flows)
checks["sni_blocked"] = any(f.get("host") == "blocked.lab.test" and f.get("verdict") == "block" for f in flows)
checks["dns_attributed"] = any(f.get("host") == "web.lab.test" and f.get("host_src") == "dns" for f in flows)
checks["dns_answers_seen"] = sum(1 for f in flows if f.get("event") == "dns")
print()
print("Checks:", json.dumps(checks))
ok = all(v for k, v in checks.items() if isinstance(v, bool))
print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)

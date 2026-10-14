#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# A0 Spike 1 lab: measure the packet engine against direct routing on one Linux host.
#
# Topology (two network namespaces joined by a veth pair):
#
#   snscli: apps --> sntun0 --> [engine] --mark 1--> vcli 10.99.0.2 ---+
#                                                                       |
#   snsrv:  echo, DNS, iperf3 on 10.88.0.1/.2/.53 <-- vsrv 10.99.0.1 <-+
#
# The socket mark plays the role of VpnService.protect(): marked sockets use routing
# table 100, which bypasses the tunnel. Needs root, iproute2, iperf3 and python3.
#
# Usage: STACK=smoltcp|ipstack [TCP_BUFFER=bytes] [SKIP_BUILD=1] crates/sentinel-vpn/lab/run-lab.sh [output-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB="$ROOT/crates/sentinel-vpn/lab"
OUT="${1:-$(mktemp -d)}"
BIN="$ROOT/target/release/examples/linux_lab"
STACK="${STACK:-smoltcp}"
TCP_BUFFER="${TCP_BUFFER:-}"
CLI="ip netns exec snscli"
SRV="ip netns exec snsrv"
mkdir -p "$OUT"

cleanup() {
  [[ -n "${ENGINE_PID:-}" ]] && kill "$ENGINE_PID" 2>/dev/null || true
  [[ -n "${SERVERS_PID:-}" ]] && kill "$SERVERS_PID" 2>/dev/null || true
  # Only kill the pid in the file if it is still our iperf3 (pids get reused).
  if [[ -f "$OUT/iperf3.pid" ]]; then
    pid=$(tr -d '\0' <"$OUT/iperf3.pid")
    [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == iperf3 ]] && kill "$pid" 2>/dev/null || true
    rm -f "$OUT/iperf3.pid"
  fi
  ip netns del snscli 2>/dev/null || true
  ip netns del snsrv 2>/dev/null || true
}
trap cleanup EXIT
cleanup

if [[ -z "${SKIP_BUILD:-}" ]]; then
  (cd "$ROOT" && cargo build -q --release -p sentinel-vpn --features ipstack --example linux_lab)
fi

ip netns add snsrv
ip netns add snscli
ip link add vsrv type veth peer name vcli
ip link set vsrv netns snsrv
ip link set vcli netns snscli

$SRV ip link set lo up
$SRV ip addr add 10.99.0.1/24 dev vsrv
$SRV ip link set vsrv up
for a in 10.88.0.1 10.88.0.2 10.88.0.53; do $SRV ip addr add "$a/32" dev lo; done

$CLI ip link set lo up
$CLI ip addr add 10.99.0.2/24 dev vcli
$CLI ip link set vcli up
$CLI ip tuntap add dev sntun0 mode tun
$CLI ip addr add 10.111.0.1/24 dev sntun0
$CLI ip link set sntun0 mtu 1500 up
# Marked (protected) sockets bypass the tunnel.
$CLI ip route add 10.88.0.0/24 via 10.99.0.1 dev vcli table 100
$CLI ip rule add fwmark 1 lookup 100 pref 100
# Phase 1: direct routing.
$CLI ip route add 10.88.0.0/24 via 10.99.0.1 dev vcli

$SRV python3 "$LAB/servers.py" >"$OUT/servers.log" 2>&1 &
SERVERS_PID=$!
$SRV iperf3 -s -B 10.88.0.1 -D -I "$OUT/iperf3.pid"
sleep 1

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat"; }
# Wake-ups are what cost battery on a phone: count context switches of all threads.
wakeups() { cat /proc/"$1"/task/*/status | awk '/voluntary_ctxt_switches/ {s += $2} END {print s}'; }
rss_kb() { awk '/VmRSS/ {print $2}' "/proc/$1/status"; }

iperf() { # label, extra args
  $CLI iperf3 -c 10.88.0.1 -t 5 -J "${@:2}" >"$OUT/iperf-$1.json"
}

echo "== direct =="
$CLI python3 "$LAB/bench.py" direct >"$OUT/bench-direct.json"
iperf direct-up
iperf direct-down -R

echo "== through engine ($STACK) =="
$CLI ip route replace 10.88.0.0/24 dev sntun0
$CLI "$BIN" --tun sntun0 --mark 1 --threads 2 --stack "$STACK" ${TCP_BUFFER:+--tcp-buffer "$TCP_BUFFER"} \
  --block-host blocked.lab.test >"$OUT/flows.jsonl" 2>"$OUT/engine.log" &
ENGINE_PID=$!
sleep 1

# Idle cost: no traffic for 10 s.
w0=$(wakeups "$ENGINE_PID"); c0=$(cpu_ticks "$ENGINE_PID")
sleep 10
w1=$(wakeups "$ENGINE_PID"); c1=$(cpu_ticks "$ENGINE_PID")
m_start=$(rss_kb "$ENGINE_PID")
$CLI python3 "$LAB/bench.py" engine >"$OUT/bench-engine.json"
m_bench=$(rss_kb "$ENGINE_PID")
t0=$(cpu_ticks "$ENGINE_PID")
iperf engine-up
t1=$(cpu_ticks "$ENGINE_PID")
m_up=$(rss_kb "$ENGINE_PID")
iperf engine-down -R
t2=$(cpu_ticks "$ENGINE_PID")
m_down=$(rss_kb "$ENGINE_PID")
# 500 concurrent open connections (SRS CM-03).
sleep 6  # let short flows from the benchmarks finish
r0=$(rss_kb "$ENGINE_PID")
$CLI python3 "$LAB/hold.py" 500 6 >"$OUT/hold.log" &
HOLD_PID=$!
sleep 4
r1=$(rss_kb "$ENGINE_PID")
wait "$HOLD_PID"
# Slow upstream (SRS NF-03, D2 in the threat model): an app uploads through the engine
# while the real network carries only 20 Mbit/s, as on mobile data. The engine must
# slow the app down instead of buffering the upload in memory.
$CLI tc qdisc add dev vcli root tbf rate 20mbit burst 32kbit latency 50ms
s0=$(rss_kb "$ENGINE_PID"); s_max=$s0
$CLI iperf3 -c 10.88.0.1 -t 6 -J >"$OUT/iperf-engine-slow-up.json" &
SLOW_PID=$!
while kill -0 "$SLOW_PID" 2>/dev/null; do
  r=$(rss_kb "$ENGINE_PID"); (( r > s_max )) && s_max=$r
  sleep 0.5
done
$CLI tc qdisc del dev vcli root
grep -E "VmHWM|VmRSS" "/proc/$ENGINE_PID/status" >"$OUT/engine-memory.txt"
cat >"$OUT/engine-cpu.json" <<JSON
{"up_cpu_ticks": $((t1 - t0)), "down_cpu_ticks": $((t2 - t1)), "clk_tck": $(getconf CLK_TCK),
 "idle_wakeups_10s": $((w1 - w0)), "idle_cpu_ticks_10s": $((c1 - c0)),
 "rss_kb_before_500": $r0, "rss_kb_with_500": $r1,
 "rss_kb_phases": {"start": $m_start, "after_bench": $m_bench, "after_upload": $m_up, "after_download": $m_down},
 "slow_upload_rss_kb_before": $s0, "slow_upload_rss_kb_max": $s_max}
JSON
sleep 1

python3 "$LAB/report.py" "$OUT"
echo "raw results in $OUT"

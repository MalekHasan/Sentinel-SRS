#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# SP-02 on a device (ADR-0038): when Sentinel's process dies while monitoring runs,
# Android starts monitoring again by itself. The instrumented tests cannot check this,
# as they die with the process, so this script drives the app from outside:
#
#   1. installs the debug app, grants what the user's consent grants, opens it and taps
#      "Start monitoring";
#   2. kills the process as Android does to free memory (SIGKILL);
#   3. waits for the service to run again in a new process, in the foreground, and to
#      stay running.
#
#   apps/android/scripts/restart-after-kill.sh [path/to/app-debug.apk]
#
# Needs adb and one device or emulator. CI runs it after the instrumented tests.

set -eu

pkg=io.github.malekhasan.sentinel
service=$pkg/.SentinelVpnService
apk=${1:-app/build/outputs/apk/debug/app-debug.apk}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $1" >&2
  adb shell dumpsys activity services "$service" >&2 || true
  # What Android said about Sentinel's process and service: a restart scheduled, put
  # off, or not made.
  adb logcat -d -v time 'ActivityManager:I' 'ActivityTaskManager:I' 'SentinelVpn:V' '*:S' |
    grep -i -e sentinel -e restart | tail -n 60 >&2 || true
  exit 1
}

# Waits up to $1 seconds for the command in the other arguments to succeed.
wait_for() {
  limit=$1
  shift
  i=0
  while [ "$i" -lt "$limit" ]; do
    if "$@"; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

pid() { adb shell pidof "$pkg" | tr -d '\r'; }

# The service runs in the foreground, as it does while monitoring.
monitoring() { adb shell dumpsys activity services "$service" | grep -q 'isForeground=true'; }

# The tunnel is up: Android binds to the service as a VPN once the service establishes it.
# (Reading the network interfaces is denied to adb's shell.)
tunnel_up() {
  adb shell dumpsys activity services "$service" | grep -q 'act=android.net.VpnService'
}

restarted() { [ -n "$(pid)" ] && [ "$(pid)" != "$before" ] && monitoring; }

adb install -r -g "$apk" >/dev/null
# What the user's "OK" in Android's VPN consent dialog grants.
adb shell appops set "$pkg" ACTIVATE_VPN allow
adb shell am start -W -n "$pkg/.MainActivity" >/dev/null

# The screen's accessibility tree, with the "Start monitoring" button in it.
start_shown() {
  adb shell uiautomator dump /data/local/tmp/ui.xml >/dev/null &&
    adb shell cat /data/local/tmp/ui.xml >"$work/ui.xml" &&
    grep -q 'text="Start monitoring"' "$work/ui.xml"
}

# Tap "Start monitoring", found by its text.
wait_for 20 start_shown || fail "no Start monitoring button on the main screen"
point=$(python3 - "$work/ui.xml" <<'EOF'
import re, sys
xml = open(sys.argv[1], encoding="utf-8").read()
node = re.search(r'<node [^>]*text="Start monitoring"[^>]*>', xml).group(0)
x1, y1, x2, y2 = map(int, re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node).groups())
print((x1 + x2) // 2, (y1 + y2) // 2)
EOF
)
# Word splitting gives input its two coordinates.
# shellcheck disable=SC2086
adb shell input tap $point
wait_for 30 monitoring || fail "monitoring did not start"
# Android kills a process that runs monitoring, not one still starting it: the service
# is in the foreground before its tunnel is up.
wait_for 30 tunnel_up || fail "the tunnel did not come up"
sleep 3
before=$(pid)
echo "monitoring runs in process $before; killing it"

# SIGKILL, as Android's low-memory killer does; run-as gives the app's own user, which
# may kill its own process.
adb shell run-as "$pkg" kill -9 "$before"
wait_for 60 restarted || fail "monitoring did not come back within 60 s of the kill"
after=$(pid)
# Running, not just started: a start that fails stops the service again.
sleep 5
restarted || fail "monitoring came back in process $after but did not stay"
echo "monitoring came back by itself in process $after"

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Open N TCP connections through the engine, echo one byte on each, hold them open.

SRS CM-03 asks for a smooth live view at 500 concurrent flows; this measures what 500
open connections cost the engine. Usage: hold.py N SECONDS
"""
import socket
import sys
import time

n, seconds = int(sys.argv[1]), float(sys.argv[2])
conns = []
for _ in range(n):
    s = socket.create_connection(("10.88.0.1", 7007), timeout=5)
    s.sendall(b"h")
    s.recv(1)
    conns.append(s)
print(f"holding {len(conns)} connections", flush=True)
time.sleep(seconds)
for s in conns:
    s.close()

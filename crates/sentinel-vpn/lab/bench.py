#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Latency and correctness checks for the Spike 1 lab. Run inside the "client" namespace.

Prints one JSON object. The same script runs once with direct routing and once through
the engine, so the difference is the engine's cost.
"""
import json
import socket
import struct
import sys
import time

TARGET = "10.88.0.1"
RESOLVER = "10.88.0.53"


def pct(samples, p):
    s = sorted(samples)
    return round(s[min(len(s) - 1, int(len(s) * p / 100))], 3)


def summary(samples):
    if not samples:
        return {"n": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None}
    return {"n": len(samples), "p50_ms": pct(samples, 50), "p95_ms": pct(samples, 95), "p99_ms": pct(samples, 99)}


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def tcp_connect_first_byte(n=300):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        with socket.create_connection((TARGET, 7007), timeout=5) as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(b"x")
            recv_exact(s, 1)
        out.append((time.perf_counter() - t) * 1000)
    return summary(out)


def tcp_round_trips(n=3000, size=64):
    out = []
    payload = b"y" * size
    with socket.create_connection((TARGET, 7007), timeout=5) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for _ in range(n):
            t = time.perf_counter()
            s.sendall(payload)
            recv_exact(s, size)
            out.append((time.perf_counter() - t) * 1000)
    return summary(out)


def udp_round_trips(n=3000, size=64):
    out = []
    lost = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect((TARGET, 7007))
    for _ in range(n):
        t = time.perf_counter()
        s.send(b"z" * size)
        try:
            s.recv(65535)
            out.append((time.perf_counter() - t) * 1000)
        except socket.timeout:
            lost += 1
    s.close()
    r = summary(out)
    r["lost"] = lost
    return r


def dns_query(name, qid=1):
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def resolve(name, sock):
    sock.send(dns_query(name))
    reply = sock.recv(512)
    return socket.inet_ntoa(reply[-4:])


def dns_lookups(n=300):
    out = []
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((RESOLVER, 53))  # a new source port per query, like real resolvers
        t = time.perf_counter()
        resolve(f"q{i}.lab.test", s)
        out.append((time.perf_counter() - t) * 1000)
        s.close()
    return summary(out)


def server_first(n=50):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        with socket.create_connection((TARGET, 2222), timeout=5) as s:
            banner = s.recv(64)
            assert banner.startswith(b"SSH-2.0"), banner
        out.append((time.perf_counter() - t) * 1000)
    return summary(out)


def client_hello(server_name, pad=1500):
    """A TLS 1.3-shaped ClientHello big enough to need two TCP segments."""
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0x0033, pad) + b"\xab" * pad  # large key_share first
    ext += struct.pack("!HH", 0x0000, len(sni)) + sni
    body = b"\x03\x03" + b"\x07" * 32 + b"\x20" + b"\x09" * 32
    body += b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def checks():
    """Metadata the engine should report. The lab script reads the engine's flow log."""
    results = {}
    # 1. SNI on a ClientHello split across segments.
    hello = client_hello("sni-check.lab.test")
    with socket.create_connection((TARGET, 7007), timeout=5) as s:
        s.sendall(hello)
        results["sni_echo_ok"] = recv_exact(s, len(hello)) == hello
    # 2. Blocking by server name: the connection must be closed without an echo.
    try:
        with socket.create_connection((TARGET, 7007), timeout=5) as s:
            s.sendall(client_hello("blocked.lab.test"))
            data = s.recv(10)
            results["blocked_closed"] = data == b""
    except (ConnectionError, socket.timeout, OSError):
        results["blocked_closed"] = True
    # 3. DNS name attached to a later plain connection.
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.settimeout(2)
    r.connect((RESOLVER, 53))
    ip = resolve("web.lab.test", r)
    r.close()
    with socket.create_connection((ip, 7007), timeout=5) as s:
        s.sendall(b"hello")
        results["dns_flow_ok"] = recv_exact(s, 5) == b"hello"
    # 4. Half-close: send, shut down our sending side, then read the whole reply.
    try:
        with socket.create_connection((TARGET, 7007), timeout=3) as s:
            s.sendall(b"half")
            s.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                chunk = s.recv(16)
                if not chunk:
                    break
                data += chunk
            results["half_close_ok"] = data == b"half"
    except OSError:
        results["half_close_ok"] = False
    return results


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    report = {
        "label": label,
        "tcp_connect_first_byte": tcp_connect_first_byte(),
        "tcp_round_trip_64B": tcp_round_trips(),
        "udp_round_trip_64B": udp_round_trips(),
        "dns_lookup": dns_lookups(),
        "server_first_banner": server_first(),
        "checks": checks(),
    }
    print(json.dumps(report))

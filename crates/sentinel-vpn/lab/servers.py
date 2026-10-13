#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test servers for the Spike 1 lab. Run inside the "server" network namespace.

- TCP echo on port 7007 (all lab addresses)
- TCP "server speaks first" on port 2222: sends a banner on connect, like SSH
- UDP echo on port 7007
- DNS on 10.88.0.53:53: web.lab.test -> 10.88.0.2, any other *.lab.test -> 10.88.0.1
"""
import socket
import socketserver
import struct
import threading


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class Banner(Echo):
    def handle(self):
        self.request.sendall(b"SSH-2.0-lab\r\n")
        super().handle()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_echo():
    # Bound to the target address, so replies come from it (a connected client socket
    # drops replies from any other source address).
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.88.0.1", 7007))
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


def dns_answer(query):
    if len(query) < 12:
        return None
    qid, _flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount != 1:
        return None
    # Walk the question name.
    i, labels = 12, []
    while i < len(query) and query[i] != 0:
        n = query[i]
        labels.append(query[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    question = query[12:i + 5]
    name = ".".join(labels).lower()
    header = lambda an, rcode: struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0)
    if not name.endswith(".lab.test"):
        return header(0, 3) + question  # NXDOMAIN
    ip = "10.88.0.2" if name == "web.lab.test" else "10.88.0.1"
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + socket.inet_aton(ip)
    return header(1, 0) + question + answer


def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.88.0.53", 53))
    while True:
        query, addr = s.recvfrom(512)
        reply = dns_answer(query)
        if reply:
            s.sendto(reply, addr)


if __name__ == "__main__":
    for target in (udp_echo, dns):
        threading.Thread(target=target, daemon=True).start()
    banner = Server(("0.0.0.0", 2222), Banner)
    threading.Thread(target=banner.serve_forever, daemon=True).start()
    print("servers ready", flush=True)
    Server(("0.0.0.0", 7007), Echo).serve_forever()

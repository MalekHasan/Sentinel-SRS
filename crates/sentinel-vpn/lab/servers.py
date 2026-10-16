#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test servers for the Spike 1 lab. Run inside the "server" network namespace.

- TCP echo on port 7007 (all lab addresses)
- TCP "server speaks first" on port 2222: sends a banner on connect, like SSH
- TCP "server closes first" on port 8081: answers one request and closes, like HTTP/1.0
- UDP echo on port 7007
- DNS on 10.88.0.53:53: web.lab.test -> 10.88.0.2, any other *.lab.test -> 10.88.0.1;
  AAAA: web6.lab.test -> fd88::2, any other *.lab.test -> fd88::1
- With LAB_IPV6=1: TCP echo on [::]:7007 and UDP echo on [fd88::1]:7007
"""
import os
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


class CloseFirst(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(65536)
        self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        # Closing here, before the client, is what HTTP/1.0 servers do.


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Server6(Server):
    address_family = socket.AF_INET6

    def server_bind(self):
        # IPv6 only, so it can share port 7007 with the IPv4 server.
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def udp_echo(family=socket.AF_INET, addr="10.88.0.1"):
    # Bound to the target address, so replies come from it (a connected client socket
    # drops replies from any other source address).
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((addr, 7007))
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
    if len(question) < i - 12 + 5:
        return None
    (qtype,) = struct.unpack("!H", query[i + 1:i + 3])
    name = ".".join(labels).lower()
    header = lambda an, rcode: struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0)
    if not name.endswith(".lab.test"):
        return header(0, 3) + question  # NXDOMAIN
    if qtype == 1:  # A
        ip = "10.88.0.2" if name == "web.lab.test" else "10.88.0.1"
        rdata = socket.inet_aton(ip)
    elif qtype == 28:  # AAAA
        ip = "fd88::2" if name == "web6.lab.test" else "fd88::1"
        rdata = socket.inet_pton(socket.AF_INET6, ip)
    else:
        return header(0, 0) + question  # no data of this type
    answer = struct.pack("!HHHIH", 0xC00C, qtype, 1, 300, len(rdata)) + rdata
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
    if os.environ.get("LAB_IPV6") == "1":
        threading.Thread(target=udp_echo, args=(socket.AF_INET6, "fd88::1"), daemon=True).start()
        echo6 = Server6(("::", 7007), Echo)
        threading.Thread(target=echo6.serve_forever, daemon=True).start()
    close_first = Server(("0.0.0.0", 8081), CloseFirst)
    threading.Thread(target=close_first.serve_forever, daemon=True).start()
    banner = Server(("0.0.0.0", 2222), Banner)
    threading.Thread(target=banner.serve_forever, daemon=True).start()
    print("servers ready", flush=True)
    Server(("0.0.0.0", 7007), Echo).serve_forever()

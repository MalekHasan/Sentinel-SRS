#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The HTTP server the device tests reach through the tunnel.

Serves an empty directory, like `python3 -m http.server`, but with a listen backlog
large enough for LiveViewTest, which opens 500 connections at once. With the default
backlog of 5, connections beyond it wait for TCP retries.

    python3 apps/android/scripts/test-server.py [--bind 127.0.0.1] [--port 8765]
"""

import argparse
import functools
import http.server
import tempfile


class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 1024


def main():
    parser = argparse.ArgumentParser(description="HTTP server for the device tests")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sentinel-www-") as root:
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
        with Server((args.bind, args.port), handler) as server:
            print(f"serving an empty directory on {args.bind}:{args.port}", flush=True)
            server.serve_forever()


if __name__ == "__main__":
    main()

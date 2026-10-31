#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# close_origin.py <port>: an HTTP origin whose response body is delimited by
# the connection closing -- no Content-Length, no chunking -- so the client can
# only tell the end of the body from a truncation by how the connection ends.
# Bound to 127.0.0.1. Prints "READY" once listening.

import socket
import sys
import threading

BODY = b"body-runs-until-close\n" * 64


def serve(c):
    try:
        c.settimeout(10)
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = c.recv(65536)
            if not chunk:
                return
            req += chunk
        c.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + BODY)
    except OSError:
        pass
    finally:
        c.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", int(sys.argv[1])))
    s.listen(16)
    print("READY", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()

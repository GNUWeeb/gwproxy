#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Minimal HTTP/1.1 origin used by the forwarding-proxy "Expect: 100-continue"
# test. It honours the expectation: when a request carries
# "Expect: 100-continue" it sends a 100 (Continue) interim response before
# reading the body, then a final 200. Every request that arrives appends one
# "<received_body_length>\n" line to the log file (argv[2]); a request that the
# proxy rejects before contacting the origin therefore leaves no line, which is
# how the test detects that an unauthenticated body was not forwarded.

import socket
import sys
import threading

port = int(sys.argv[1])
logpath = sys.argv[2]

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)


def handle(c):
    try:
        c.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                return
            data += chunk
        hdr, _, body = data.partition(b"\r\n\r\n")
        content_length = 0
        expect = False
        for line in hdr.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1])
            elif low.startswith(b"expect:") and b"100-continue" in low:
                expect = True
        if expect:
            c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        while len(body) < content_length:
            chunk = c.recv(4096)
            if not chunk:
                break
            body += chunk
        with open(logpath, "a") as f:
            f.write("%d\n" % len(body))
        msg = b"ok"
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                  b"Connection: close\r\n\r\n" % len(msg))
        c.sendall(msg)
    except Exception:
        pass
    finally:
        c.close()


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTP CONNECT client that sends the first tunnel bytes in the same write as
# its request, without waiting for the 200 reply, against an echo origin of
# its own. The proxy must forward the bytes that came with the request: the
# client waits for their echo and sends nothing else.
#
# Usage: pipelined_connect.py <proxy_host> <proxy_port>
# Exits 0 on success, 1 on failure (with a message on stderr).

import socket
import sys
import threading


def die(msg):
    sys.stderr.write("pipelined_connect: %s\n" % msg)
    sys.exit(1)


def echo_origin(lsock):
    c, _ = lsock.accept()
    while True:
        d = c.recv(65536)
        if not d:
            break
        c.sendall(d)


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(4)
    threading.Thread(target=echo_origin, args=(lsock,), daemon=True).start()
    oport = lsock.getsockname()[1]

    s = socket.create_connection((host, port), timeout=5)
    s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\nping"
              % oport)
    got = b""
    try:
        while not (b"\r\n\r\n" in got and
                   len(got.split(b"\r\n\r\n", 1)[1]) >= 4):
            d = s.recv(4096)
            if not d:
                die("proxy closed the tunnel: %r" % got)
            got += d
    except socket.timeout:
        die("timed out, got %r" % got)
    rep, data = got.split(b"\r\n\r\n", 1)
    if b" 200 " not in rep.split(b"\r\n")[0]:
        die("CONNECT refused: %r" % rep)
    if data != b"ping":
        die("bytes sent with the CONNECT came back as %r" % data)


if __name__ == "__main__":
    main()

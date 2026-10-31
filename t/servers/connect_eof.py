#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that sends its request and closes its write side while the proxy
# is still connecting to the target. The target is a local listener whose
# accept queue is full, so the proxy's connect() stays in progress until the
# queue is drained half a second after the client's FIN. The target then
# reads until end of stream and answers with "EOF:" and what it got. The
# proxy must hold the client's bytes and its FIN until the target is up and
# deliver both: a target that waits for the end of the request otherwise
# never answers.
#
# Usage: connect_eof.py socks5 <proxy_port> <data|nodata>
#        connect_eof.py plain <proxy_port> <target_port> <data|nodata>
#
# In socks5 mode the target listens on a port of its own and the client
# pipelines its greeting, its CONNECT request and the bytes. In plain mode
# the proxy forwards to <target_port> (--target), where the target listens.
# Prints "OK", or what went wrong.

import socket
import struct
import sys
import threading
import time


def recv_all(s):
    got = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                return got, None
            got += d
    except OSError as e:
        return got, e


def main():
    mode = sys.argv[1]
    pport = int(sys.argv[2])
    tport = int(sys.argv[3]) if mode == "plain" else 0
    data = b"" if sys.argv[-1] == "nodata" else b"request"

    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", tport))
    ls.listen(0)
    tport = ls.getsockname()[1]

    # Fill the accept queue, so that the proxy's SYN goes unanswered.
    fillers = []
    for _ in range(16):
        f = socket.socket()
        f.setblocking(False)
        f.connect_ex(("127.0.0.1", tport))
        fillers.append(f)
    time.sleep(0.2)
    fports = {f.getsockname()[1] for f in fillers}
    go = threading.Event()

    def serve(c):
        c.settimeout(5)
        got, err = recv_all(c)
        try:
            c.sendall((b"NO EOF:" if err else b"EOF:") + got)
        except OSError:
            pass
        c.close()

    def target():
        go.wait()
        for f in fillers:
            f.close()
        while True:
            c, a = ls.accept()
            if a[1] in fports:
                c.close()
                continue
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=target, daemon=True).start()

    s = socket.create_connection(("127.0.0.1", pport), timeout=10)
    out = b""
    if mode == "socks5":
        out = b"\x05\x01\x00" + b"\x05\x01\x00\x01" + \
            socket.inet_aton("127.0.0.1") + struct.pack(">H", tport)
    s.sendall(out + data)
    s.shutdown(socket.SHUT_WR)
    time.sleep(0.5)
    go.set()

    got, err = recv_all(s)
    want = b"EOF:" + data
    if mode == "socks5":
        if got[:2] != b"\x05\x00" or got[2:4] != b"\x05\x00":
            print("SOCKS5 replies %r" % got[:12])
            return
        got = got[12:]
    if got != want or err is not None:
        print("got %r%s, want %r and end of stream" %
              (got, " (%s)" % err if err else "", want))
        return
    print("OK")


if __name__ == "__main__":
    main()

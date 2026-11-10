#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that grants a CONNECT only once the downstream proxy is
# held at a point of its choosing (see t/servers/hold_at_log_line.c): it
# waits for <hold_file> to appear, sends its success reply and some tunnel
# data, gives the proxy's pending recv time to take them in, then removes
# <hold_file> to let the proxy go on.
#
# The script is the upstream (an http:// or socks5:// server listening on
# <upstream_port>) and the client: it sends a CONNECT to 192.0.2.1:80 through
# the proxy at <proxy_port>, an HTTP or a SOCKS5 one by <mode>, and reads
# what the proxy answers until EOF.
#
# Prints "OK timeout" when the client got exactly the proxy's own timeout
# answer, "NOT HELD" when the proxy never reached the point the shim holds
# at, or what went wrong.
#
# Usage: upstream_answers_while_held.py <http|socks5> <proxy_port>
#        <upstream_port> <hold_file>

import os
import socket
import sys
import threading
import time

HTTP_GRANT = b"HTTP/1.1 200 Connection established\r\n\r\n"
S5_GRANT = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x12\x34"
DATA = b"tunnel data from the upstream " * 4


def recv_until(s, pred, limit):
    got = b""
    while not pred(got) and len(got) < limit:
        d = s.recv(limit - len(got))
        if not d:
            break
        got += d
    return got


def main():
    mode, pport, uport, hold_file = (sys.argv[1], int(sys.argv[2]),
                                     int(sys.argv[3]), sys.argv[4])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", uport))
    ls.listen(1)
    ls.settimeout(30)
    state = {"held": False, "err": None}

    def upstream():
        try:
            c, _ = ls.accept()
            c.settimeout(30)
            if mode == "http":
                recv_until(c, lambda d: b"\r\n\r\n" in d, 65536)
            else:
                recv_until(c, lambda d: len(d) >= 3, 3)
                c.sendall(b"\x05\x00")
                recv_until(c, lambda d: len(d) >= 10, 10)
            end = time.monotonic() + 30
            while not os.path.exists(hold_file):
                if time.monotonic() > end:
                    return
                time.sleep(0.01)
            state["held"] = True
            c.sendall((HTTP_GRANT if mode == "http" else S5_GRANT) + DATA)
            # The proxy's recv takes the bytes in while it is held.
            time.sleep(0.5)
            os.unlink(hold_file)
            time.sleep(2)
            c.close()
        except OSError as e:
            state["err"] = str(e)

    t = threading.Thread(target=upstream, daemon=True)
    t.start()

    s = socket.create_connection(("127.0.0.1", pport), timeout=30)
    if mode == "http":
        s.sendall(b"CONNECT 192.0.2.1:80 HTTP/1.1\r\n"
                  b"Host: 192.0.2.1:80\r\n\r\n")
    else:
        s.sendall(b"\x05\x01\x00")
        if recv_until(s, lambda d: len(d) >= 2, 2) != b"\x05\x00":
            print("no method reply")
            return
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("192.0.2.1") +
                  b"\x00\x50")

    s.settimeout(40)
    got, end = b"", "open"
    try:
        while True:
            d = s.recv(4096)
            if not d:
                end = "EOF"
                break
            got += d
    except socket.timeout:
        pass
    except ConnectionResetError:
        end = "RST"
    t.join(10)

    if state["err"]:
        print("upstream: %s" % state["err"])
        return
    if not state["held"]:
        print("NOT HELD")
        return
    if mode == "http":
        ok = (got.startswith(b"HTTP/1.1 504 Gateway Timeout\r\n") and
              got.endswith(b"\r\n\r\n") and got.count(b"HTTP/") == 1)
    else:
        ok = got == b"\x05\x06\x00\x01" + b"\x00" * 6
    if not ok or end == "open":
        print("not the timeout answer: %r, then %s" % (got, end))
        return
    print("OK timeout")


if __name__ == "__main__":
    main()

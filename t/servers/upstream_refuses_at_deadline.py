#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that refuses a CONNECT just as the downstream proxy's
# connect timeout runs out, with the downstream proxy stopped across its
# deadline: the refusal and the expiry are then taken in by the proxy
# together. The client must get exactly one complete answer, the upstream's
# refusal or the timeout, and nothing after it.
#
# The script is the upstream (an http:// or socks5:// server listening on
# <upstream_port>) and the client: it sends a CONNECT to 192.0.2.1:80 through
# the proxy at <proxy_port>, an HTTP or a SOCKS5 one by <mode>. Once the
# upstream has the request, it stops the proxy (<proxy_pid>) half a second
# before <connect_timeout> has passed, refuses, and resumes the proxy once
# the timeout is over.
#
# Prints "OK upstream" or "OK timeout", for which answer the client got, or
# what went wrong.
#
# Usage: upstream_refuses_at_deadline.py <http|socks5> <proxy_port>
#        <upstream_port> <proxy_pid> <connect_timeout>

import os
import signal
import socket
import sys
import threading
import time

HTTP_REFUSAL = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
S5_REFUSAL = b"\x05\x05\x00\x01" + b"\x00" * 6


def recv_until(s, pred, limit):
    got = b""
    while not pred(got) and len(got) < limit:
        d = s.recv(limit - len(got))
        if not d:
            break
        got += d
    return got


def stopped(pid):
    with open("/proc/%d/stat" % pid) as f:
        return f.read().rsplit(")", 1)[1].split()[0] in ("T", "t")


def main():
    mode, pport, uport, pid, ct = (sys.argv[1], int(sys.argv[2]),
                                   int(sys.argv[3]), int(sys.argv[4]),
                                   float(sys.argv[5]))
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", uport))
    ls.listen(1)
    ls.settimeout(30)
    have_req = threading.Event()
    refused = threading.Event()
    err = []

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
            have_req.set()
            # Not before the proxy is stopped: see below.
            if not refused.wait(30):
                return
            c.sendall(HTTP_REFUSAL if mode == "http" else S5_REFUSAL)
            time.sleep(1)
            c.close()
        except OSError as e:
            err.append(str(e))
            have_req.set()

    threading.Thread(target=upstream, daemon=True).start()

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

    # The connect timer was armed before the proxy dialled the upstream.
    if not have_req.wait(30) or err:
        print("the upstream did not get the request: %s" % err)
        return
    t0 = time.monotonic()
    time.sleep(max(ct - 0.5 - (time.monotonic() - t0), 0))
    os.kill(pid, signal.SIGSTOP)
    try:
        for _ in range(500):
            if stopped(pid):
                break
            time.sleep(0.01)
        refused.set()
        # Past the deadline, with time for the refusal to reach the proxy.
        time.sleep(max(t0 + ct + 0.5 - time.monotonic(), 0.3))
    finally:
        os.kill(pid, signal.SIGCONT)

    s.settimeout(10)
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

    if mode == "http":
        answers = {
            "upstream": b"HTTP/1.1 502 Bad Gateway\r\n",
            "timeout": b"HTTP/1.1 504 Gateway Timeout\r\n",
        }
        kind = [k for k, v in answers.items() if got.startswith(v)]
        complete = got.endswith(b"\r\n\r\n") and got.count(b"HTTP/") == 1
    else:
        answers = {"upstream": b"\x05\x05", "timeout": b"\x05\x06"}
        kind = [k for k, v in answers.items() if got[:2] == v]
        complete = len(got) == 10 and got[2:] == S5_REFUSAL[2:]
    if not kind or not complete or end == "open":
        print("not one complete answer: %r, then %s" % (got, end))
        return
    print("OK %s" % kind[0])


if __name__ == "__main__":
    main()

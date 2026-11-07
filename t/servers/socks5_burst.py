#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Open <count> SOCKS5 connections through the proxy, <conc> at a time, each
# a no-auth greeting and a CONNECT to 127.0.0.1:<target_port>, read the
# reply and close. Prints "rep0=N fail=N err=N": how many were granted
# (REP 0x00), refused with any other REP, or ended otherwise (the proxy
# hanging up, a timeout).
#
# Usage: socks5_burst.py <proxy_port> <target_port> <count> <conc>
import socket, struct, sys, threading

pport, tport, count, conc = (int(a) for a in sys.argv[1:5])
lock = threading.Lock()
left = [count]
res = {'rep0': 0, 'fail': 0, 'err': 0}


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError("short read")
        b += d
    return b


def one():
    c = socket.create_connection(("127.0.0.1", pport), timeout=60)
    try:
        c.sendall(b"\x05\x01\x00")
        if recv_exact(c, 2) != b"\x05\x00":
            return 'err'
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                  struct.pack(">H", tport))
        r = recv_exact(c, 10)
        return 'rep0' if r[1] == 0 else 'fail'
    finally:
        c.close()


def worker():
    while True:
        with lock:
            if not left[0]:
                return
            left[0] -= 1
        try:
            k = one()
        except (OSError, EOFError):
            k = 'err'
        with lock:
            res[k] += 1


th = [threading.Thread(target=worker) for _ in range(conc)]
for t in th:
    t.start()
for t in th:
    t.join()
print("rep0=%d fail=%d err=%d" % (res['rep0'], res['fail'], res['err']))

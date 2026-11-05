#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Ask a SOCKS5 proxy for a UDP ASSOCIATE as <user>:<pass> and print the
# reply's REP code ("REP <n>"), or "HUP" when the proxy hangs up first.
#
# Usage: socks5_udp_assoc.py <proxy_port> <user> <pass>
import socket, sys

port, user, pw = int(sys.argv[1]), sys.argv[2], sys.argv[3]


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            print("HUP")
            sys.exit(0)
        b += d
    return b


c = socket.create_connection(("127.0.0.1", port), timeout=10)
c.sendall(b"\x05\x01\x02")
if recv_exact(c, 2) != b"\x05\x02":
    sys.exit("the proxy did not take user/password")
c.sendall(b"\x01" + bytes([len(user)]) + user.encode() +
          bytes([len(pw)]) + pw.encode())
if recv_exact(c, 2) != b"\x01\x00":
    sys.exit("the proxy refused the credentials")
c.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
print("REP %d" % recv_exact(c, 4)[1])

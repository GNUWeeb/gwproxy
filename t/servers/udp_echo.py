#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# A trivial UDP echo server for the SOCKS5 UDP ASSOCIATE tests.
#
# udp_echo.py <addr> <port>: pass port 0 to let the kernel pick a free one.
# Once bound, prints "READY <port>" with the port actually in use, so the
# caller learns it from this process rather than from whoever else may hold
# a socket on some port number it guessed.
import socket, sys

fam = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
print("READY %d" % s.getsockname()[1], flush=True)
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)

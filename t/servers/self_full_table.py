#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Leave proxy <pid> at most one free descriptor number and see what it does with
# a target on its own port number. RLIMIT_NOFILE limits numbers, not how many are
# open, and the proxy may hold high ones it inherited, so count free numbers.
#
# socks5 <pid> <port> <dst>: a connected client asks for <dst> <port>, the attempt
# takes the last number. Prints the reply, "REP=0xNN" or CLOSED.
#
# plain <pid> <port>: the client takes the last number, so the target socket has
# none. Prints "WAITED" if it is still connected after a while, then lifts the
# limit and adds how it ends: EOF, or TIMEOUT.
#
# Usage: self_full_table.py socks5|plain <pid> <port> [<dst>]
import ipaddress, os, resource, socket, struct, sys, time

mode, pid, port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
soft, hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)


def one_free_number():
    used = set(map(int, os.listdir("/proc/%d/fd" % pid)))
    lim, free = 0, 0
    while free < 1:
        free += lim not in used
        lim += 1
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, hard))


def recv_some(c, want):
    buf = b""
    while len(buf) < want:
        d = c.recv(want - len(buf))
        if not d:
            break
        buf += d
    return buf


if mode == "socks5":
    dst = ipaddress.ip_address(sys.argv[4]).packed
    c = socket.create_connection(("127.0.0.1", port), timeout=60)
    c.sendall(b"\x05\x01\x00")
    if recv_some(c, 2) != b"\x05\x00":
        sys.exit("no method selection")
    one_free_number()
    c.sendall(b"\x05\x01\x00\x01" + dst + struct.pack("!H", port))
    try:
        rep = recv_some(c, 2)
    except OSError:
        rep = b""
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (soft, hard))
    print("REP=0x%02x" % rep[1] if len(rep) == 2 else "CLOSED")
else:
    one_free_number()
    c = socket.create_connection(("127.0.0.1", port), timeout=60)
    # Well past a retry of the target socket, which comes every 100 ms.
    c.settimeout(2)
    try:
        c.recv(1)
        sys.exit("disconnected with the table full")
    except socket.timeout:
        pass
    except OSError as e:
        sys.exit("disconnected with the table full: %r" % e)
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (soft, hard))
    c.settimeout(60)
    try:
        got = "DATA" if c.recv(1) else "EOF"
    except socket.timeout:
        got = "TIMEOUT"
    except OSError:
        got = "EOF"
    print("WAITED " + got)

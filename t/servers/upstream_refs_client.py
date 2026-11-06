#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Put a SOCKS5 proxy through many connections that end in every way a
# connection through an upstream can end, for t/0049-upstream-refs.sh:
#
#   ok        CONNECT to the target, fetch a file, read to EOF
#   refused   CONNECT to a port nothing listens on
#   greeting  hang up halfway through the greeting
#   request   hang up right after the CONNECT request, before its reply
#   udp       UDP ASSOCIATE, which a chaining proxy refuses
#
# Each kind runs <count> times. Then <held> tunnels to the target are opened
# and left open, so the proxy has connections left to free when it is told to
# stop. Prints "ok=N refused=N ..." and then "HELD", and sleeps until killed.
#
# Usage: upstream_refs_client.py <proxy_port> <target_port> <closed_port>
#                                <count> <held>
import socket, struct, sys, time

pport, tport, cport, count, held = (int(a) for a in sys.argv[1:6])


def conn():
    c = socket.create_connection(("127.0.0.1", pport), timeout=10)
    return c


def request(cmd, port):
    return b"\x05" + bytes([cmd]) + b"\x00\x01" + socket.inet_aton(
        "127.0.0.1") + struct.pack("!H", port)


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            break
        b += d
    return b


def tunnel(cmd, port):
    """Greeting and request; return the reply code, or -1 if hung up."""
    c = conn()
    c.sendall(b"\x05\x01\x00")
    if recv_exact(c, 2) != b"\x05\x00":
        c.close()
        return c, -1
    c.sendall(request(cmd, port))
    rep = recv_exact(c, 10)
    return c, rep[1] if len(rep) == 10 else -1


res = {"ok": 0, "refused": 0, "greeting": 0, "request": 0, "udp": 0}
for _ in range(count):
    c, rep = tunnel(1, tport)
    if rep == 0:
        c.sendall(b"GET /file.bin HTTP/1.0\r\n\r\n")
        while c.recv(65536):
            pass
        res["ok"] += 1
    c.close()

    c, rep = tunnel(1, cport)
    if rep > 0:
        res["refused"] += 1
    c.close()

    c = conn()
    c.sendall(b"\x05")
    c.close()
    res["greeting"] += 1

    c = conn()
    c.sendall(b"\x05\x01\x00" + request(1, tport))
    c.close()
    res["request"] += 1

    c, rep = tunnel(3, 0)
    if rep > 0:
        res["udp"] += 1
    c.close()

keep = []
for _ in range(held):
    c, rep = tunnel(1, tport)
    if rep != 0:
        print("held tunnel refused: %d" % rep, flush=True)
        sys.exit(1)
    keep.append(c)

print(" ".join("%s=%d" % kv for kv in res.items()), flush=True)
print("HELD", flush=True)
time.sleep(600)

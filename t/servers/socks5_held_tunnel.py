#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Hold one SOCKS5 tunnel open across a change on the proxy (a reload, say)
# and show that it still works afterwards. Authenticates as <user>:<pass>,
# CONNECTs to <host>:<port> by name, and fetches <path> over HTTP/1.1
# keep-alive: once, printing "FIRST <bytes>", then again over the same
# tunnel once <go-file> exists, printing "SECOND <bytes>". Then prints
# "HELD" and keeps the tunnel open until killed. Gives up (exit 1) on any
# error, or when <go-file> has not appeared in 120 seconds.
#
# Usage: socks5_held_tunnel.py <proxy_port> <user> <pass> <host> <port>
#                              <path> <go-file>
import os, socket, struct, sys, time

pport, user, pw, host, port, path, go = sys.argv[1:8]
pport, port = int(pport), int(port)


def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError("short read")
        b += d
    return b


def fetch(c):
    """One GET over the tunnel; returns the body length."""
    c.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" %
              (path.encode(), host.encode()))
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = c.recv(65536)
        if not d:
            raise EOFError("no response header")
        buf += d
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.1 200"):
        raise RuntimeError("bad response: %r" % head[:40])
    clen = None
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            clen = int(v.strip())
    if clen is None:
        raise RuntimeError("no Content-Length")
    while len(body) < clen:
        d = c.recv(65536)
        if not d:
            raise EOFError("short body")
        body += d
    return len(body)


c = socket.create_connection(("127.0.0.1", pport), timeout=30)
c.sendall(b"\x05\x01\x02")
if recv_exact(c, 2) != b"\x05\x02":
    sys.exit("the proxy did not take user/password")
c.sendall(b"\x01" + bytes([len(user)]) + user.encode() +
          bytes([len(pw)]) + pw.encode())
if recv_exact(c, 2) != b"\x01\x00":
    sys.exit("the proxy refused the credentials")
c.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() +
          struct.pack("!H", port))
rep = recv_exact(c, 4)
if rep[1] != 0:
    sys.exit("CONNECT refused: %d" % rep[1])
if rep[3] == 1:
    recv_exact(c, 4 + 2)
elif rep[3] == 4:
    recv_exact(c, 16 + 2)
else:
    recv_exact(c, recv_exact(c, 1)[0] + 2)

print("FIRST %d" % fetch(c), flush=True)
deadline = time.monotonic() + 120
while not os.path.exists(go):
    if time.monotonic() > deadline:
        sys.exit("gave up waiting for %s" % go)
    time.sleep(0.1)
print("SECOND %d" % fetch(c), flush=True)
print("HELD", flush=True)
time.sleep(600)

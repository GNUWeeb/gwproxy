#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""A DNS server that drops the first queries of some names.

Usage: dns_drop_first.py <query-log>

Binds a UDP port on 127.0.0.1 chosen by the kernel and prints "READY <port>".

A name starting with "dropN-" (N a digit) has the first N queries for each
record type it is asked about dropped, as if lost on the way; the next one is
answered. A name starting with "silent" is never answered. Everything else is
answered at once. A query for an A record gets 127.0.0.1, any other type an
empty answer.

Every query received is appended to <query-log> as "<name> <type> <txid>"
(the type and the ID as decimal numbers), one line each, so a test can count
the sends and check that a resend reuses the ID.
"""
import socket, struct, sys

log_path = sys.argv[1]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print("READY %d" % s.getsockname()[1], flush=True)

seen = {}


def parse(q):
    """The question's name, its type and the end of the question, or None."""
    off, labels = 12, []
    while off < len(q) and q[off]:
        labels.append(q[off + 1:off + 1 + q[off]].decode("latin-1"))
        off += q[off] + 1
    if off + 5 > len(q):
        return None
    qtype = struct.unpack("!H", q[off + 1:off + 3])[0]
    return ".".join(labels).lower(), qtype, off + 5


while True:
    q, peer = s.recvfrom(2048)
    if len(q) < 12:
        continue
    p = parse(q)
    if p is None:
        continue
    name, qtype, qend = p
    txid = struct.unpack("!H", q[:2])[0]
    with open(log_path, "a") as f:
        f.write("%s %d %d\n" % (name, qtype, txid))

    if name.startswith("silent"):
        continue
    key = (name, qtype)
    seen[key] = seen.get(key, 0) + 1
    if len(name) > 5 and name.startswith("drop") and name[4].isdigit() \
            and name[5] == "-" and seen[key] <= int(name[4]):
        continue

    head = q[:2] + struct.pack("!HHHHH", 0x8180, 1, qtype == 1, 0, 0)
    rr = b""
    if qtype == 1:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + \
            bytes([127, 0, 0, 1])
    s.sendto(head + q[12:qend] + rr, peer)

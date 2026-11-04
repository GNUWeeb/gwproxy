#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""A DNS server that holds back the answers for some names.

Usage: dns_hold.py <port> <names-file> <release-file>

A name starting with "hold" gets no answer until <release-file> exists, so a
lookup of one blocks for as long as the test wants, with no timing involved.
Everything else is answered at once. A query for an A record gets 127.0.0.1,
any other an empty answer. A name starting with "holdnx" is answered, when its
time comes, with NXDOMAIN.

<names-file> always holds the distinct held names received so far, one per
line, so a test can tell which lookups really started.
"""
import os, select, socket, struct, sys

port = int(sys.argv[1])
names_file, release_file = sys.argv[2:4]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
print("READY", flush=True)

held = []
seen = set()


def parse(q):
    """The question's name and its type, or (None, None) if malformed."""
    off, labels = 12, []
    while off < len(q) and q[off]:
        labels.append(q[off + 1:off + 1 + q[off]].decode("latin-1"))
        off += q[off] + 1
    if off + 5 > len(q):
        return None, None
    return ".".join(labels).lower(), struct.unpack("!H", q[off + 1:off + 3])[0]


def answer(q, qtype, peer):
    qend = 12
    while q[qend]:
        qend += q[qend] + 1
    qend += 5
    if parse(q)[0].startswith("holdnx"):
        s.sendto(q[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + q[12:qend], peer)
        return
    head = q[:2] + struct.pack("!HHHHH", 0x8180, 1, qtype == 1, 0, 0)
    rr = b""
    if qtype == 1:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
    s.sendto(head + q[12:qend] + rr, peer)


def write_names():
    with open(names_file + ".tmp", "w") as f:
        f.write("".join(n + "\n" for n in sorted(seen)))
    os.replace(names_file + ".tmp", names_file)


write_names()
while True:
    ready = select.select([s], [], [], 0.05)[0]
    released = os.path.exists(release_file)
    if released:
        for q, qtype, peer in held:
            answer(q, qtype, peer)
        held = []
    if not ready:
        continue
    q, peer = s.recvfrom(2048)
    if len(q) < 12:
        continue
    name, qtype = parse(q)
    if name is None:
        continue
    if name.startswith("hold"):
        if name not in seen:
            seen.add(name)
            write_names()
        if not released:
            held.append((q, qtype, peer))
            continue
    answer(q, qtype, peer)

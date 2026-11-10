#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""A DNS server that answers a name at a time the name gives.

Usage: dns_answer_at.py <port>

A name whose first label is "at-<ns>-<anything>" gets its A record
(127.0.0.1) once CLOCK_MONOTONIC reads <ns> nanoseconds, so a test can have
a lookup complete at a moment of its choosing, to well under a millisecond.
Every other query, AAAA included, is answered at once: A with 127.0.0.1,
the other types with an empty answer. Prints READY once bound to 127.0.0.1.
"""
import socket
import struct
import sys
import threading
import time

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
lock = threading.Lock()
print("READY", flush=True)


def parse(q):
    """The question's name, its type and where it ends; raises if bad."""
    off, labels = 12, []
    while q[off]:
        labels.append(q[off + 1:off + 1 + q[off]].decode("latin-1"))
        off += q[off] + 1
    qtype = struct.unpack("!H", q[off + 1:off + 3])[0]
    return ".".join(labels).lower(), qtype, off + 5


def build(q, qend, qtype):
    rr = b""
    if qtype == 1:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + \
             bytes([127, 0, 0, 1])
    return q[:2] + struct.pack("!HHHHH", 0x8180, 1, 1 if rr else 0, 0, 0) + \
        q[12:qend] + rr


def send(out, peer):
    with lock:
        s.sendto(out, peer)


def later(at_ns, out, peer):
    while True:
        left = at_ns - time.monotonic_ns()
        if left <= 0:
            break
        # Sleep most of the way, then spin for the last two milliseconds.
        if left > 2_000_000:
            time.sleep((left - 1_000_000) / 1e9)
    send(out, peer)


while True:
    q, peer = s.recvfrom(4096)
    try:
        name, qtype, qend = parse(q)
    except (IndexError, struct.error):
        continue
    out = build(q, qend, qtype)
    first = name.split(".")[0].split("-")
    if qtype == 1 and len(first) >= 3 and first[0] == "at":
        threading.Thread(target=later, args=(int(first[1]), out, peer),
                         daemon=True).start()
    else:
        send(out, peer)

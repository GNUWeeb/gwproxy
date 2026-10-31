#!/usr/bin/env python3
"""Malformed-DNS-response server, for testing gwproxy's raw resolver.

Answers every query with a deliberately malformed response chosen by mode.
Modes mirror the four findings in src/gwproxy/dns_parser.c.
"""
import os, socket, struct, sys, time

mode = sys.argv[1]
port = int(sys.argv[2])
# Optional: a file that always holds the number of queries received so far.
count_file = sys.argv[3] if len(sys.argv) > 3 else None
# Optional: a file to append "<txid> <source port>" to for every query.
query_log = sys.argv[4] if len(sys.argv) > 4 else None
nr_queries = 0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
sys.stderr.write("ready\n"); sys.stderr.flush()


def qname_end(q, off):
    """Walk the question name, return offset just past the terminating 0."""
    while off < len(q) and q[off] != 0:
        off += q[off] + 1
    return off + 1


while True:
    q, peer = s.recvfrom(2048)
    if len(q) < 12:
        continue
    nr_queries += 1
    if count_file:
        with open(count_file + ".tmp", "w") as f:
            f.write("%d\n" % nr_queries)
        os.replace(count_file + ".tmp", count_file)
    txid = q[:2]
    if query_log:
        with open(query_log, "a") as f:
            f.write("%d %d\n" % (struct.unpack("!H", txid)[0], peer[1]))
    qend = qname_end(q, 12)
    question = q[12:qend + 4]          # name + qtype + qclass
    name = q[12:qend]

    if mode == "slow":
        # The ordinary answer, but only after a lookup's worth of waiting.
        time.sleep(2)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "good":
        # Control: a perfectly ordinary compressed-name A record.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "uncompressed-name":
        # A perfectly legal answer whose owner NAME is a literal label rather
        # than a compression pointer. RFC 1035 permits this.
        rr = name + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "cname-jump":
        # One CNAME whose RDLENGTH is enormous; the parser adds it to the
        # cursor and loops without ever re-checking the bound.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 0xFFFF)
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0) + question + rr

    elif mode == "rdata-truncated":
        # AAAA claiming 16 bytes of RDATA, response ends after one.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + b"\x01"
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "field-truncated":
        # The reply ends two bytes into the answer's TTL, so the TTL and
        # RDLENGTH reads run off the end of what arrived.
        rr = b"\xc0\x0c" + struct.pack("!HH", 1, 1) + b"\x00\x00"
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "tc-set":
        # A well-formed A answer from a server that says it truncated the
        # reply (TC). What is left looks complete, but may not be.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8380, 1, 1, 0, 0) + question + rr

    elif mode == "question-label":
        # Echo a question whose second label length is 0xC0 (192): the question
        # walker has no notion of compression and strides 193 bytes forward.
        bad_q = b"\x01a\xc0" + b"\x00" * 3 + struct.pack("!HH", 1, 1)
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + bad_q
        resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])

    elif mode in ("wrong-name", "wrong-type", "upper-name"):
        # A well-formed A answer to a question other than the one asked:
        # its first label's letters shifted, or the QTYPE swapped. The
        # control echoes the name in upper case, which is the same name.
        qtype = q[qend:qend + 2]
        if mode == "wrong-name":
            name = name[:2] + bytes([ord("z")]) + name[3:]
        elif mode == "upper-name":
            name = name.upper()
        else:
            qtype = b"\x00\x1c" if qtype == b"\x00\x01" else b"\x00\x01"
        question = name + qtype + q[qend + 2:qend + 4]
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    else:
        raise SystemExit("unknown mode " + mode)

    s.sendto(resp, peer)

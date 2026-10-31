#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 client that does not wait for any reply: it sends the greeting,
# the RFC 1929 credentials (with --user/--pass), the request and, for a
# CONNECT, the first tunnel bytes in a single write, then reads. Against an
# echo origin of its own, a CONNECT must get REP 0x00 and the bytes back; a
# UDP ASSOCIATE must get REP 0x00. Prints "OK", or what went wrong.
#
# Usage: socks5_pipeline.py <proxy_port> <connect|udp> [--user U --pass P]

import socket
import struct
import sys
import threading


def echo_origin(lsock):
    c, _ = lsock.accept()
    while True:
        d = c.recv(65536)
        if not d:
            break
        c.sendall(d)


def recv_exact(s, n):
    got = b""
    while len(got) < n:
        d = s.recv(n - len(got))
        if not d:
            break
        got += d
    return got


def main():
    port, cmd = int(sys.argv[1]), sys.argv[2]
    args = sys.argv[3:]
    user = args[args.index("--user") + 1].encode() if "--user" in args else None
    pw = args[args.index("--pass") + 1].encode() if "--pass" in args else b""

    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    threading.Thread(target=echo_origin, args=(lsock,), daemon=True).start()

    out = b"\x05\x01\x02" if user is not None else b"\x05\x01\x00"
    if user is not None:
        out += b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw
    if cmd == "connect":
        out += b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + \
               struct.pack(">H", lsock.getsockname()[1]) + b"ping"
    else:
        out += b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(out)
    try:
        method = recv_exact(s, 2)
        if method != (b"\x05\x02" if user is not None else b"\x05\x00"):
            print("greeting answered %r" % method)
            return
        if user is not None:
            st = recv_exact(s, 2)
            if st != b"\x01\x00":
                print("authentication answered %r" % st)
                return
        rep = recv_exact(s, 10)
        if len(rep) < 10 or rep[1] != 0:
            print("request answered %r" % rep)
            return
        if cmd == "connect":
            data = recv_exact(s, 4)
            if data != b"ping":
                print("tunnel bytes came back as %r" % data)
                return
    except socket.timeout:
        print("timed out")
        return
    print("OK")


if __name__ == "__main__":
    main()

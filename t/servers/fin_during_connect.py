#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Clients that make their request and close their write side while the proxy's
# connect to a target that never answers is still in progress. The proxy runs
# with --connect-timeout=0 and a short --protocol-timeout, which must then bound
# the connect: each client is to get its timeout reply (SOCKS5 REP 0x06, HTTP
# 504; nothing in plain forwarding) and the end of the stream, no sooner than
# about the bound and well before the kernel would give up on the SYN. In plain
# forwarding a reset counts as the end too: the io_uring loop reads nothing from
# the client before the target is up, and the close of a socket with unread
# bytes resets it.
#
# Next to each, a client that keeps its write side open waits for the same
# target, and must still be connected once the half-closed one is gone:
# --connect-timeout=0 still sets no limit for it.
#
# Usage: fin_during_connect.py socks5 <proxy_port> <target_port> <bound>
#        fin_during_connect.py http <proxy_port> <target_port> <bound>
#        fin_during_connect.py plain <proxy_port> <bound>
#
# Prints "OK", or what went wrong.

import socket
import struct
import sys
import time

# How long a client waits for the end of the stream: far above the bound, far
# below the kernel's SYN retries (about two minutes by default).
WAIT = 40


def request(mode, tport):
    if mode == "socks5":
        return b"\x05\x01\x00" + b"\x05\x01\x00\x01" + \
            socket.inet_aton("127.0.0.1") + struct.pack(">H", tport)
    if mode == "http":
        a = "127.0.0.1:%d" % tport
        return ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (a, a)).encode()
    return b"request"


def recv_all(s, deadline):
    got = b""
    while True:
        s.settimeout(max(deadline - time.monotonic(), 0.01))
        try:
            d = s.recv(65536)
        except socket.timeout:
            return got, "no end of stream"
        except OSError as e:
            return got, str(e)
        if not d:
            return got, None
        got += d


def main():
    mode = sys.argv[1]
    pport = int(sys.argv[2])
    tport = int(sys.argv[3]) if mode != "plain" else 0
    bound = float(sys.argv[-1])

    req = request(mode, tport)
    stay = socket.create_connection(("127.0.0.1", pport), timeout=10)
    stay.sendall(req)

    s = socket.create_connection(("127.0.0.1", pport), timeout=10)
    t0 = time.monotonic()
    s.sendall(req)
    s.shutdown(socket.SHUT_WR)
    got, err = recv_all(s, t0 + WAIT)
    took = time.monotonic() - t0
    s.close()
    # In plain forwarding the io_uring loop has not read the client's bytes
    # when the pair goes, and closing a socket with unread data resets it.
    if mode == "plain" and not got and err and "reset" in err:
        err = None
    if err is not None:
        print("half-closed client: %s after %.1f s (got %r)" % (err, took, got))
        return 1
    if took < bound * 0.75:
        print("half-closed client: closed after %.1f s, before the bound "
              "of %g s" % (took, bound))
        return 1
    if mode == "socks5":
        if got[:2] != b"\x05\x00" or got[2:4] != b"\x05\x06":
            print("half-closed client: SOCKS5 replies %r, want REP 0x06" %
                  got[:12])
            return 1
    elif mode == "http":
        if not got.startswith(b"HTTP/1.1 504"):
            print("half-closed client: HTTP reply %r, want 504" % got[:40])
            return 1
    elif got:
        print("half-closed client: got %r in plain forwarding" % got)
        return 1

    # The client that stays: still connected, and not answered.
    want = {"socks5": 2, "http": 0, "plain": 0}[mode]
    stay.settimeout(0.5)
    try:
        d = stay.recv(65536)
    except socket.timeout:
        d = None
    except OSError as e:
        print("client that stays: %s" % e)
        return 1
    if d is not None and len(d) != want:
        print("client that stays: got %r" % d)
        return 1
    if d is not None:
        try:
            d = stay.recv(65536)
        except socket.timeout:
            d = None
        if d is not None:
            print("client that stays: got %r after the method reply" % d)
            return 1
    stay.close()
    print("OK %.1f s" % took)
    return 0


if __name__ == "__main__":
    sys.exit(main())

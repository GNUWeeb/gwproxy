#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client that makes the proxy's engine queue more for it than its
# socket can take, by asking for KeyUpdates without reading the answers,
# and sends a request the proxy refuses along with them. The failure reply
# then sits behind the answers, and the proxy cannot send it in one go: it
# has to keep the connection until the client reads, and then deliver every
# answer, the reply and its close_notify, before it closes.
#
# Usage: tls_fail_reply_unread.py <proxy_port> <target> <status> [<wait>]
#
# <target> is the authority of the CONNECT ("127.0.0.1:9", say), <status>
# the reply the proxy must give ("407", "502", "504"), and <wait> how long
# to leave the answers unread once the request is out, in seconds (default
# 1): long enough for the proxy to have given its reply, and well within
# the time it holds on to the pair for that reply to be taken.
#
# With "-" as <status>, the client prints "SENT" once the request is out
# and reads nothing for <wait> seconds, longer than the proxy may hold on
# to it: by then the proxy must have closed the connection, and the client
# must find it closed, without the reply having come whole.
#
# Prints "ok", or what went wrong. Exits 77 if the OpenSSL library cannot
# be used this way.

import os
import select
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tls_keyupdate_client import (  # noqa: E402
    LIB, Client, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE)

SSL_ERROR_ZERO_RETURN = 6
# OpenSSL allows 32 KeyUpdates without data in between: one request byte
# goes after every UPDATES_PER_BYTE of them.
UPDATES_PER_BYTE = 20
# Answers of 27 bytes each: about 135 KiB, several times what the socket
# takes with the client's small receive buffer and segment size, and below
# what the proxy queues for a client before it stops reading it (some
# 200 KiB at the default --target-buf-size).
NR_UPDATES = 5000
# The client's receive and send buffers, and its segment size, which keeps
# the proxy's send buffer from growing to megabytes on loopback.
RCVBUF = 4096
MSS = 1000
DEADLINE = 60


def push(c, data):
    """Send @data (or the pending KeyUpdate if None) on the non-blocking
    socket, waiting for room as long as it takes."""
    end = time.monotonic() + DEADLINE
    while True:
        if data is None:
            r = LIB.SSL_do_handshake(c.ssl)
        else:
            r = LIB.SSL_write(c.ssl, data, len(data))
        if r == 1 or (data is not None and r == len(data)):
            return
        if LIB.SSL_get_error(c.ssl, r) != SSL_ERROR_WANT_WRITE:
            raise RuntimeError("could not send to the proxy")
        if time.monotonic() > end:
            raise RuntimeError("the proxy stopped reading the request")
        select.select([], [c.s], [], 0.1)


def run(port, target, status, wait):
    c = Client(port, rcvbuf=RCVBUF, mss=MSS)
    c.s.setblocking(False)
    # The session tickets: out of the way, so that what is left unread is
    # the answers.
    c.drain(0.5)

    req = (b"CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Pad: %s\r\n\r\n" %
           (target.encode(), target.encode(),
            b"p" * (NR_UPDATES // UPDATES_PER_BYTE)))
    updates = 0
    for i in range(len(req)):
        for _ in range(UPDATES_PER_BYTE):
            if updates >= NR_UPDATES:
                break
            c.key_update()
            push(c, None)
            updates += 1
        push(c, req[i:i + 1])

    if status == "-":
        print("SENT", flush=True)
    time.sleep(wait)

    got = b""
    end = time.monotonic() + DEADLINE
    while True:
        if time.monotonic() > end:
            return "no end after %d s, got %r" % (DEADLINE, got[:200])
        n = LIB.SSL_read(c.ssl, c.buf, len(c.buf))
        if n > 0:
            got += c.buf.raw[:n]
            continue
        e = LIB.SSL_get_error(c.ssl, n)
        if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
            select.select([c.s], [], [], 0.5)
            continue
        break

    if status == "-":
        if e == SSL_ERROR_ZERO_RETURN:
            return "the reply came whole after %g s unread: %r" % (
                wait, got[:200])
        return None

    want = b"HTTP/1.1 %s " % status.encode()
    if not got.startswith(want):
        return "expected %r, got %r (SSL error %d)" % (want, got[:200], e)
    if e != SSL_ERROR_ZERO_RETURN:
        return "the %s came without a close_notify (SSL error %d)" % (
            status, e)
    return None


def main():
    port, target, status = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    wait = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
    try:
        err = run(port, target, status, wait)
    except (RuntimeError, OSError) as e:
        err = repr(e)
    print(err or "ok")


if __name__ == "__main__":
    main()

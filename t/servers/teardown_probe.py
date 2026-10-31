# SPDX-License-Identifier: GPL-2.0-only
#
# Drive plain forwarded connections to their end in the ways a pair is torn
# down, and check what each peer sees and that the proxy lets go of the
# pair's descriptors.
#
# Usage: teardown_probe.py <proxy-port> <target-port> <proxy-pid> <rounds>
#
# The helper is the target itself (listening on <target-port>), so it
# controls both ends. Per round it runs:
#
#   client-first   The client sends a request and half-closes. The target
#                  must see the request and then EOF while the client still
#                  reads, then answers with a large reply and closes. The
#                  client must get the whole reply and a clean EOF.
#   target-first   The target sends a large reply and half-closes. The
#                  client must get all of it and EOF, then uploads a large
#                  body and half-closes; the target must get all of it and
#                  a clean EOF.
#   client-reset   The client resets the connection (SO_LINGER 0) while the
#                  proxy has a recv armed on both sockets. The target must
#                  see its side end.
#   target-reset   The same with the target resetting; the client must see
#                  its side end.
#
# A clean EOF is recv() returning b"": a proxy that closed a socket with
# unread data would send an RST, which shows up as ECONNRESET instead.
# Afterwards the proxy's descriptor count must come back to where it was
# before the rounds, so no pair was left waiting on a request that nothing
# cancels. Prints "OK ..." or "FAIL: ..." and exits 0 or 1.

import os
import socket
import struct
import sys
import threading
import time

TMO = 10
BIG = 300000


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def nr_fds(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def payload(n, seed):
    b = bytes((i * 7 + seed) & 0xff for i in range(256))
    return (b * (n // 256 + 1))[:n]


def read_all(s, what):
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except ConnectionResetError:
            fail("%s: connection reset after %d bytes, expected a clean EOF"
                 % (what, len(data)))
        except socket.timeout:
            fail("%s: no EOF within %ds (%d bytes read)"
                 % (what, TMO, len(data)))
        if not chunk:
            return data
        data += chunk


def send_bg(s, data, then):
    # Send from a thread: the reader is this thread, and a large send
    # would otherwise fill every buffer on the way and block for good.
    def run():
        try:
            s.sendall(data)
            then()
        except OSError:
            pass
    th = threading.Thread(target=run)
    th.start()
    return th


def pair(lsn, pport):
    c = socket.create_connection(("127.0.0.1", pport), timeout=TMO)
    c.settimeout(TMO)
    try:
        t, _ = lsn.accept()
    except socket.timeout:
        fail("the proxy did not connect to the target")
    t.settimeout(TMO)
    return c, t


def reset(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def ends(s, what):
    # The peer's side must end: EOF or a reset, but not a hang.
    try:
        while s.recv(65536):
            pass
    except ConnectionResetError:
        pass
    except socket.timeout:
        fail("%s: the proxy kept the connection open after its peer reset"
             % what)


def client_first(lsn, pport, i):
    c, t = pair(lsn, pport)
    req = payload(1000, i)
    c.sendall(req)
    c.shutdown(socket.SHUT_WR)
    got = read_all(t, "client-first: target reading the request")
    if got != req:
        fail("client-first: target got %d of %d request bytes"
             % (len(got), len(req)))
    rep = payload(BIG, i + 1)
    th = send_bg(t, rep, t.close)
    got = read_all(c, "client-first: client reading the reply")
    th.join()
    if got != rep:
        fail("client-first: client got %d of %d reply bytes"
             % (len(got), len(rep)))
    c.close()


def target_first(lsn, pport, i):
    c, t = pair(lsn, pport)
    rep = payload(BIG, i + 2)
    th = send_bg(t, rep, lambda: t.shutdown(socket.SHUT_WR))
    got = read_all(c, "target-first: client reading the reply")
    th.join()
    if got != rep:
        fail("target-first: client got %d of %d reply bytes"
             % (len(got), len(rep)))
    up = payload(BIG, i + 3)
    th = send_bg(c, up, lambda: c.shutdown(socket.SHUT_WR))
    got = read_all(t, "target-first: target reading the upload")
    th.join()
    if got != up:
        fail("target-first: target got %d of %d upload bytes"
             % (len(got), len(up)))
    t.close()
    c.close()


def client_reset(lsn, pport, i):
    c, t = pair(lsn, pport)
    # One exchange first, so the proxy is past the connect and has a recv
    # armed on both sockets.
    c.sendall(b"ping")
    if t.recv(4) != b"ping":
        fail("client-reset: target did not get the request")
    t.sendall(b"pong")
    if c.recv(4) != b"pong":
        fail("client-reset: client did not get the reply")
    reset(c)
    ends(t, "client-reset")
    t.close()


def target_reset(lsn, pport, i):
    c, t = pair(lsn, pport)
    c.sendall(b"ping")
    if t.recv(4) != b"ping":
        fail("target-reset: target did not get the request")
    t.sendall(b"pong")
    if c.recv(4) != b"pong":
        fail("target-reset: client did not get the reply")
    reset(t)
    ends(c, "target-reset")
    c.close()


def main():
    pport, tport, pid, rounds = (int(a) for a in sys.argv[1:5])

    lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("127.0.0.1", tport))
    lsn.listen(64)
    lsn.settimeout(TMO)

    # Warm up: the first connection may make the proxy open descriptors
    # it keeps (an io-wq worker's, the log's), which are not leaks.
    client_first(lsn, pport, 0)
    time.sleep(0.2)
    base = nr_fds(pid)

    for i in range(rounds):
        client_first(lsn, pport, i)
        target_first(lsn, pport, i)
        client_reset(lsn, pport, i)
        target_reset(lsn, pport, i)

    deadline = time.time() + TMO
    while True:
        n = nr_fds(pid)
        if n <= base:
            break
        if time.time() > deadline:
            fail("the proxy holds %d descriptors after %d rounds, %d before"
                 % (n, rounds, base))
        time.sleep(0.05)

    print("OK %d rounds of 4 teardowns, %d descriptors before and after"
          % (rounds, base))


if __name__ == "__main__":
    main()

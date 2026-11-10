# SPDX-License-Identifier: GPL-2.0-only
#
# Peers for the tests of how a connection pair ends (t/0270-0279): what the
# survivor of a reset gets, and how it ends.
#
# Usage:
#   pair_end.py send-error <mode> <dir> <proxy_port> <proxy_pid> <target_port>
#
# <mode> is how the client reaches the target listening on <target_port>:
# plain (the proxy runs with --target pointing there), socks5 or http (a
# CONNECT tunnel).
#
# "send-error": the peer named by <dir> (tgt or cli) sends until every buffer
# on its way to the other one, which does not read, is full, and resets. The
# other one then sends a few bytes, which the proxy fails to pass on to the
# reset peer, and reads: it must get every byte the proxy acknowledged, then
# an end of stream (EOF or a reset).
#
# Prints "ok", or one line per problem.

import fcntl
import os
import socket
import struct
import sys
import time

TIMEOUT = 30
SIOCOUTQ = 0x5411
errors = []


def payload(n, off=0):
    """
    Bytes @off to @off + @n of a stream of numbered lines: a lost or misplaced
    part shows.
    """
    first = off // 9
    blob = b"".join(b"%08d\n" % i
                    for i in range(first, (off + n) // 9 + 1))
    return blob[off - first * 9:off - first * 9 + n]


def outq(s):
    return struct.unpack("i", fcntl.ioctl(s.fileno(), SIOCOUTQ, b"\0" * 4))[0]


def rst(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            break
        buf += d
    return buf


def read_all(s):
    """Read until the end; return (data, how it ended)."""
    s.settimeout(TIMEOUT)
    buf = bytearray()
    while True:
        try:
            d = s.recv(65536)
        except ConnectionResetError:
            return bytes(buf), "rst"
        except socket.timeout:
            return bytes(buf), "timeout"
        if not d:
            return bytes(buf), "eof"
        buf += d


def listener(port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(8)
    ls.settimeout(TIMEOUT)
    return ls


def open_tunnel(mode, pport, ls, tport):
    """Connect a client through the proxy; return (client, target)."""
    c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
    c.settimeout(TIMEOUT)
    if mode == "socks5":
        c.sendall(b"\x05\x01\x00")
        if recv_exact(c, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting refused")
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                  struct.pack("!H", tport))
        rep = recv_exact(c, 10)
        if len(rep) != 10 or rep[1] != 0:
            raise RuntimeError("SOCKS5 CONNECT failed: %r" % rep)
    elif mode == "http":
        c.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" % tport)
        hdr = b""
        while b"\r\n\r\n" not in hdr:
            d = c.recv(1)
            if not d:
                raise RuntimeError("no CONNECT reply: %r" % hdr)
            hdr += d
        if not hdr.startswith(b"HTTP/1.1 200"):
            raise RuntimeError("CONNECT failed: %r" % hdr)
    t, _ = ls.accept()
    t.settimeout(TIMEOUT)
    # One byte each way, so the tunnel is up at the proxy, not only here.
    c.sendall(b"P")
    if recv_exact(t, 1) != b"P":
        raise RuntimeError("ping to the target lost")
    t.sendall(b"Q")
    if recv_exact(c, 1) != b"Q":
        raise RuntimeError("ping to the client lost")
    return c, t


def fill(snd):
    """
    Send from @snd until nothing has moved for a while, so that every queue
    on the way is full, and the send queue no longer shrinks. Returns (data,
    acked): what the proxy's kernel acknowledged, which the reset cannot take
    back. None if the proxy never stopped taking data.
    """
    snd.setblocking(False)
    sent = 0
    idle_since = time.monotonic()
    end = idle_since + TIMEOUT
    chunk = b""
    while time.monotonic() - idle_since < 0.5:
        # Socket buffers grow to tens of MB each on some hosts.
        if time.monotonic() > end or sent >= 1 << 29:
            return None
        if not chunk:
            chunk = payload(65536, sent)
        try:
            n = snd.send(chunk)
        except BlockingIOError:
            n = 0
        chunk = chunk[n:]
        if n:
            sent += n
            idle_since = time.monotonic()
        else:
            time.sleep(0.01)
    q = outq(snd)
    while True:
        time.sleep(0.2)
        q2 = outq(snd)
        if q2 == q:
            break
        q = q2
    return payload(sent - q), sent - q


def send_error(mode, d, pport, pid, tport):
    ls = listener(tport)
    c, t = open_tunnel(mode, pport, ls, tport)
    snd, rcv = (t, c) if d == "tgt" else (c, t)
    rcv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    r = fill(snd)
    if r is None:
        errors.append("%s %s: the proxy never stopped taking data" % (mode, d))
        return
    data, acked = r
    rst(snd)
    time.sleep(0.2)
    # The proxy reads these and fails to send them to the reset peer.
    rcv.sendall(b"x" * 10)
    time.sleep(0.3)
    got, how = read_all(rcv)
    rcv.close()
    ls.close()
    if got != data[:acked]:
        errors.append("%s %s: the proxy took %d bytes, the other side got "
                      "%d%s, then %s" %
                      (mode, d, acked, len(got),
                       "" if got == data[:len(got)] else " (corrupt)", how))
    elif how == "timeout":
        errors.append("%s %s: no end after the data" % (mode, d))


def main():
    a = sys.argv[1:]
    if a[0] == "send-error":
        send_error(a[1], a[2], int(a[3]), int(a[4]), int(a[5]))
    else:
        raise SystemExit("unknown case %r" % a[0])
    print("\n".join(errors) if errors else "ok")


if __name__ == "__main__":
    main()

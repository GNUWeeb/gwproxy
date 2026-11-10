# SPDX-License-Identifier: GPL-2.0-only
#
# Peers for the tests of how a connection pair ends (t/0270-0279): what the
# survivor of a reset gets, and how it ends.
#
# Usage:
#   pair_end.py send-error <mode> <dir> <proxy_port> <proxy_pid> <target_port>
#   pair_end.py origin-reset <how> <proxy_port> <origin_port> [<rounds>]
#   pair_end.py fail-reply <how> <bytes> <proxy_port> <target_port>
#   pair_end.py linger-load <clients> <proxy_port> <proxy_pid>
#   pair_end.py two-way <mode> <proxy_port> <target_port> <ends>
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
# "origin-reset": an HTTP forwarding request ("GET http://...") to an origin
# that ends before a complete response header, as <how> says: "rst" reads the
# request and resets, "part-rst" sends part of a header and resets,
# "accept-rst" resets right after the accept, unread, and "part-fin" sends
# part of a header and closes (the control). The client must get a 502 every
# time.
#
# "fail-reply": the proxy refuses a request after the client sent <bytes>
# more behind it, which the proxy may not have read: "s5-late" and
# "http-late" send a SOCKS5 or HTTP CONNECT to <target_port>, where nothing
# answers the SYN, and the rest 0.3 s later, before --connect-timeout
# expires; "http-upload" sends a forwarding POST with a body of <bytes> to a
# proxy that wants credentials. The client must read its failure reply (REP
# 0x06, 504, 407) and then an EOF, not a reset.
#
# "two-way": the client uploads into the target, which does not read, while
# the target sends into the client, which does not read either, until every
# buffer is full; then the target resets, the client stops uploading and
# reads. It must get every byte the proxy acknowledged from the target, then
# an end in <ends> (a comma-separated list of eof and rst).
#
# "linger-load": <clients> clients send a forwarding POST to a proxy that
# wants credentials, and keep sending the body for 4 s, a little at a time,
# while they read. Each must get its 407 and an EOF; the proxy must hold
# their sockets while they send, at most for its 2 s bound, and then be back
# at the descriptors it had before, without having used much CPU, and use
# none once they are gone.
#
# Prints "ok", or one line per problem.

import fcntl
import os
import select
import socket
import struct
import sys
import threading
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


def origin(ls, how, rounds):
    for _ in range(rounds):
        try:
            t, _ = ls.accept()
        except OSError:
            return
        t.settimeout(TIMEOUT)
        try:
            if how != "accept-rst":
                req = b""
                while b"\r\n\r\n" not in req:
                    d = t.recv(4096)
                    if not d:
                        break
                    req += d
            if how.startswith("part"):
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Le")
                time.sleep(0.05)
        except OSError:
            pass
        if how.endswith("rst"):
            rst(t)
        else:
            t.close()


def origin_reset(how, pport, oport, rounds):
    ls = listener(oport)
    th = threading.Thread(target=origin, args=(ls, how, rounds), daemon=True)
    th.start()
    for i in range(rounds):
        c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
        c.sendall(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\n"
                  b"Host: 127.0.0.1:%d\r\n\r\n" % (oport, oport))
        got, end = read_all(c)
        c.close()
        if not got.startswith(b"HTTP/1.1 502 "):
            errors.append("%s round %d: %r, then %s" %
                          (how, i, got[:40], end))
    th.join(TIMEOUT)
    ls.close()


def fail_reply(how, n, pport, tport):
    c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
    c.settimeout(TIMEOUT)
    late = payload(n)
    if how == "s5-late":
        c.sendall(b"\x05\x01\x00\x05\x01\x00\x01" +
                  socket.inet_aton("127.0.0.1") + struct.pack("!H", tport))
        if recv_exact(c, 2) != b"\x05\x00":
            errors.append("%s: no method reply" % how)
            return
        want = b"\x05\x06"
    elif how == "http-late":
        c.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" %
                  tport)
        want = b"HTTP/1.1 504 "
    else:
        late = (b"POST http://127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n"
                b"Content-Length: %d\r\n\r\n" % (tport, n)) + late
        want = b"HTTP/1.1 407 "

    def send_late():
        if how != "http-upload":
            time.sleep(0.3)
        try:
            c.sendall(late)
        except OSError:
            pass

    th = threading.Thread(target=send_late, daemon=True)
    th.start()
    got, end = read_all(c)
    th.join(TIMEOUT)
    c.close()
    if not got.startswith(want):
        errors.append("%s %d: got %r, then %s" % (how, n, got[:40], end))
    elif end != "eof":
        errors.append("%s %d: the reply, then %s instead of an EOF" %
                      (how, n, end))


def two_way(mode, pport, tport, want):
    ls = listener(tport)
    c, t = open_tunnel(mode, pport, ls, tport)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    stop = threading.Event()

    def upload():
        blob = b"u" * 16384
        while not stop.is_set():
            try:
                _, w, _ = select.select([], [c], [], 0.05)
                if w:
                    c.send(blob)
            except OSError:
                return

    th = threading.Thread(target=upload, daemon=True)
    th.start()
    r = fill(t)
    if r is None:
        stop.set()
        errors.append("two-way %s: the proxy never stopped taking data" %
                      mode)
        return
    data, acked = r
    rst(t)
    time.sleep(0.5)
    stop.set()
    th.join(TIMEOUT)
    got, how = read_all(c)
    c.close()
    ls.close()
    if got != data[:acked]:
        errors.append("two-way %s: the proxy took %d bytes, the client got "
                      "%d%s, then %s" %
                      (mode, acked, len(got),
                       "" if got == data[:len(got)] else " (corrupt)", how))
    elif how not in want:
        errors.append("two-way %s: all the data, then %s" % (mode, how))


def nfds(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def cpu(pid):
    with open("/proc/%d/stat" % pid) as f:
        st = f.read().rsplit(")", 1)[1].split()
    return (int(st[11]) + int(st[12])) / os.sysconf("SC_CLK_TCK")


def linger_load(n, pport, pid):
    fds0, cpu0 = nfds(pid), cpu(pid)
    hdr = (b"POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n"
           b"Content-Length: 1000000000\r\n\r\n")
    socks, got, ends = [], [], []
    for _ in range(n):
        c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
        c.sendall(hdr)
        c.setblocking(False)
        socks.append(c)
        got.append(b"")
        ends.append(None)
    peak = 0
    t0 = time.monotonic()
    while time.monotonic() - t0 < 4:
        for i, c in enumerate(socks):
            try:
                c.send(b"x" * 512)
            except OSError:
                pass
            while ends[i] is None:
                try:
                    d = c.recv(65536)
                except BlockingIOError:
                    break
                except ConnectionResetError:
                    ends[i] = "rst"
                    break
                if not d:
                    ends[i] = "eof"
                    break
                got[i] += d
        peak = max(peak, nfds(pid))
        time.sleep(0.05)
    fds1, cpu1 = nfds(pid), cpu(pid)
    for c in socks:
        c.close()
    time.sleep(1)
    cpu2 = cpu(pid)

    bad = [i for i in range(n)
           if not got[i].startswith(b"HTTP/1.1 407 ") or ends[i] != "eof"]
    if bad:
        i = bad[0]
        errors.append("%d of %d clients did not get a 407 and an EOF; "
                      "client %d: %r, then %s" %
                      (len(bad), n, i, got[i][:40], ends[i]))
    if peak < fds0 + n // 2:
        errors.append("the proxy held %d descriptors at most, %d before: "
                      "no lingering close" % (peak, fds0))
    if fds1 > fds0:
        errors.append("the proxy holds %d descriptors after the bound, %d "
                      "before" % (fds1, fds0))
    if cpu1 - cpu0 > 1.0:
        errors.append("the proxy used %.2f s of CPU in 4 s" % (cpu1 - cpu0))
    if cpu2 - cpu1 > 0.2:
        errors.append("the proxy used %.2f s of CPU in 1 s idle" %
                      (cpu2 - cpu1))


def main():
    a = sys.argv[1:]
    if a[0] == "send-error":
        send_error(a[1], a[2], int(a[3]), int(a[4]), int(a[5]))
    elif a[0] == "fail-reply":
        fail_reply(a[1], int(a[2]), int(a[3]), int(a[4]))
    elif a[0] == "two-way":
        two_way(a[1], int(a[2]), int(a[3]), a[4].split(","))
    elif a[0] == "linger-load":
        linger_load(int(a[1]), int(a[2]), int(a[3]))
    elif a[0] == "origin-reset":
        origin_reset(a[1], int(a[2]), int(a[3]),
                     int(a[4]) if len(a) > 4 else 10)
    else:
        raise SystemExit("unknown case %r" % a[0])
    print("\n".join(errors) if errors else "ok")


if __name__ == "__main__":
    main()

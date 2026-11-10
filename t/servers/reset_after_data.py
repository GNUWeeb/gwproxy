# SPDX-License-Identifier: GPL-2.0-only
#
# Peers that send data and then reset the connection, for t/0220. Everything a
# peer sent before its reset that the proxy's kernel acknowledged must reach
# the other side, followed by an end of stream (EOF or a reset).
#
# Usage:
#   reset_after_data.py stopped <mode> <dir> <proxy_port> <proxy_pid> \
#       <target_port> [<bytes> [<rounds>]]
#   reset_after_data.py slow <mode> <proxy_port> <proxy_pid> <target_port>
#
# <mode> is how the client reaches the target listening on <target_port>:
# plain (the proxy runs with --target pointing there), socks5 or http (a
# CONNECT tunnel).
#
# "stopped": the proxy is stopped (SIGSTOP) while the peer named by <dir>
# (tgt or cli) sends <bytes> and resets, once its kernel has had every byte
# acknowledged; then it is continued. The data and the reset are both waiting
# in the proxy's socket when it looks at it again, however fast the machine.
#
# "slow": the client does not read. The target sends until the proxy's buffers
# and every socket queue on the way are full, and resets. The proxy must then
# use no CPU (it has nothing to do until the client reads), and the client
# must get every byte the proxy acknowledged once it reads.
#
# Prints "ok", or one line per problem.

import fcntl
import os
import signal
import socket
import struct
import sys
import time

TIMEOUT = 30
SIOCOUTQ = 0x5411
errors = []


def payload(n, seed=0):
    """@n bytes of numbered lines: a lost or misplaced part shows."""
    return b"".join(b"%08d\n" % i
                    for i in range(seed, seed + n // 9 + 1))[:n]


def tcp_buf_max(name):
    """The largest size TCP autotuning may grow a socket buffer to."""
    try:
        with open("/proc/sys/net/ipv4/" + name) as f:
            return int(f.read().split()[2])
    except (OSError, ValueError, IndexError):
        return 32 << 20


def outq(s):
    return struct.unpack("i", fcntl.ioctl(s.fileno(), SIOCOUTQ, b"\0" * 4))[0]


def wait_outq_empty(s):
    end = time.monotonic() + TIMEOUT
    while outq(s):
        if time.monotonic() > end:
            return False
        time.sleep(0.005)
    return True


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


def stopped(mode, d, pport, pid, tport, n, rounds):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", tport))
    ls.listen(8)
    ls.settimeout(TIMEOUT)
    for r in range(rounds):
        data = payload(n, r * n)
        c, t = open_tunnel(mode, pport, ls, tport)
        snd, rcv = (t, c) if d == "tgt" else (c, t)
        os.kill(pid, signal.SIGSTOP)
        try:
            snd.sendall(data)
            acked = wait_outq_empty(snd)
            rst(snd)
            time.sleep(0.1)
        finally:
            os.kill(pid, signal.SIGCONT)
        got, end = read_all(rcv)
        rcv.close()
        if not acked:
            errors.append("%s %s round %d: the proxy did not take the data"
                          % (mode, d, r))
        elif got != data:
            errors.append("%s %s round %d: got %d of %d bytes%s, then %s" %
                          (mode, d, r, len(got), n,
                           "" if got == data[:len(got)] else " (corrupt)",
                           end))
        elif end == "timeout":
            errors.append("%s %s round %d: no end after the data" %
                          (mode, d, r))
    ls.close()


def cpu(pid):
    with open("/proc/%d/stat" % pid) as f:
        st = f.read().rsplit(")", 1)[1].split()
    return (int(st[11]) + int(st[12])) / os.sysconf("SC_CLK_TCK")


def slow(mode, pport, pid, tport):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", tport))
    ls.listen(8)
    ls.settimeout(TIMEOUT)
    c, t = open_tunnel(mode, pport, ls, tport)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
    # More than the proxy's two sockets can ever queue: autotuning grows
    # them up to the tcp_rmem and tcp_wmem maxima (32 MiB each on some
    # hosts), and a payload they absorb whole never fills the queues.
    data = payload(tcp_buf_max("tcp_rmem") + tcp_buf_max("tcp_wmem") +
                   (16 << 20))
    t.setblocking(False)
    sent = 0
    # Until nothing has moved for a while: every queue on the way is full.
    idle_since = time.monotonic()
    end = idle_since + TIMEOUT
    while time.monotonic() - idle_since < 0.5:
        if time.monotonic() > end or sent >= len(data):
            errors.append("slow %s: the proxy never stopped taking data" %
                          mode)
            return
        try:
            n = t.send(data[sent:sent + 65536])
        except BlockingIOError:
            n = 0
        if n:
            sent += n
            idle_since = time.monotonic()
        else:
            time.sleep(0.01)
    # Stable once the send queue stops shrinking: what is left in it the
    # proxy has not acknowledged, and is lost with the reset.
    q = outq(t)
    while True:
        time.sleep(0.2)
        q2 = outq(t)
        if q2 == q:
            break
        q = q2
    acked = sent - q
    rst(t)
    time.sleep(0.3)
    c0 = cpu(pid)
    time.sleep(2)
    used = cpu(pid) - c0
    got, how = read_all(c)
    c.close()
    ls.close()
    if used > 0.5:
        errors.append("slow %s: the proxy used %.2f s of CPU in 2 s while "
                      "it waited for the client" % (mode, used))
    if got != data[:acked]:
        errors.append("slow %s: the proxy took %d bytes, the client got "
                      "%d%s, then %s" %
                      (mode, acked, len(got),
                       "" if got == data[:len(got)] else " (corrupt)", how))


def main():
    a = sys.argv[1:]
    if a[0] == "stopped":
        stopped(a[1], a[2], int(a[3]), int(a[4]), int(a[5]),
                int(a[6]) if len(a) > 6 else 30000,
                int(a[7]) if len(a) > 7 else 5)
    else:
        slow(a[1], int(a[2]), int(a[3]), int(a[4]))
    print("\n".join(errors) if errors else "ok")


if __name__ == "__main__":
    main()

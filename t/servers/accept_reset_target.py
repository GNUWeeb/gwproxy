# SPDX-License-Identifier: GPL-2.0-only
#
# A target that accepts, sends a short banner and resets at once, before the
# proxy has looked at its connect's result, for t/0223. The connect succeeded:
# the client must get a success reply and the banner, then an end of stream.
# For an HTTP forwarding request the "banner" is a whole response, which the
# client must get as the origin's answer.
#
# Usage: accept_reset_target.py <mode> <proxy_port> <proxy_pid> \
#     <target_port> [<rounds>]
#
# <mode> is how the client asks for the target: plain (the proxy runs with
# --target pointing at <target_port>), socks5, http (CONNECT) or fwd (an HTTP
# GET in absolute form).
#
# To have the proxy see the result only after the reset, whatever the timing:
# the target's accept queue is kept full (listen(0) and a connection that is
# not accepted), so the proxy's SYN is dropped and its connect stays pending.
# Once it is, the proxy is stopped (SIGSTOP), the queue is emptied, the SYN's
# retransmission is accepted, and the banner and the reset are sent. The proxy
# is then continued, with its connect complete and reset in one.
#
# Prints "ok", or one line per problem.

import os
import signal
import socket
import struct
import sys
import time

TIMEOUT = 30
BANNER = b"HELLO-BANNER\n"
RESPONSE = b"HTTP/1.1 503 Busy\r\nContent-Length: 4\r\n\r\nbusy"
errors = []


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            break
        buf += d
    return buf


def read_all(s):
    buf = b""
    while True:
        try:
            d = s.recv(4096)
        except ConnectionResetError:
            return buf, "rst"
        except socket.timeout:
            return buf, "timeout"
        if not d:
            return buf, "eof"
        buf += d


def syn_sent(port):
    """Whether a connect to 127.0.0.1:<port> waits for its SYN's answer."""
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(name) as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for ln in lines:
            fl = ln.split()
            if fl[3] == "02" and int(fl[2].rsplit(":", 1)[1], 16) == port:
                return True
    return False


def one(mode, pport, pid, ls, tport):
    filler = socket.create_connection(("127.0.0.1", tport), timeout=TIMEOUT)
    c = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
    c.settimeout(TIMEOUT)
    if mode == "socks5":
        c.sendall(b"\x05\x01\x00")
        if recv_exact(c, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 greeting refused")
        c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                  struct.pack("!H", tport))
    elif mode == "fwd":
        c.sendall(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n\r\n" %
                  tport)
    elif mode == "http":
        c.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" % tport)

    end = time.monotonic() + TIMEOUT
    while not syn_sent(tport):
        if time.monotonic() > end:
            raise RuntimeError("the proxy did not connect")
        time.sleep(0.005)

    os.kill(pid, signal.SIGSTOP)
    try:
        f, _ = ls.accept()
        f.close()
        filler.close()
        t, _ = ls.accept()	# the retransmitted SYN, a second later
        t.sendall(RESPONSE if mode == "fwd" else BANNER)
        t.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack("ii", 1, 0))
        t.close()
        time.sleep(0.1)
    finally:
        os.kill(pid, signal.SIGCONT)

    if mode == "socks5":
        rep = recv_exact(c, 10)
        if len(rep) != 10 or rep[1] != 0:
            errors.append("socks5: reply %r, not a success" % rep)
            return
    elif mode == "http":
        hdr = b""
        while b"\r\n\r\n" not in hdr:
            d = c.recv(1)
            if not d:
                break
            hdr += d
        if not hdr.startswith(b"HTTP/1.1 200"):
            errors.append("http: reply %r, not 200" %
                          hdr.split(b"\r\n", 1)[0])
            return
    got, how = read_all(c)
    c.close()
    if mode == "fwd":
        # The proxy adds its own Connection headers.
        if (not got.startswith(b"HTTP/1.1 503 Busy\r\n") or
                not got.endswith(b"\r\n\r\nbusy") or how == "timeout"):
            errors.append("fwd: got %r, then %s, not the origin's 503" %
                          (got, how))
        return
    if got != BANNER or how == "timeout":
        errors.append("%s: got %r, then %s, not the banner and an end" %
                      (mode, got, how))


def main():
    mode, pport, pid, tport = sys.argv[1], int(sys.argv[2]), \
        int(sys.argv[3]), int(sys.argv[4])
    rounds = int(sys.argv[5]) if len(sys.argv) > 5 else 3
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", tport))
    ls.listen(0)
    ls.settimeout(TIMEOUT)
    for _ in range(rounds):
        one(mode, pport, pid, ls, tport)
    ls.close()
    print("\n".join(errors) if errors else "ok")


if __name__ == "__main__":
    main()

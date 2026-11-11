# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client tunnels through SOCKS5 to a plaintext target that sends data
# and then ends the connection, for t/0224. Whatever the target sent reaches
# the client; how the target ended must show in how the TLS stream ends:
#
#   fin      the target closes normally: a close_notify, a clean end;
#   rst      the target resets: no close_notify, so the client can tell the
#            stream was cut (a TCP EOF without it, or a reset);
#   stopped  as rst, while the proxy is stopped (SIGSTOP), so that the data
#            and the reset both wait in the proxy's socket.
#
# Usage: tls_target_reset.py <proxy_port> <proxy_pid> [<bytes>]
# Prints "ok", or one line per problem.

import fcntl
import os
import signal
import socket
import ssl
import struct
import sys
import time

TIMEOUT = 30
SIOCOUTQ = 0x5411
errors = []


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            break
        buf += d
    return buf


def outq_empty(s):
    end = time.monotonic() + TIMEOUT
    while struct.unpack("i", fcntl.ioctl(s.fileno(), SIOCOUTQ,
                                         b"\0" * 4))[0]:
        if time.monotonic() > end:
            return False
        time.sleep(0.005)
    return True


def read_tls(c):
    got = 0
    while True:
        try:
            d = c.recv(65536)
        except ssl.SSLEOFError:
            return got, "cut"
        except ssl.SSLZeroReturnError:
            return got, "close_notify"
        except ConnectionResetError:
            return got, "cut"
        except socket.timeout:
            return got, "timeout"
        if not d:
            return got, "close_notify"
        got += len(d)


def one(pport, pid, how, n):
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ls.settimeout(TIMEOUT)
    tport = ls.getsockname()[1]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", pport), timeout=TIMEOUT)
    c = ctx.wrap_socket(raw, server_hostname="localhost",
                        suppress_ragged_eofs=False)
    c.sendall(b"\x05\x01\x00")
    if recv_exact(c, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 greeting refused")
    c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
              struct.pack("!H", tport))
    rep = recv_exact(c, 10)
    if len(rep) != 10 or rep[1] != 0:
        raise RuntimeError("SOCKS5 CONNECT failed: %r" % rep)
    t, _ = ls.accept()
    t.settimeout(TIMEOUT)
    ls.close()
    # A byte each way: the tunnel is up at the proxy too.
    c.sendall(b"P")
    if recv_exact(t, 1) != b"P":
        raise RuntimeError("ping to the target lost")

    # While it is stopped, the proxy's socket takes no more than its window.
    data = b"D" * (min(n, 30000) if how == "stopped" else n)
    if how == "stopped":
        os.kill(pid, signal.SIGSTOP)
    try:
        t.sendall(data)
        if how != "fin":
            if not outq_empty(t):
                errors.append("%s: the proxy did not take the data" % how)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
        t.close()
        if how == "stopped":
            time.sleep(0.1)
    finally:
        if how == "stopped":
            os.kill(pid, signal.SIGCONT)

    got, end = read_tls(c)
    c.close()
    want = "close_notify" if how == "fin" else "cut"
    if got != len(data) or end != want:
        errors.append("%s: the client got %d of %d bytes, then %s, not %s" %
                      (how, got, len(data), end, want))


def main():
    pport, pid = int(sys.argv[1]), int(sys.argv[2])
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
    for how in ("fin", "rst", "stopped", "stopped"):
        one(pport, pid, how, n)
    print("\n".join(errors) if errors else "ok")


if __name__ == "__main__":
    main()

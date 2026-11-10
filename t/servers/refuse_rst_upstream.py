# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that refuses every CONNECT and resets the connection right
# behind its refusal, for t/0222. Both arrive while the proxy in front of it
# is stopped (SIGSTOP), as when its worker is busy, so that the refusal and
# the reset wait in its socket together when it looks again.
#
# Usage: refuse_rst_upstream.py <kind> <port> <pid_file> <log> [<status>]
#
# <kind> is socks5 (it answers REP 0x05, connection refused) or http (it
# answers "HTTP/1.1 <status>", 403 Forbidden by default). The front proxy's
# pid is read from <pid_file> when the first request comes in. Each
# connection appends a line to <log>. Bound to 127.0.0.1.

import os
import signal
import socket
import struct
import sys
import time

TIMEOUT = 30
kind, port, pid_file, log = sys.argv[1], int(sys.argv[2]), sys.argv[3], \
    sys.argv[4]
status = sys.argv[5].encode() if len(sys.argv) > 5 else b"403 Forbidden"


def serve(c):
    pid = None
    try:
        c.settimeout(TIMEOUT)
        if kind == "socks5":
            c.recv(512)
            c.sendall(b"\x05\x00")
            c.recv(512)
            reply = b"\x05\x05\x00\x01" + b"\x00" * 6
        else:
            req = b""
            while b"\r\n\r\n" not in req:
                d = c.recv(4096)
                if not d:
                    return
                req += d
            reply = (b"HTTP/1.1 " + status +
                     b"\r\nContent-Length: 0\r\n\r\n")
        with open(pid_file) as f:
            pid = int(f.read())
        # The front proxy has sent its request and waits for the reply.
        os.kill(pid, signal.SIGSTOP)
        c.sendall(reply)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack("ii", 1, 0))
        c.close()
        time.sleep(0.05)
    except OSError:
        pass
    finally:
        if pid:
            os.kill(pid, signal.SIGCONT)


def main():
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(16)
    while True:
        c, _ = ls.accept()
        with open(log, "a") as f:
            f.write("conn\n")
        # One at a time: each stops the proxy around its own reply.
        serve(c)


if __name__ == "__main__":
    main()

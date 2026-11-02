# SPDX-License-Identifier: GPL-2.0-only
#
# TLS client for t/0137: sends records that the proxy has taken off the socket by
# the time it can do something with them, so that no further receive will bring
# them to its attention.
#
# Usage: tls_held_records.py upstream <http|socks5> <close_notify|exact_fill>
#                            <proxy_port> <upstream_port>
#
#   close_notify
#       Send a CONNECT and a close_notify in one go, and keep the connection
#       open. Once the tunnel through the upstream proxy is up, the end of the
#       stream must reach the far end, which only then answers.
#   exact_fill
#       Send a CONNECT that exactly fills a proxy's --client-buf-size=256 with
#       more records behind it, and nothing after that. Those must come through
#       the tunnel, which echoes them.
#
# Prints "ok" on success, or what went wrong.

import socket
import ssl
import sys
import threading

TIMEOUT = 20
CLIENT_BUF = 256


class Upstream:
    """An upstream proxy that then acts as the far end of the tunnel itself."""

    def __init__(self, kind, port, mode):
        self.kind, self.mode = kind, mode
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(1)
        self.ls.settimeout(TIMEOUT)
        self.err = None
        threading.Thread(target=self.run, daemon=True).start()

    def handshake(self, c):
        if self.kind == "http":
            b = b""
            while b"\r\n\r\n" not in b:
                d = c.recv(1)
                if not d:
                    raise RuntimeError("no end of the request")
                b += d
            c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            return
        g = self.recvn(c, 2)
        self.recvn(c, g[1])
        c.sendall(b"\x05\x00")
        h = self.recvn(c, 4)
        n = {1: 6, 4: 18}.get(h[3])
        if n is None:
            n = self.recvn(c, 1)[0] + 2
        self.recvn(c, n)
        c.sendall(b"\x05\x00\x00\x01\x7f\0\0\x01\0\x50")

    @staticmethod
    def recvn(c, n):
        b = b""
        while len(b) < n:
            d = c.recv(n - len(b))
            if not d:
                raise RuntimeError("short handshake")
            b += d
        return b

    def run(self):
        try:
            c, _ = self.ls.accept()
            c.settimeout(TIMEOUT * 2)
            self.handshake(c)
            while True:
                d = c.recv(65536)
                if not d:
                    break
                if self.mode == "exact_fill":
                    c.sendall(d)
            if self.mode == "close_notify":
                c.sendall(b"ANSWER")
            c.close()
        except (OSError, RuntimeError) as e:
            self.err = repr(e)


class Client:
    def __init__(self, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.inb, self.outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.o = ctx.wrap_bio(self.inb, self.outb)
        self.s = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            try:
                self.o.do_handshake()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.inb.write(self.s.recv(65536))
        self.flush()

    def flush(self):
        d = self.outb.read()
        if d:
            self.s.sendall(d)

    def close_notify(self):
        try:
            self.o.unwrap()
        except ssl.SSLWantReadError:
            pass

    def read_until(self, want):
        """Plaintext up to and including @want, or all there was by then."""
        got = b""
        try:
            while want not in got:
                d = self.s.recv(65536)
                if not d:
                    break
                self.inb.write(d)
                try:
                    while True:
                        p = self.o.read(65536)
                        if not p:
                            break
                        got += p
                except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                    pass
        except (socket.timeout, ConnectionError):
            pass
        return got


def connect_request(port, pad_to=None):
    req = "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n" % port
    if pad_to:
        req += "X-Pad: " + "a" * (pad_to - len(req) - len("X-Pad: \r\n\r\n"))
        req += "\r\n"
    return (req + "\r\n").encode()


def upstream(kind, mode, port, up_port):
    u = Upstream(kind, up_port, mode)
    c = Client(port)
    if mode == "close_notify":
        c.o.write(connect_request(1))
        c.close_notify()
        c.flush()
        want = b"ANSWER"
    else:
        c.o.write(connect_request(1, CLIENT_BUF))
        c.o.write(b"ping1")
        c.o.write(b"ping2")
        c.flush()
        want = b"ping1ping2"
    got = c.read_until(want)
    c.s.close()
    if u.err:
        return "upstream: " + u.err
    if want not in got:
        return "got only %r" % got
    return "ok"


def main():
    if sys.argv[1] == "upstream":
        print(upstream(sys.argv[2], sys.argv[3], int(sys.argv[4]),
                       int(sys.argv[5])))


if __name__ == "__main__":
    main()

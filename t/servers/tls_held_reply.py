# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS SOCKS5 client for t/0185 whose method reply is still being sent to it
# when the proxy's connect to its upstream completes, and the SOCKS5 upstream
# that connect goes to. The proxy must start the handshake with the upstream
# once the reply is out.
#
# Usage: tls_held_reply.py <proxy_port> <upstream_port> <rounds>
#
# The client asks for KeyUpdates, each of which the proxy's TLS engine answers
# with a record of its own, and reads none of them: the proxy's sending stalls,
# and with it its reading of the client. Behind those KeyUpdates come the last
# bytes of the greeting and a CONNECT to a name, so the proxy looks the name
# up, and more KeyUpdates (with a byte of data now and then, as OpenSSL wants),
# so the pass of the protocol that takes the CONNECT in also has many answers
# to send, ahead of the method reply. The client then reads slowly, a little at
# a time: the name resolves and the upstream is connected long before the
# reply has gone out.
#
# An HTTP client gets no reply before the connect, so its handshake with the
# upstream is not held up this way on io_uring, whose protocol pass leaves the
# answers to the tunnel: there is no HTTP variant.
#
# A round passes once the upstream got its greeting, the CONNECT and all the
# data. Nothing moving for STALL_SECS fails it. Rounds go on until one in
# which the reply held the handshake up (the client had to read for
# the greeting to reach the upstream), up to <rounds>.
#
# Prints "ok" if every round passed and one was held, "not held" if every one
# passed but none was, or what went wrong. Exits 77 if the OpenSSL library
# cannot be used this way.

import queue
import socket
import sys
import threading
import time

import tls_keyupdate_client as K

LIB = K.LIB
NAME = b"localhost"
TAIL = 150              # request bytes sent after the client stops reading
KU_PER_BYTE = 20        # OpenSSL allows 32 KeyUpdates without data in between
AFTER = 100             # bytes of data behind the CONNECT, each after KUs
TRICKLE = 128           # what the client reads at a time...
TRICKLE_GAP = 0.005     # ... and how long it waits in between
HELD_READ = 1024        # read between accept and greeting: the reply held it
STALL_SECS = 15         # nothing moved for this long: the pair is stuck


class Upstream:
    """A SOCKS5 server that takes any CONNECT and swallows what follows,
    noting when each connection was accepted and greeted, and how much the
    client had read by then."""

    def __init__(self, port):
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", port))
        self.ls.listen(8)
        self.conns = queue.Queue()
        self.read = 0           # what the client of the round has read
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            c, _ = self.ls.accept()
            st = {"accept_read": self.read, "greet_read": None, "data": 0,
                  "stage": "accepted"}
            self.conns.put(st)
            threading.Thread(target=self.serve, args=(c, st),
                             daemon=True).start()

    def recv_exact(self, c, n):
        got = b""
        while len(got) < n:
            d = c.recv(n - len(got))
            if not d:
                raise OSError("EOF")
            got += d
        return got

    def serve(self, c, st):
        try:
            g = self.recv_exact(c, 2)
            g += self.recv_exact(c, g[1])
            st["greet_read"] = self.read
            st["stage"] = "greeted"
            if g[0] != 5 or 0 not in g[2:]:
                st["stage"] = "bad greeting %r" % g
                return
            c.sendall(b"\x05\x00")
            r = self.recv_exact(c, 4)
            if r[3] == 1:
                self.recv_exact(c, 4 + 2)
            elif r[3] == 4:
                self.recv_exact(c, 16 + 2)
            else:
                st["stage"] = "bad CONNECT %r" % r
                return
            st["stage"] = "connected"
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            while True:
                d = c.recv(4096)
                if not d:
                    break
                st["data"] += len(d)
        except OSError:
            pass
        finally:
            c.close()


def ssl_write(ssl, data):
    if LIB.SSL_write(ssl, data, len(data)) != len(data):
        raise RuntimeError("SSL_write failed")


def key_updates(ssl):
    for _ in range(KU_PER_BYTE):
        if (LIB.SSL_key_update(ssl, K.SSL_KEY_UPDATE_REQUESTED) != 1 or
                LIB.SSL_do_handshake(ssl) != 1):
            raise RuntimeError("SSL_key_update failed")


def request():
    """The greeting, which offers every method ("no authentication" first),
    and the CONNECT."""
    return (bytes([5, 255]) + bytes(255) +
            bytes([5, 1, 0, 3, len(NAME)]) + NAME + (8080).to_bytes(2, "big"))


def one_round(port, up):
    s = socket.socket()
    # Small segments and a small window: what the proxy sends piles up in
    # its socket, and the client's slow reading frees little at a time.
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 536)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    # Room for all it sends: it does so before reading anything.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    s.connect(("127.0.0.1", port))
    ctx = LIB.SSL_CTX_new(LIB.TLS_client_method())
    LIB.SSL_CTX_ctrl(ctx, K.SSL_CTRL_SET_MIN_PROTO_VERSION, K.TLS1_3_VERSION,
                     None)
    ssl = LIB.SSL_new(ctx)
    LIB.SSL_set_fd(ssl, s.fileno())
    if LIB.SSL_connect(ssl) != 1:
        raise RuntimeError("TLS handshake failed")

    req = request()
    head = len(req) - TAIL
    up.read = 0
    ssl_write(ssl, req[:head])
    for i in range(head, len(req)):
        key_updates(ssl)
        ssl_write(ssl, req[i:i + 1])
    for _ in range(AFTER):
        key_updates(ssl)
        ssl_write(ssl, b"p")

    s.setblocking(False)
    st = None
    seen = None
    moved = time.monotonic()
    while True:
        try:
            d = s.recv(TRICKLE)
            if not d:
                raise RuntimeError("proxy hung up (upstream: %s)" %
                                   (st["stage"] if st else "not connected"))
            up.read += len(d)
        except BlockingIOError:
            pass
        if st is None and not up.conns.empty():
            st = up.conns.get()
        if st and st["data"] >= AFTER:
            break
        now = time.monotonic()
        state = (up.read, st and st["stage"], st and st["data"])
        if state != seen:
            seen, moved = state, now
        elif now - moved > STALL_SECS:
            raise RuntimeError(
                "stuck: client read %d, upstream %s, %d of %d data bytes" %
                (up.read, st["stage"] if st else "not connected",
                 st["data"] if st else 0, AFTER))
        time.sleep(TRICKLE_GAP)
    s.close()
    return st["greet_read"] - st["accept_read"] >= HELD_READ


def main():
    port, up_port, rounds = (int(a) for a in sys.argv[1:4])
    up = Upstream(up_port)
    try:
        for _ in range(rounds):
            if one_round(port, up):
                print("ok")
                return
        print("not held")
    except (RuntimeError, OSError) as e:
        print(repr(e))


if __name__ == "__main__":
    main()

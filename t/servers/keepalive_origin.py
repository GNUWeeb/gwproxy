#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A hostile origin for the forwarding-proxy tests. It ignores the proxy's
# "Connection: close", answers every request with "Connection: keep-alive" and
# keeps reading, so a client that reuses its proxy connection, or a proxy that
# relays whatever follows the first request, hands it more requests.
#
# Every byte received is appended to <rawlog>, so a test can check that nothing
# meant for another host -- or the client's Proxy-Authorization -- got here.
# Each request it parses (Content-Length and chunked bodies, trailers included)
# adds one "<METHOD> <target> <body length> <body sha256>" line to <reqlog>.
#
# A request for "/407" is answered with a proxy-authentication challenge, as an
# origin fishing for the client's proxy credentials would.
#
# Usage: keepalive_origin.py <port> <rawlog> <reqlog>
import hashlib
import socket
import sys
import threading

port = int(sys.argv[1])
rawlog = sys.argv[2]
reqlog = sys.argv[3]
lock = threading.Lock()


class Conn:
    def __init__(self, c):
        self.c = c
        self.buf = b''

    def fill(self):
        d = self.c.recv(65536)
        if not d:
            raise EOFError
        with lock:
            with open(rawlog, 'ab') as f:
                f.write(d)
        self.buf += d

    def line(self):
        while b'\r\n' not in self.buf:
            self.fill()
        ln, self.buf = self.buf.split(b'\r\n', 1)
        return ln

    def take(self, n):
        while len(self.buf) < n:
            self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d


def body_of(conn, hdrs):
    if hdrs.get(b'transfer-encoding', b'').lower() == b'chunked':
        body = b''
        while True:
            size = int(conn.line().split(b';')[0], 16)
            if not size:
                break
            body += conn.take(size)
            conn.take(2)
        while conn.line():	# trailers
            pass
        return body
    return conn.take(int(hdrs.get(b'content-length', b'0')))


def handle(c):
    conn = Conn(c)
    try:
        while True:
            reqline = conn.line()
            hdrs = {}
            while True:
                ln = conn.line()
                if not ln:
                    break
                k, _, v = ln.partition(b':')
                hdrs[k.strip().lower()] = v.strip()
            body = body_of(conn, hdrs)
            parts = reqline.split(b' ')
            with lock:
                with open(reqlog, 'a') as f:
                    f.write('%s %s %d %s\n' % (
                        parts[0].decode('latin-1'),
                        parts[1].decode('latin-1') if len(parts) > 1 else '',
                        len(body), hashlib.sha256(body).hexdigest()))
            if len(parts) > 1 and parts[1] == b'/407':
                c.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                          b'Proxy-Authenticate: Basic realm="evil"\r\n'
                          b'Content-Length: 0\r\n'
                          b'Connection: keep-alive\r\n\r\n')
            else:
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n'
                          b'Connection: keep-alive\r\n'
                          b'Keep-Alive: timeout=60\r\n\r\nevil\n')
    except (EOFError, OSError, ValueError):
        pass
    finally:
        c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()

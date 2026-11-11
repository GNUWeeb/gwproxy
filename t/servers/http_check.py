# SPDX-License-Identifier: GPL-2.0-only
#
# Helpers for the HTTP proxy tests, imported by their drivers: an origin on
# loopback that records every request that reaches it and answers as it is
# told, and a client that sends one request through the proxy and returns
# everything the proxy says until it closes.
#
#   sys.path.insert(0, servers_dir); import http_check
#   o = http_check.Origin(reply)	# reply: bytes, or f(request) -> bytes
#   r = http_check.xact(proxy_port, b'GET http://127.0.0.1:%d/ ...' % o.port)
#   http_check.status(r)		# 'HTTP/1.1 200 OK', or 'CLOSED'
import socket
import threading
import time


def framed(buf):
    """Whether @buf holds a whole request, by the rules of a plain origin."""
    head, sep, rest = buf.partition(b'\r\n\r\n')
    if not sep:
        return False
    for line in head.split(b'\r\n')[1:]:
        name, _, val = line.partition(b':')
        if name.strip().lower() == b'content-length':
            try:
                return len(rest) >= int(val)
            except ValueError:
                return True
        if name.strip().lower() == b'transfer-encoding':
            return rest.endswith(b'0\r\n\r\n')
    return True


class Origin:
    """Records each request (all bytes its connection sent) in .reqs, in
    the order the connections end, and answers with @reply."""

    def __init__(self, reply=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                 b'Connection: close\r\n\r\nok'):
        self.reply = reply
        self.lock = threading.Lock()
        self.reqs = []
        self.conns = 0
        self.ls = socket.socket()
        self.ls.bind(('127.0.0.1', 0))
        self.ls.listen(64)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            c, _ = self.ls.accept()
            with self.lock:
                self.conns += 1
            threading.Thread(target=self._conn, args=(c,),
                             daemon=True).start()

    def _conn(self, c):
        buf = b''
        c.settimeout(10)
        try:
            while not framed(buf):
                d = c.recv(65536)
                if not d:
                    break
                buf += d
            r = self.reply(buf) if callable(self.reply) else self.reply
            c.sendall(r)
            # Anything behind the request would be the client's next one.
            c.settimeout(0.2)
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
        except OSError:
            pass
        c.close()
        with self.lock:
            self.reqs.append(buf)

    def count(self):
        with self.lock:
            return self.conns

    def nr_reqs(self):
        with self.lock:
            return len(self.reqs)

    def wait(self, n, limit=20):
        """Wait until @n requests are recorded; return request n - 1."""
        end = time.monotonic() + limit
        while time.monotonic() < end:
            with self.lock:
                if len(self.reqs) >= n:
                    return self.reqs[n - 1]
            time.sleep(0.02)
        return None


def xact(port, data, limit=20):
    """Send @data to the proxy; return all it says until it closes."""
    s = socket.create_connection(('127.0.0.1', port))
    s.settimeout(limit)
    r = b''
    try:
        s.sendall(data)
        while True:
            d = s.recv(65536)
            if not d:
                break
            r += d
    except OSError:
        pass
    s.close()
    return r


def status(reply):
    """The status line of @reply, or CLOSED if the proxy said nothing."""
    return reply.split(b'\r\n', 1)[0].decode('latin-1') or 'CLOSED'

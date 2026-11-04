#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An https:// upstream proxy for the upstream TLS tests: HTTP CONNECT spoken
# over TLS, which records what it sees so a test can tell what gwproxy sent,
# and when.
#
#   tls_upstream.py server <cert> <key> <port> <log> [user:pass]
#       Listen on <port> on every loopback address "localhost" has, with the
#       certificate chain <cert> and key <key>. Per connection it appends to
#       <log>:
#           "hs-ok sni=<name>" ("sni=-" without SNI) once the handshake is done
#           "hs-fail <reason>" when it is not
#           "connect <authority> auth=<Proxy-Authorization value or ->"
#       and keeps every byte as it came in: the TCP stream (ciphertext) in
#       <log>.raw, what TLS decrypted of it in <log>.plain. With user:pass, a
#       CONNECT without those Basic credentials is answered 407. CONNECT to
#       echo.invalid:7 echoes the tunnel back; to junk.invalid:80 answers a
#       request with a response header that never ends, 1 MB of it, and
#       closes; anything else is connected to.
#
#   tls_upstream.py echo <socks5|http> <proxy_port> <nbytes>
#       Through the gwproxy front at 127.0.0.1:<proxy_port>, tunnel to
#       echo.invalid:7, send <nbytes> bytes while reading the echo, and check
#       every byte comes back in order before a clean end of stream.
#
#   tls_upstream.py socks5-rep <proxy_port>
#       Ask the SOCKS5 front at 127.0.0.1:<proxy_port> for echo.invalid:7 and
#       print the reply's REP byte, "rep=0x01" say.
#
#   tls_upstream.py junk <proxy_port>
#       Through the HTTP front, GET http://junk.invalid/ (see the server) and
#       read to the end: print "eof <status line>", or exit 1 on a reset.
import base64, os, selectors, socket, ssl, struct, sys, threading

lock = threading.Lock()


def record(log, line):
    with lock:
        with open(log, 'a') as f:
            f.write(line + '\n')


def keep(path, data):
    with lock:
        with open(path, 'ab') as f:
            f.write(data)


class Tls:
    """A server-side TLS session over a socket, through memory BIOs, so the
    ciphertext can be kept as it came in."""

    def __init__(self, ctx, sock, log):
        self.sock, self.log = sock, log
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.inc, self.out, server_side=True)

    def flush(self):
        data = self.out.read()
        if data:
            self.sock.sendall(data)

    def feed(self):
        data = self.sock.recv(65536)
        keep(self.log + '.raw', data)
        if not data:
            self.inc.write_eof()
            return False
        self.inc.write(data)
        return True

    def handshake(self):
        while True:
            try:
                self.obj.do_handshake()
                self.flush()
                return
            except ssl.SSLWantReadError:
                self.flush()
                if not self.feed():
                    raise EOFError('peer closed during the handshake')

    def read(self):
        """Plaintext available now, b'' at the end of the stream, or None
        when more ciphertext is needed."""
        try:
            data = self.obj.read(65536)
        except ssl.SSLWantReadError:
            return None
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b''
        keep(self.log + '.plain', data)
        return data

    def recv(self):
        while True:
            data = self.read()
            if data is not None:
                return data
            if not self.feed():
                data = self.read()
                return data if data else b''

    def send(self, data):
        self.obj.write(data)
        self.flush()

    def close_notify(self):
        try:
            self.obj.unwrap()
        except ssl.SSLError:
            pass
        self.flush()


def relay(tls, up, echo):
    """Tunnel between the TLS session and @up (or echo it, without @up)."""
    sel = selectors.DefaultSelector()
    sel.register(tls.sock, selectors.EVENT_READ, 'tls')
    if up:
        sel.register(up, selectors.EVENT_READ, 'up')
    tls_open, up_open = True, up is not None

    def from_tls():
        nonlocal tls_open
        while True:
            data = tls.read()
            if data is None:
                return
            if not data:
                tls_open = False
                sel.unregister(tls.sock)
                if echo:
                    tls.close_notify()
                    tls.sock.shutdown(socket.SHUT_WR)
                else:
                    up.shutdown(socket.SHUT_WR)
                return
            if echo:
                tls.send(data)
            else:
                up.sendall(data)

    from_tls()			# what came in with the CONNECT
    while tls_open or up_open:
        for key, _ in sel.select(timeout=60) or [(None, None)]:
            if key is None:
                return
            if key.data == 'tls':
                if not tls.feed():
                    from_tls()
                    if tls_open:
                        tls_open = False
                        sel.unregister(tls.sock)
                    continue
                from_tls()
            else:
                data = up.recv(65536)
                if data:
                    tls.send(data)
                    continue
                up_open = False
                sel.unregister(up)
                tls.close_notify()
                tls.sock.shutdown(socket.SHUT_WR)


def junk(tls):
    """An origin whose response header never ends, sent in one go: many
    records, which reach the proxy together, and then the end of it."""
    tls.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
    buf = b''
    while b'\r\n\r\n' not in buf:
        data = tls.recv()
        if not data:
            return
        buf += data
    tls.send(b'HTTP/1.1 200 OK\r\nX-Junk: ' + b'a' * 1000000)
    tls.close_notify()
    tls.sock.shutdown(socket.SHUT_WR)
    try:
        while tls.sock.recv(65536):
            pass
    except OSError:
        pass


def serve(ctx, conn, log, creds):
    tls = Tls(ctx, conn, log)
    up = None
    try:
        try:
            tls.handshake()
        except (ssl.SSLError, EOFError, OSError) as e:
            record(log, 'hs-fail %s' % e)
            return
        record(log, 'hs-ok sni=%s' % (getattr(tls.obj, 'gwp_sni', None) or '-'))

        buf = b''
        while b'\r\n\r\n' not in buf:
            data = tls.recv()
            if not data:
                return
            buf += data
        head, rest = buf.split(b'\r\n\r\n', 1)
        lines = head.decode('latin-1').split('\r\n')
        parts = lines[0].split()
        auth = '-'
        for l in lines[1:]:
            name, _, value = l.partition(':')
            if name.strip().lower() == 'proxy-authorization':
                auth = value.strip()
        authority = parts[1] if len(parts) > 1 else '-'
        record(log, 'connect %s auth=%s' % (authority, auth))

        if creds and auth != 'Basic ' + base64.b64encode(creds.encode()).decode():
            tls.send(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                     b'Content-Length: 0\r\n\r\n')
            tls.close_notify()
            return

        echo = authority == 'echo.invalid:7'
        if authority == 'junk.invalid:80':
            junk(tls)
            return
        if not echo:
            host, _, port = authority.rpartition(':')
            try:
                up = socket.create_connection((host.strip('[]'), int(port)),
                                              timeout=10)
            except (OSError, ValueError):
                tls.send(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
                return
        tls.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
        if rest:
            if echo:
                tls.send(rest)
            else:
                up.sendall(rest)
        relay(tls, up, echo)
    except (OSError, ssl.SSLError, EOFError):
        pass
    finally:
        for s in (conn, up):
            if s:
                try:
                    s.close()
                except OSError:
                    pass


def server(cert, key, port, log, creds=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def on_sni(obj, name, _ctx):
        obj.gwp_sni = name
    ctx.sni_callback = on_sni

    open(log, 'w').close()
    open(log + '.raw', 'wb').close()
    open(log + '.plain', 'wb').close()

    socks = []
    for fam, _, _, _, addr in socket.getaddrinfo('localhost', port, 0,
                                                  socket.SOCK_STREAM):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            s.bind(addr[:2])
        except OSError:
            s.close()
            continue
        s.listen(64)
        socks.append(s)
    if not socks:
        sys.exit('cannot listen on port %d' % port)

    sel = selectors.DefaultSelector()
    for s in socks:
        sel.register(s, selectors.EVENT_READ)
    while True:
        for key, _ in sel.select():
            conn, _ = key.fileobj.accept()
            threading.Thread(target=serve, args=(ctx, conn, log, creds),
                             daemon=True).start()


def recv_exactly(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        assert d, 'short reply'
        buf += d
    return buf


def echo_client(front, port, nbytes):
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    if front == 'socks5':
        s.sendall(b'\x05\x01\x00')
        assert s.recv(2) == b'\x05\x00', 'socks5 greeting refused'
        host = b'echo.invalid'
        s.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host +
                  struct.pack('!H', 7))
        rep = recv_exactly(s, 4)
        assert rep[1] == 0, 'socks5 CONNECT refused: rep=0x%02x' % rep[1]
        alen = {1: 4, 4: 16}.get(rep[3])
        if alen is None:
            alen = recv_exactly(s, 1)[0]
        recv_exactly(s, alen + 2)
    else:
        s.sendall(b'CONNECT echo.invalid:7 HTTP/1.1\r\nHost: echo.invalid:7\r\n\r\n')
        rep = b''
        while b'\r\n\r\n' not in rep:
            d = s.recv(1)
            assert d, 'no http reply'
            rep += d
        assert rep.split()[1] == b'200', 'CONNECT refused: %r' % rep

    data = os.urandom(nbytes)
    got = bytearray()

    def reader():
        while True:
            d = s.recv(65536)
            if not d:
                return
            got.extend(d)
    t = threading.Thread(target=reader)
    t.start()
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    t.join(60)
    assert not t.is_alive(), 'no end of stream after %d bytes' % len(got)
    assert bytes(got) == data, 'echo differs: %d of %d bytes' % (len(got), nbytes)
    print('echo ok %d' % nbytes)


def socks5_rep(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    s.sendall(b'\x05\x01\x00')
    assert recv_exactly(s, 2) == b'\x05\x00', 'socks5 greeting refused'
    host = b'echo.invalid'
    s.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host +
              struct.pack('!H', 7))
    print('rep=0x%02x' % recv_exactly(s, 2)[1])


def junk_client(port):
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    s.sendall(b'GET http://junk.invalid/ HTTP/1.1\r\nHost: junk.invalid\r\n\r\n')
    buf = b''
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            buf += d
    except ConnectionResetError:
        print('reset after %r' % buf[:40])
        sys.exit(1)
    print('eof %s' % buf.split(b'\r\n', 1)[0].decode('latin-1'))


if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5],
               sys.argv[6] if len(sys.argv) > 6 else None)
    elif sys.argv[1] == 'socks5-rep':
        socks5_rep(int(sys.argv[2]))
    elif sys.argv[1] == 'junk':
        junk_client(int(sys.argv[2]))
    else:
        echo_client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# https:// upstream proxies whose TLS does what a renegotiation or a fatal
# alert makes of a session, and the SOCKS5 clients that go through gwproxy to
# them. Python's ssl module cannot renegotiate, so the server drives the
# OpenSSL library through ctypes.
#
#   tls_reneg_upstream.py server <mode> <cert> <key> <port> <log>
#       Listen on 127.0.0.1:<port> with the certificate chain <cert> and key
#       <key>. Every connection is a TLS session that reads an HTTP CONNECT
#       and then, by <mode>:
#
#       after     (TLS 1.2) Answer 200, echo the first chunk of the tunnel,
#                 then send a HelloRequest and look at what comes back. A
#                 new ClientHello (the proxy renegotiates) is never answered:
#                 the connection is held for HOLD seconds. A no_renegotiation
#                 alert is handed to OpenSSL, which takes it as fatal, sends
#                 its own alert and the connection is closed.
#       before    (TLS 1.2) Send a HelloRequest before the reply and wait up
#                 to HOLD seconds for the proxy to answer it. A renegotiation
#                 is completed, then the CONNECT answered 200 and the tunnel
#                 echoed; a no_renegotiation alert ends it as in "after".
#       alert     Answer the CONNECT with a genuine fatal alert: a forged
#                 record is fed to the server's own engine, which fails it
#                 (bad_record_mac) and sends the alert, encrypted.
#       good      Answer 200 and echo the tunnel.
#
#       Per connection it appends a line to <log>: "reneg-accepted",
#       "reneg-refused", "reneg-done", "reneg-unanswered", "alert-sent" or
#       "tunnel" (the 200 went out).
#
#   tls_reneg_upstream.py after <proxy_port> <proxy_pid>
#       Through the SOCKS5 front, tunnel to an "after" server: send a chunk
#       and read its echo, give the HelloRequest time to arrive, then send
#       another chunk. Print the proxy's CPU time over the next WINDOW
#       seconds as "cpu=<percent>", and when the tunnel ended, counted from
#       that chunk, "end=<seconds>", or "end=none" if it did not within
#       END_WAIT seconds.
#
#   tls_reneg_upstream.py connect <proxy_port>
#       Ask the SOCKS5 front for a tunnel and print "rep=0x<REP>
#       secs=<seconds to the reply>", and with REP 0x00 also "echo=ok" when
#       a ping comes back through it, "echo=bad" otherwise.
#
# Exits 77 when the OpenSSL library cannot be used this way.

import ctypes
import ctypes.util
import os
import select
import socket
import ssl
import struct
import sys
import threading
import time

HOLD = 30		# how long the server waits for, or holds, the proxy
WINDOW = 2.0		# the client's CPU window
END_WAIT = 10		# how long the client waits for the tunnel to end
IO_WAIT = 20		# any other wait, bounded

SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_CTRL_SET_MAX_PROTO_VERSION = 124
TLS1_2_VERSION = 0x0303
SSL_FILETYPE_PEM = 1

lock = threading.Lock()


def record(log, line):
    with lock:
        with open(log, 'a') as f:
            f.write(line + '\n')


def load_libssl():
    for name in ("libssl.so.3", "libssl.so.1.1", ctypes.util.find_library("ssl")):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
            lib.SSL_renegotiate
            break
        except (OSError, AttributeError):
            continue
    else:
        print("no usable libssl")
        sys.exit(77)
    vp, ci, cl = ctypes.c_void_p, ctypes.c_int, ctypes.c_long
    for name, res, args in (
        ("TLS_server_method", vp, []),
        ("SSL_CTX_new", vp, [vp]),
        ("SSL_CTX_ctrl", cl, [vp, ci, cl, vp]),
        ("SSL_CTX_use_certificate_chain_file", ci, [vp, ctypes.c_char_p]),
        ("SSL_CTX_use_PrivateKey_file", ci, [vp, ctypes.c_char_p, ci]),
        ("SSL_new", vp, [vp]),
        ("SSL_free", None, [vp]),
        ("SSL_set_fd", ci, [vp, ci]),
        ("SSL_accept", ci, [vp]),
        ("SSL_do_handshake", ci, [vp]),
        ("SSL_renegotiate", ci, [vp]),
        ("SSL_renegotiate_pending", ci, [vp]),
        ("SSL_write", ci, [vp, ctypes.c_char_p, ci]),
        ("SSL_read", ci, [vp, vp, ci]),
        ("SSL_get_error", ci, [vp, ci]),
    ):
        f = getattr(lib, name)
        f.restype, f.argtypes = res, args
    return lib


class Session:
    """A server-side OpenSSL session on a non-blocking socket."""

    def __init__(self, lib, ctx, sock):
        self.lib, self.sock = lib, sock
        sock.setblocking(False)
        self.ssl = lib.SSL_new(ctx)
        lib.SSL_set_fd(self.ssl, sock.fileno())

    def free(self):
        self.lib.SSL_free(self.ssl)

    def wait(self, ret, deadline):
        """After a call that returned @ret <= 0: wait for what it wants, or
        raise once it failed for good or @deadline has passed."""
        err = self.lib.SSL_get_error(self.ssl, ret)
        if err == SSL_ERROR_WANT_READ:
            want = ([self.sock], [])
        elif err == SSL_ERROR_WANT_WRITE:
            want = ([], [self.sock])
        else:
            raise OSError("TLS error %d" % err)
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("TLS wait")
        rd, wr, _ = select.select(want[0], want[1], [], left)
        if not rd and not wr:
            raise TimeoutError("TLS wait")

    def accept(self):
        deadline = time.monotonic() + IO_WAIT
        while True:
            r = self.lib.SSL_accept(self.ssl)
            if r == 1:
                return
            self.wait(r, deadline)

    def handshake(self, deadline):
        while True:
            r = self.lib.SSL_do_handshake(self.ssl)
            if r == 1:
                return
            self.wait(r, deadline)

    def read(self, deadline):
        buf = ctypes.create_string_buffer(16384)
        while True:
            r = self.lib.SSL_read(self.ssl, buf, len(buf))
            if r > 0:
                return buf.raw[:r]
            if self.lib.SSL_get_error(self.ssl, r) not in (
                    SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                return b''
            self.wait(r, deadline)

    def write(self, data):
        deadline = time.monotonic() + IO_WAIT
        while data:
            r = self.lib.SSL_write(self.ssl, data, len(data))
            if r > 0:
                data = data[r:]
                continue
            self.wait(r, deadline)

    def kick(self):
        """Send the HelloRequest a renegotiation queued: the call
        writes it and then wants to read the answer, which is not waited
        for here."""
        r = self.lib.SSL_do_handshake(self.ssl)
        if r != 1 and self.lib.SSL_get_error(self.ssl, r) != SSL_ERROR_WANT_READ:
            raise OSError("could not send the request")

    def peek_record(self, deadline):
        """The content type of the next record the proxy sends (an alert,
        0x15, or a handshake message, 0x16, are visible in TLS 1.2), or
        None when nothing comes by @deadline or the connection ends."""
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                return None
            try:
                hdr = self.sock.recv(5, socket.MSG_PEEK)
            except BlockingIOError:
                continue
            except OSError:
                return None
            if not hdr:
                return None
            if len(hdr) < 5:
                time.sleep(0.01)
                continue
            return hdr[0]

    def read_connect(self):
        deadline = time.monotonic() + IO_WAIT
        req = b''
        while b'\r\n\r\n' not in req:
            data = self.read(deadline)
            if not data:
                raise EOFError("no CONNECT")
            req += data
        return req

    def echo(self):
        deadline = time.monotonic() + IO_WAIT
        while True:
            try:
                data = self.read(deadline)
            except (OSError, TimeoutError):
                return
            if not data:
                return
            self.write(data)

    def refused(self, log):
        """A no_renegotiation alert is next: have OpenSSL read it."""
        record(log, "reneg-refused")
        try:
            self.read(time.monotonic() + 2)
        except (OSError, TimeoutError):
            pass


def serve(lib, ctx, mode, conn, log):
    s = Session(lib, ctx, conn)
    try:
        s.accept()
        s.read_connect()
        ok = b'HTTP/1.1 200 Connection established\r\n\r\n'
        if mode == 'after':
            s.write(ok)
            record(log, "tunnel")
            first = s.read(time.monotonic() + IO_WAIT)
            if not first:
                return
            s.write(first)
            lib.SSL_renegotiate(s.ssl)
            s.kick()
            while True:
                t = s.peek_record(time.monotonic() + HOLD)
                if t == 0x16:
                    record(log, "reneg-accepted")
                    time.sleep(HOLD)
                    return
                if t == 0x15:
                    s.refused(log)
                    return
                if t is None:
                    return
                # Tunnel data sent before the proxy read the request.
                if not s.read(time.monotonic() + IO_WAIT):
                    return
        elif mode == 'before':
            lib.SSL_renegotiate(s.ssl)
            s.kick()
            t = s.peek_record(time.monotonic() + HOLD)
            if t == 0x15:
                s.refused(log)
                return
            if t != 0x16:
                record(log, "reneg-unanswered")
                return
            s.handshake(time.monotonic() + IO_WAIT)
            record(log, "reneg-done")
            s.write(ok)
            record(log, "tunnel")
            s.echo()
        else:
            s.write(ok)
            record(log, "tunnel")
            s.echo()
    except (OSError, EOFError, TimeoutError):
        pass
    finally:
        s.free()
        conn.close()


def serve_alert(ctx, conn, log):
    """The "alert" mode, with Python's ssl module: its engine is to fail on a
    record of its own making, so it goes through memory BIOs."""
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_side=True)
    conn.settimeout(IO_WAIT)

    def feed():
        data = conn.recv(65536)
        if not data:
            raise EOFError("closed")
        inc.write(data)

    try:
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                conn.sendall(out.read())
                feed()
        conn.sendall(out.read())
        req = b''
        while b'\r\n\r\n' not in req:
            try:
                req += obj.read(65536)
            except ssl.SSLWantReadError:
                conn.sendall(out.read())
                feed()
        inc.write(b'\x17\x03\x03\x00\x20' + os.urandom(32))
        try:
            obj.read(100)
        except ssl.SSLError:
            pass
        conn.sendall(out.read())
        record(log, "alert-sent")
        time.sleep(1)
    except (OSError, EOFError, ssl.SSLError):
        pass
    finally:
        conn.close()


def server(mode, cert, key, port, log):
    lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(('127.0.0.1', int(port)))
    lsn.listen(64)
    if mode == 'alert':
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        handler = lambda c: serve_alert(ctx, c, log)
    else:
        lib = load_libssl()
        ctx = lib.SSL_CTX_new(lib.TLS_server_method())
        if (not ctx or
                lib.SSL_CTX_use_certificate_chain_file(ctx, cert.encode()) != 1 or
                lib.SSL_CTX_use_PrivateKey_file(ctx, key.encode(),
                                                SSL_FILETYPE_PEM) != 1):
            print("cannot set up the TLS context")
            sys.exit(1)
        if mode in ('after', 'before'):
            lib.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION,
                             TLS1_2_VERSION, None)
        handler = lambda c: serve(lib, ctx, mode, c, log)
    while True:
        conn, _ = lsn.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def socks5_connect(port):
    """A SOCKS5 tunnel to echo.invalid:7: the socket, the REP and how long
    the reply took."""
    s = socket.create_connection(('127.0.0.1', int(port)), timeout=IO_WAIT)
    s.sendall(b'\x05\x01\x00')
    if recv_exact(s, 2) != b'\x05\x00':
        raise RuntimeError("greeting refused")
    host = b'echo.invalid'
    t0 = time.monotonic()
    s.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host +
              struct.pack('!H', 7))
    head = recv_exact(s, 4)
    secs = time.monotonic() - t0
    if head[3] == 1:
        recv_exact(s, 6)
    elif head[3] == 4:
        recv_exact(s, 18)
    elif head[3] == 3:
        recv_exact(s, recv_exact(s, 1)[0] + 2)
    return s, head[1], secs


def recv_exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise RuntimeError("closed after %d of %d bytes" % (len(data), n))
        data += chunk
    return data


def cpu_ticks(pid):
    with open('/proc/%d/stat' % pid) as f:
        fields = f.read().rsplit(')', 1)[1].split()
    return int(fields[11]) + int(fields[12])


def client_after(port, pid):
    s, rep, _ = socks5_connect(port)
    if rep != 0:
        print("rep=0x%02x" % rep)
        return
    s.sendall(b'ping1')
    if recv_exact(s, 5) != b'ping1':
        print("no echo")
        return
    # The HelloRequest follows the echo: let the proxy take it.
    time.sleep(0.5)
    hz = os.sysconf('SC_CLK_TCK')
    t0, c0 = time.monotonic(), cpu_ticks(pid)
    try:
        s.sendall(b'ping2')
    except OSError:
        pass
    end = cpu = None
    s.settimeout(0.05)
    while True:
        now = time.monotonic()
        if cpu is None and now - t0 >= WINDOW:
            cpu = 100 * (cpu_ticks(pid) - c0) / (hz * (now - t0))
        if cpu is not None and (end is not None or now - t0 >= END_WAIT):
            break
        if end is not None:
            time.sleep(0.05)
            continue
        try:
            if not s.recv(65536):
                end = time.monotonic() - t0
        except socket.timeout:
            pass
        except OSError:
            end = time.monotonic() - t0
    print("cpu=%d end=%s" % (cpu, "none" if end is None else "%.2f" % end))


def client_connect(port):
    s, rep, secs = socks5_connect(port)
    out = "rep=0x%02x secs=%.2f" % (rep, secs)
    if rep == 0:
        try:
            s.sendall(b'ping')
            ok = recv_exact(s, 4) == b'ping'
        except (OSError, RuntimeError):
            ok = False
        out += " echo=%s" % ("ok" if ok else "bad")
    print(out)


def main():
    if len(sys.argv) == 7 and sys.argv[1] == 'server':
        server(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == 'after':
        client_after(sys.argv[2], int(sys.argv[3]))
    elif len(sys.argv) == 3 and sys.argv[1] == 'connect':
        client_connect(sys.argv[2])
    else:
        sys.exit("usage: see the comment at the top")


if __name__ == '__main__':
    main()

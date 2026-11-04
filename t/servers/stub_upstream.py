#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that records what it was asked for, and from where, and
# answers with success without connecting anywhere, so a test can name any
# destination without reaching it or a resolver. Once the tunnel is up it sends
# BANNER, which proves to the client that it came through the upstream.
#
# One line is appended to the log per request:
#   socks5: "src=<peer ip> atyp=<n> addr=<host> port=<n>"
#   http:   "src=<peer ip> authority=<host:port>"
#
# Usage: stub_upstream.py <socks5|http> <bind_port> <logfile>
import socket, struct, sys, threading

mode, port, logpath = sys.argv[1], int(sys.argv[2]), sys.argv[3]
BANNER = b'UPSTREAM-TUNNEL\n'


def record(line):
    with open(logpath, 'a') as f:
        f.write(line + '\n')


def recv_exactly(c, n):
    buf = b''
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def socks5(c, src):
    _, nmeth = recv_exactly(c, 2)
    recv_exactly(c, nmeth)
    c.sendall(b'\x05\x00')
    atyp = recv_exactly(c, 4)[3]
    if atyp == 1:
        addr = socket.inet_ntoa(recv_exactly(c, 4))
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, recv_exactly(c, 16))
    else:
        addr = recv_exactly(c, recv_exactly(c, 1)[0]).decode()
    dport = struct.unpack('!H', recv_exactly(c, 2))[0]
    record('src=%s atyp=%d addr=%s port=%d' % (src, atyp, addr, dport))
    c.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)


def http(c, src):
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = c.recv(4096)
        if not chunk:
            raise EOFError
        buf += chunk
    record('src=%s authority=%s' % (src, buf.split()[1].decode()))
    c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')


def serve(c, src):
    try:
        (socks5 if mode == 'socks5' else http)(c, src)
        c.sendall(BANNER)
        # Stay up until the proxy hangs up, so the tunnel outlives the test's
        # read of the banner.
        while c.recv(4096):
            pass
    except (OSError, EOFError):
        pass
    c.close()


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port))
srv.listen(64)
while True:
    conn, peer = srv.accept()
    threading.Thread(target=serve, args=(conn, peer[0]), daemon=True).start()

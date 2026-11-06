#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A minimal upstream proxy that RECORDS what it was asked for, then relays the
# tunnel to the real destination so the transfer still completes end to end.
# The chaining tests use it to assert what gwproxy actually put on the wire --
# in particular whether a socks5h:// upstream forwards the hostname (ATYP=3)
# instead of resolving it locally first (ATYP=1), which is otherwise invisible
# because both schemes produce a working transfer.
#
# One line is appended to the log per request:
#   socks5: "atyp=<n> addr=<host> port=<n>"
#   http:   "authority=<host:port>"
# and, when the request carried credentials (SOCKS5 user/password, which is
# then accepted, or an HTTP Proxy-Authorization: Basic header), at its end:
#   socks5: " user=<user> pass=<pass>"
#   http:   " auth=<user:pass>"
#
# Usage: recording_proxy.py <socks5|http> <bind_host> <bind_port> <logfile>
import base64, selectors, socket, struct, sys, threading

mode, host, port, logpath = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
log_lock = threading.Lock()


def record(line):
    with log_lock:
        with open(logpath, 'a') as f:
            f.write(line + '\n')
            f.flush()


def relay(a, b):
    """Pump bytes both ways until either side is done."""
    sel = selectors.DefaultSelector()
    a.setblocking(False)
    b.setblocking(False)
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    open_count = 2
    while open_count:
        for key, _ in sel.select(timeout=30) or []:
            src, dst = key.fileobj, key.data
            try:
                data = src.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                data = b''
            if not data:
                sel.unregister(src)
                open_count -= 1
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                dst.sendall(data)
            except OSError:
                open_count = 0
                break
        else:
            continue
    sel.close()
    for s in (a, b):
        try:
            s.close()
        except OSError:
            pass


def recv_exactly(s, n):
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def handle_socks5(c):
    ver, nmeth = recv_exactly(c, 2)
    creds = ''
    if 2 in recv_exactly(c, nmeth):
        c.sendall(b'\x05\x02')		# username/password (RFC 1929)
        recv_exactly(c, 1)
        user = recv_exactly(c, recv_exactly(c, 1)[0]).decode()
        pw = recv_exactly(c, recv_exactly(c, 1)[0]).decode()
        creds = ' user=%s pass=%s' % (user, pw)
        c.sendall(b'\x01\x00')
    else:
        c.sendall(b'\x05\x00')		# no authentication required
    hdr = recv_exactly(c, 4)
    atyp = hdr[3]
    if atyp == 1:
        addr = socket.inet_ntoa(recv_exactly(c, 4))
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, recv_exactly(c, 16))
    elif atyp == 3:
        dlen = recv_exactly(c, 1)[0]
        addr = recv_exactly(c, dlen).decode()
    else:
        c.close()
        return
    dport = struct.unpack('!H', recv_exactly(c, 2))[0]
    record('atyp=%d addr=%s port=%d%s' % (atyp, addr, dport, creds))

    try:
        up = socket.create_connection((addr, dport), timeout=10)
    except OSError:
        c.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)	# connection refused
        c.close()
        return
    c.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
    relay(c, up)


def handle_http(c):
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = c.recv(4096)
        if not chunk:
            c.close()
            return
        buf += chunk
    line = buf.split(b'\r\n', 1)[0].decode()
    parts = line.split()
    if len(parts) < 2 or parts[0].upper() != 'CONNECT':
        c.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n')
        c.close()
        return
    authority = parts[1]
    creds = ''
    for h in buf.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]:
        name, _, val = h.decode().partition(':')
        val = val.strip().split()
        if (name.strip().lower() == 'proxy-authorization' and
                len(val) == 2 and val[0].lower() == 'basic'):
            creds = ' auth=%s' % base64.b64decode(val[1]).decode()
    record('authority=%s%s' % (authority, creds))

    hostpart, _, portpart = authority.rpartition(':')
    try:
        up = socket.create_connection((hostpart.strip('[]'), int(portpart)), timeout=10)
    except OSError:
        c.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
        c.close()
        return
    c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
    relay(c, up)


def serve(c):
    try:
        if mode == 'socks5':
            handle_socks5(c)
        else:
            handle_http(c)
    except (OSError, EOFError):
        try:
            c.close()
        except OSError:
            pass


fam = socket.AF_INET6 if ':' in host else socket.AF_INET
srv = socket.socket(fam, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(64)
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()

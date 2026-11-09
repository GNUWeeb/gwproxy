#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 server that grants UDP ASSOCIATE and does nothing else, for the
# tests of UDP through an upstream: it shows what the proxy in front of it
# sends where gwproxy as the upstream would not (a domain target, which
# gwproxy's own relay drops), and answers in ways gwproxy does not.
#
# Usage: socks5_udp_upstream.py <log> [--rep N] [--bnd IP]
#
# Prints "READY <port>" once it listens on 127.0.0.1. Each UDP ASSOCIATE is
# answered REP N (default 0) with BND.ADDR IP (default 0.0.0.0, "use the
# server's own address") and the port of a fresh UDP socket on 127.0.0.1.
# That socket sends every datagram back to where it came from as it is,
# SOCKS5 header and all, as if the target had answered at once. A payload
# ending in "stray" also gets a datagram from another socket, which the
# proxy must not pass on. One ending in "bye" is not sent back: it closes
# the control connection instead, as a datagram sent just before would race
# the close to the proxy, which may drop it with the association.
# The log gets a line per request and per datagram:
#   assoc dst=<addr>:<port>
#   dgram from=<ip>:<port> atyp=<n> dst=<addr>:<port> len=<n>
#   closed
import socket, struct, sys, threading

argv = sys.argv[1:]
logf = argv.pop(0)
rep = 0
bnd = '0.0.0.0'
while argv:
    o = argv.pop(0)
    if o == '--rep':
        rep = int(argv.pop(0))
    elif o == '--bnd':
        bnd = argv.pop(0)
    else:
        sys.exit('unknown option ' + o)

lock = threading.Lock()


def log(line):
    with lock:
        with open(logf, 'a') as f:
            f.write(line + '\n')


def recv_exactly(c, n):
    b = b''
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError
        b += d
    return b


def read_addr(c):
    atyp = recv_exactly(c, 1)[0]
    if atyp == 1:
        a = socket.inet_ntoa(recv_exactly(c, 4))
    elif atyp == 4:
        a = socket.inet_ntop(socket.AF_INET6, recv_exactly(c, 16))
    elif atyp == 3:
        a = recv_exactly(c, recv_exactly(c, 1)[0]).decode('latin-1')
    else:
        raise EOFError
    return a, struct.unpack('!H', recv_exactly(c, 2))[0]


def parse_hdr(d):
    atyp = d[3]
    if atyp == 1:
        return atyp, socket.inet_ntoa(d[4:8]), struct.unpack('!H', d[8:10])[0]
    if atyp == 4:
        return (atyp, socket.inet_ntop(socket.AF_INET6, d[4:20]),
                struct.unpack('!H', d[20:22])[0])
    n = d[4]
    return (atyp, d[5:5 + n].decode('latin-1'),
            struct.unpack('!H', d[5 + n:7 + n])[0])


def relay(u, c):
    stray = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            d, src = u.recvfrom(65535)
        except OSError:
            return
        try:
            atyp, a, p = parse_hdr(d)
        except Exception:
            atyp, a, p = 0, '?', 0
        log('dgram from=%s:%d atyp=%d dst=%s:%d len=%d' %
            (src[0], src[1], atyp, a, p, len(d)))
        if d.endswith(b'stray'):
            stray.sendto(d[:-5] + b'STRAY', src)
        if d.endswith(b'bye'):
            c.shutdown(socket.SHUT_RDWR)
        else:
            u.sendto(d, src)


def serve(c):
    u = None
    try:
        ver, n = recv_exactly(c, 2)
        recv_exactly(c, n)
        c.sendall(b'\x05\x00')
        hdr = recv_exactly(c, 3)
        a, p = read_addr(c)
        log('assoc dst=%s:%d cmd=%d' % (a, p, hdr[1]))
        if rep or hdr[1] != 3:
            c.sendall(bytes([5, rep or 7, 0, 1]) + b'\x00' * 6)
            return
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(('127.0.0.1', 0))
        c.sendall(b'\x05\x00\x00\x01' + socket.inet_aton(bnd) +
                  struct.pack('!H', u.getsockname()[1]))
        threading.Thread(target=relay, args=(u, c), daemon=True).start()
        while c.recv(4096):
            pass
    except (EOFError, OSError):
        pass
    finally:
        log('closed')
        if u:
            u.close()
        c.close()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(64)
print('READY %d' % s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()

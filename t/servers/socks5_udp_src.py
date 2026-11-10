#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Asks a SOCKS5 proxy for a UDP ASSOCIATE, then sends one datagram through
# the relay to each target in turn and prints what came back: the reply's
# payload, which udp_src_echo.py makes the source address the target saw,
# as "SRC <text>", or "NONE" when nothing came back within the wait. All
# the targets share the association.
#
# Usage: socks5_udp_src.py [--proxy IP] [--wait S] <proxy_port>
#                          <target_ip> <target_port> [<ip> <port>]...
#
# --proxy reaches the proxy at IP (default 127.0.0.1); --wait is how long
# to wait for each reply (default 3 seconds). It prints "REP <n>" for the
# reply to the UDP ASSOCIATE first, and stops there on a refusal.
import socket, struct, sys, time

argv = sys.argv[1:]
proxy = '127.0.0.1'
wait = 3.0
while argv and argv[0].startswith('--'):
    o = argv.pop(0)
    if o == '--proxy':
        proxy = argv.pop(0)
    elif o == '--wait':
        wait = float(argv.pop(0))
    else:
        sys.exit('unknown option ' + o)
port = int(argv.pop(0))


def fam(ip):
    return socket.AF_INET6 if ':' in ip else socket.AF_INET


def recv_exactly(c, n):
    b = b''
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            sys.exit('the proxy hung up')
        b += d
    return b


c = socket.socket(fam(proxy), socket.SOCK_STREAM)
c.settimeout(10)
c.connect((proxy, port))
c.sendall(b'\x05\x01\x00')
if recv_exactly(c, 2) != b'\x05\x00':
    sys.exit('method selection failed')
c.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = recv_exactly(c, 4)
print('REP %d' % rep[1], flush=True)
if rep[1]:
    sys.exit(0)
if rep[3] == 1:
    bnd_ip = socket.inet_ntoa(recv_exactly(c, 4))
elif rep[3] == 4:
    bnd_ip = socket.inet_ntop(socket.AF_INET6, recv_exactly(c, 16))
else:
    sys.exit('unexpected BND.ADDR type %d' % rep[3])
relay = (bnd_ip, struct.unpack('!H', recv_exactly(c, 2))[0])
u = socket.socket(fam(bnd_ip), socket.SOCK_DGRAM)

for i in range(0, len(argv), 2):
    ip, p = argv[i], int(argv[i + 1])
    if ':' in ip:
        hdr = b'\x00\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, ip)
        hlen = 3 + 1 + 16 + 2
    else:
        hdr = b'\x00\x00\x00\x01' + socket.inet_aton(ip)
        hlen = 3 + 1 + 4 + 2
    hdr += struct.pack('!H', p)
    u.sendto(hdr + b'probe', relay)
    # Only this target's reply: a late one of an earlier target is not it.
    end = time.time() + wait
    out = 'NONE'
    while time.time() < end:
        u.settimeout(max(end - time.time(), 0.01))
        try:
            d = u.recv(65535)
        except socket.timeout:
            break
        if d[:hlen] == hdr:
            out = 'SRC %s' % d[hlen:].decode(errors='replace')
            break
    print(out, flush=True)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Sends ONE hand-built datagram through a SOCKS5 UDP relay and reports whether
# it came back. Where socks5_udp_client.py exercises the working path, this one
# builds the request header by hand so the relay's reject paths can be asserted:
# a datagram from the wrong source, a fragmented one, or one naming a domain.
#
# Usage: socks5_udp_probe.py [--src-ip IP] [--frag N] [--atyp ipv4|ipv6|domain]
#                            [--dst HOST] [--size N] [--bnd-atyp N]
#                            proxy_port target_port
#
# --src-ip sends the datagram from a different local address than the one the
# TCP control connection came from (any 127.0.0.0/8 address is local), which is
# what the RFC 1928 same-address check is supposed to reject.
#
# --bnd-atyp requires the UDP ASSOCIATE reply's BND.ADDR to have this address
# type, and the datagram is then sent to that address from an IPv4 socket.
#
# Prints RELAYED or DROPPED, or BND_ATYP=N for a reply of the wrong type.
import socket, struct, sys

argv = sys.argv[1:]


def take_opt(name, default=None):
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return default


src_ip = take_opt('--src-ip')
frag = int(take_opt('--frag', '0'))
atyp = take_opt('--atyp', 'ipv4')
dst = take_opt('--dst', '127.0.0.1')
size = int(take_opt('--size', '32'))
bnd_atyp = take_opt('--bnd-atyp')

pport = int(argv[0])
tport = int(argv[1])

t = socket.create_connection(('127.0.0.1', pport))
t.settimeout(10)
t.sendall(b'\x05\x01\x00')
assert t.recv(2) == b'\x05\x00', 'method selection failed'
t.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = t.recv(64)
assert len(rep) >= 10 and rep[1] == 0, 'UDP ASSOCIATE refused'
if bnd_atyp and rep[3] != int(bnd_atyp):
    print('BND_ATYP=%d' % rep[3])
    sys.exit(0)
bnd_addr = '127.0.0.1'
if bnd_atyp:
    bnd_addr = socket.inet_ntoa(rep[4:8])
bnd_port = struct.unpack('!H', rep[-2:])[0]

if atyp == 'domain':
    d = dst.encode()
    addr = b'\x03' + bytes([len(d)]) + d
elif atyp == 'ipv6':
    addr = b'\x04' + socket.inet_pton(socket.AF_INET6, dst)
else:
    addr = b'\x01' + socket.inet_aton(dst)

hdr = b'\x00\x00' + bytes([frag]) + addr + struct.pack('!H', tport)
payload = bytes((i * 7) & 0xff for i in range(size))

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(2)
if src_ip:
    u.bind((src_ip, 0))
u.sendto(hdr + payload, (bnd_addr, bnd_port))

try:
    u.recvfrom(65535)
except socket.timeout:
    print('DROPPED')
else:
    print('RELAYED')

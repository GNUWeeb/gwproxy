#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A UDP server that answers each datagram with the source address it came
# from, as text ("192.0.2.3", "2001:db8::3"): what the far end of a relay
# sees. An IPv4 source on the dual-stack "::" is given as IPv4. The answer
# leaves from the address the datagram was sent to.
#
# udp_src_echo.py <addr> <port>: pass port 0 to let the kernel pick a free
# one. Once bound, prints "READY <port>" with the port actually in use, as
# udp_echo.py does.
import socket, sys

fam = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
if fam == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind((sys.argv[1], int(sys.argv[2])))
print("READY %d" % s.getsockname()[1], flush=True)
# Answer from the address the datagram came to, whichever of several on
# the host: a relay takes replies only from the target it sent to.
IPV6_RECVPKTINFO = getattr(socket, 'IPV6_RECVPKTINFO', 49)
IPV6_PKTINFO = getattr(socket, 'IPV6_PKTINFO', 50)
IP_PKTINFO = 8
if fam == socket.AF_INET6:
    s.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
s.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
while True:
    data, anc, _, addr = s.recvmsg(65535, 256)
    cm = []
    for level, typ, d in anc:
        if level == socket.IPPROTO_IPV6 and typ == IPV6_PKTINFO:
            cm = [(level, typ, d[:16] + bytes(4))]
        elif level == socket.IPPROTO_IP and typ == IP_PKTINFO:
            # ipi_ifindex, ipi_spec_dst, ipi_addr: send from ipi_addr.
            cm = [(level, typ, bytes(4) + d[8:12] + bytes(4))]
    ip = addr[0]
    if ip.startswith('::ffff:') and '.' in ip:
        ip = ip[7:]
    s.sendmsg([ip.encode()], cm, 0, addr)

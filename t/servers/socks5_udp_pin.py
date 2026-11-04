#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Which local UDP socket does a SOCKS5 UDP association accept as its client?
# Every socket here has the control connection's IP address, so only the port
# and the order of the datagrams tell the real client from another party.
#
# Usage: socks5_udp_pin.py [--proxy-host H] [--echo-host H] proxy_port echo_port
#                          case
#
# Exits 0 when the case holds; otherwise says what happened, exits 1.
import socket, struct, sys

argv = sys.argv[1:]


def take_opt(name, default):
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return default


proxy_host = take_opt('--proxy-host', '127.0.0.1')
echo_host = take_opt('--echo-host', '127.0.0.1')
proxy_port, echo_port, case = int(argv[0]), int(argv[1]), argv[2]
family = socket.AF_INET6 if ':' in proxy_host else socket.AF_INET


def fail(msg):
    sys.exit('%s: %s' % (case, msg))


def sock_addr(host, port):
    if ':' in host:
        return b'\x04' + socket.inet_pton(socket.AF_INET6, host) + \
            struct.pack('!H', port)
    return b'\x01' + socket.inet_aton(host) + struct.pack('!H', port)


def udp_socket():
    u = socket.socket(family, socket.SOCK_DGRAM)
    u.bind((proxy_host, 0))
    return u


def associate(declared):
    t = socket.socket(family)
    t.settimeout(30)
    t.connect((proxy_host, proxy_port))
    t.sendall(b'\x05\x01\x00')
    if t.recv(2) != b'\x05\x00':
        fail('method selection failed')
    t.sendall(b'\x05\x03\x00' + declared)
    rep = t.recv(64)
    if len(rep) < 10 or rep[1] != 0:
        fail('UDP ASSOCIATE refused: %r' % rep)
    return t, struct.unpack('!H', rep[-2:])[0]


def dgram(tag):
    return b'\x00\x00\x00' + sock_addr(echo_host, echo_port) + tag


def relayed(u, bnd_port, tag, wait):
    """Send a datagram from @u: does its echo come back within @wait s?"""
    u.settimeout(wait)
    u.sendto(dgram(tag), (proxy_host, bnd_port))
    try:
        d = u.recv(65535)
    except socket.timeout:
        return False
    if not d.endswith(tag):
        fail('wrong echo %r' % d)
    return True


def must_relay(u, bnd_port, tag):
    # A generous limit: this only runs out when the test is about to fail.
    if not relayed(u, bnd_port, tag, 30):
        fail('%s was not relayed' % tag.decode())


def must_drop(u, bnd_port, tag):
    # A slow machine cannot make this fail wrongly, and the must_relay() that
    # follows or precedes each call shows the relay itself is working.
    if relayed(u, bnd_port, tag, 1):
        fail('%s was relayed' % tag.decode())


client, other = udp_socket(), udp_socket()
cport = client.getsockname()[1]
oport = other.getsockname()[1]
zero = b'\x01\x00\x00\x00\x00\x00\x00'
local = proxy_host

if case == 'junk-first':
    # Junk from one port does not take the association, nor does the client
    # lose it: the first datagram that parses pins its sender.
    t, bp = associate(zero)
    other.sendto(b'\xff', (proxy_host, bp))
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other')
    must_relay(client, bp, b'client again')
elif case == 'first-wins':
    # Nothing declared: the first valid datagram pins, as it always did.
    t, bp = associate(zero)
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other')
elif case == 'declared':
    # A declared address of the control IP and a port: only that port is the
    # client, even when another port sends first.
    t, bp = associate(sock_addr(local, cport))
    must_drop(other, bp, b'other')
    client.sendto(b'\xff', (proxy_host, bp))
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other again')
    must_relay(client, bp, b'client again')
elif case == 'declared-mapped':
    # The same, with an IPv4 control IP declared in its v4-mapped form.
    t, bp = associate(sock_addr('::ffff:' + local, cport))
    must_drop(other, bp, b'other')
    must_relay(client, bp, b'client')
elif case == 'declared-other-ip':
    # A declared address that is not the control IP is the client's view from
    # behind a NAT, whose port may be rewritten too: it binds nothing.
    t, bp = associate(sock_addr('192.0.2.1', oport))
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other')
elif case == 'declared-port-only':
    # A port with no address may have been rewritten the same way.
    t, bp = associate(b'\x01\x00\x00\x00\x00' + struct.pack('!H', oport))
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other')
elif case == 'declared-addr-only':
    # The control IP with no port does not say which port.
    t, bp = associate(sock_addr(local, 0))
    must_relay(client, bp, b'client')
    must_drop(other, bp, b'other')
else:
    fail('unknown case')
t.close()

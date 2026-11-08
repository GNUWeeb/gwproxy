#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 UDP ASSOCIATE client that runs a script of steps and prints what
# happened, one line per step, for the tests of UDP through an upstream.
#
# Usage: socks5_udp_up_client.py <proxy_port> [step...]
#
# It asks 127.0.0.1:<proxy_port> for a UDP ASSOCIATE and prints "REP <n>"
# (or "HUP" when the proxy hangs up first); on a refusal it stops there.
# Then the steps:
#   send:<ip|domain>:<port>:<payload>  send <payload> to that target, a
#       numeric address or else a name; print "ECHO <payload>" for each
#       datagram that comes back within 2 s carrying it (a second one is
#       printed too, so a duplicate shows), or "NONE"
#   eof   wait up to 10 s for the proxy to close the control connection;
#         print "EOF", or "OPEN" if it did not
#   sleep:<s>  pause
#
# With SOCKS5_USER and SOCKS5_PASS in the environment it authenticates with
# them (RFC 1929) instead of offering no authentication.
import os, socket, struct, sys, time

port = int(sys.argv[1])
steps = sys.argv[2:]

c = socket.create_connection(('127.0.0.1', port), timeout=10)
user = os.environ.get('SOCKS5_USER')
if user is None:
    c.sendall(b'\x05\x01\x00')
    if c.recv(2) != b'\x05\x00':
        sys.exit('method selection failed')
else:
    u, p = user.encode(), os.environ.get('SOCKS5_PASS', '').encode()
    c.sendall(b'\x05\x01\x02')
    if c.recv(2) != b'\x05\x02':
        sys.exit('method selection failed')
    c.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
    if c.recv(2) != b'\x01\x00':
        sys.exit('authentication failed')
c.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = b''
while len(rep) < 10:
    d = c.recv(10 - len(rep))
    if not d:
        print('HUP')
        sys.exit(0)
    rep += d
print('REP %d' % rep[1], flush=True)
if rep[1]:
    sys.exit(0)
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack('!H', rep[8:10])[0])

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def target(host, p):
    try:
        return b'\x01' + socket.inet_aton(host) + struct.pack('!H', p)
    except OSError:
        pass
    try:
        return (b'\x04' + socket.inet_pton(socket.AF_INET6, host) +
                struct.pack('!H', p))
    except OSError:
        h = host.encode()
        return b'\x03' + bytes([len(h)]) + h + struct.pack('!H', p)


for st in steps:
    if st.startswith('send:'):
        _, host, p, payload = st.split(':', 3)
        u.sendto(b'\x00\x00\x00' + target(host, int(p)) + payload.encode(),
                 relay)
        got = 0
        end = time.time() + 2
        while True:
            u.settimeout(max(end - time.time(), 0.01))
            try:
                d, _ = u.recvfrom(65535)
            except socket.timeout:
                break
            print('ECHO %s' % d[-len(payload):].decode('latin-1')
                  if d.endswith(payload.encode()) else
                  'OTHER %r' % d, flush=True)
            got += 1
            if got == 1:
                end = min(end, time.time() + 0.5)
        if not got:
            print('NONE', flush=True)
    elif st == 'eof':
        c.settimeout(10)
        try:
            while c.recv(4096):
                pass
            print('EOF', flush=True)
        except socket.timeout:
            print('OPEN', flush=True)
        except OSError:
            print('EOF', flush=True)
    elif st.startswith('sleep:'):
        time.sleep(float(st[6:]))
    else:
        sys.exit('unknown step ' + st)

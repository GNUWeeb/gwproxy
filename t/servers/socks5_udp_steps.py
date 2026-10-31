#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE client that runs a script of steps over ONE
# association, for checks that depend on the association's history (such as
# a cached ACL verdict). All targets are UDP echo servers on 127.0.0.1.
#
# Usage: socks5_udp_steps.py proxy_port step...
#   echo:PORT      a datagram to PORT is echoed back (retried, UDP is lossy)
#   drop:PORT      a datagram to PORT is not echoed back
#   count:N:PORT   send N datagrams to PORT one at a time (no retries) and
#                  print "count=<echoed>"
#   touch:PATH     create PATH (tell the test script a point was reached)
#   wait:PATH      wait up to 20 s for PATH to exist
import os, socket, struct, sys, time

pp = int(sys.argv[1])
steps = sys.argv[2:]

t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(10)
t.connect(('127.0.0.1', pp))
t.sendall(b'\x05\x01\x00')
sel = t.recv(2)
assert sel == b'\x05\x00', 'method selection failed'
t.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = t.recv(4)
assert len(rep) == 4 and rep[0] == 5 and rep[1] == 0, 'UDP ASSOCIATE refused'
if rep[3] == 1:
    bnd = (socket.inet_ntoa(t.recv(4)), socket.AF_INET)
elif rep[3] == 4:
    bnd = (socket.inet_ntop(socket.AF_INET6, t.recv(16)), socket.AF_INET6)
else:
    raise AssertionError('bad BND ATYP 0x%02x' % rep[3])
bnd_port = struct.unpack('!H', t.recv(2))[0]
u = socket.socket(bnd[1], socket.SOCK_DGRAM)
seq = 0


def send_once(port, timeout):
    """Send one datagram to PORT; True if it came back intact."""
    global seq
    seq += 1
    payload = b'step-%d' % seq
    hdr = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + \
        struct.pack('!H', port)
    u.sendto(hdr + payload, (bnd[0], bnd_port))
    deadline = time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            return False
        u.settimeout(left)
        try:
            data, _ = u.recvfrom(65535)
        except socket.timeout:
            return False
        off = 10 if data[3] == 1 else 22
        if data[off:] == payload:
            return True		# a late echo of an earlier datagram is skipped


for st in steps:
    kind, _, arg = st.partition(':')
    if kind == 'echo':
        assert any(send_once(int(arg), 1.0) for _ in range(5)), \
            '%s: datagram not relayed' % st
    elif kind == 'drop':
        assert not any(send_once(int(arg), 0.5) for _ in range(3)), \
            '%s: datagram relayed, want dropped' % st
    elif kind == 'count':
        n, port = (int(x) for x in arg.split(':'))
        print('count=%d' % sum(send_once(port, 1.0) for _ in range(n)))
    elif kind == 'touch':
        open(arg, 'w').close()
    elif kind == 'wait':
        for _ in range(200):
            if os.path.exists(arg):
                break
            time.sleep(0.1)
        else:
            raise AssertionError('%s: timed out' % st)
    else:
        raise AssertionError('unknown step ' + st)
print('OK')

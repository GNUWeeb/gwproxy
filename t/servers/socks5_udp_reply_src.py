#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE client that checks which sources the relay accepts
# replies from. It plays the client and every target itself (all on
# 127.0.0.1), so it knows the relay's address and can send "replies" to it
# from sockets the client has, or has not, sent to.
#
# Usage: socks5_udp_reply_src.py proxy_port sync_dir
#
# Halfway through it writes the second target's port to sync_dir/port and
# waits for sync_dir/go, so the test can reload an ACL that denies that
# target. Prints "ok" and exits 0 when every check holds.
import os, socket, struct, sys, time

pp = int(sys.argv[1])
sync = sys.argv[2]

t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(10)
t.connect(('127.0.0.1', pp))
t.sendall(b'\x05\x01\x00')
assert t.recv(2) == b'\x05\x00', 'method selection failed'
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


def udp_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    return s


t1, t2, stranger = udp_sock(), udp_sock(), udp_sock()


def client_send(target, payload):
    """Client -> target through the relay; the target's view of the relay."""
    hdr = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + \
        struct.pack('!H', target.getsockname()[1])
    for _ in range(5):
        u.sendto(hdr + payload, (bnd[0], bnd_port))
        target.settimeout(1.0)
        try:
            data, relay = target.recvfrom(65535)
        except socket.timeout:
            continue
        if data == payload:
            return relay
    raise AssertionError('%r never reached its target' % payload)


def client_gets(payload, timeout):
    """True if the client receives @payload as a relayed reply in time."""
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
            return True


def reply(sock, relay, payload, want, what):
    """Send @payload from @sock to the relay; it must (not) reach the client."""
    tries = 5 if want else 3
    got = False
    for _ in range(tries):
        sock.sendto(payload, relay)
        if client_gets(payload, 1.0 if want else 0.5):
            got = True
            break
    if got != want:
        raise AssertionError('%s: reply %s' %
                             (what, 'dropped' if want else 'relayed'))


relay = client_send(t1, b'to-t1')
reply(t1, relay, b'from-t1', True, 'a target the client sent to')
reply(stranger, relay, b'from-stranger', False,
      'a source the client never sent to')
reply(t2, relay, b'from-t2-early', False,
      'a target before the client sent to it')
client_send(t2, b'to-t2')
reply(t2, relay, b'from-t2', True, 'a second target the client sent to')

# The test now reloads an ACL that denies t2.
with open(os.path.join(sync, 'port.tmp'), 'w') as f:
    f.write('%d\n' % t2.getsockname()[1])
os.replace(os.path.join(sync, 'port.tmp'), os.path.join(sync, 'port'))
for _ in range(200):
    if os.path.exists(os.path.join(sync, 'go')):
        break
    time.sleep(0.1)
else:
    raise AssertionError('the ACL was never reloaded')

reply(t2, relay, b'from-t2-denied', False, 'a target the ACL now denies')
reply(t1, relay, b'from-t1-again', True, 'a target the ACL still allows')
print('ok')

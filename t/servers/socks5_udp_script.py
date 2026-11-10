#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 UDP ASSOCIATE client that runs a script of steps and prints what
# happened, one line per step: socks5_udp_up_client.py with the control
# connection and the UDP socket set up in more ways.
#
# Usage: socks5_udp_script.py [options] <proxy_port> [step...]
#
# Options:
#   --proxy IP   reach the proxy at IP (default 127.0.0.1; IPv6 works too)
#   --src IP     bind the control connection and the UDP socket to IP
#   --tls        wrap the control connection in TLS (no verification)
#   --connect    connect() the UDP socket to (BND.ADDR, BND.PORT), so the
#                kernel drops every datagram from another source, as many
#                clients (PySocks, for one) and stateful firewalls do
#
# It asks for a UDP ASSOCIATE and prints "REP <n>" (or "HUP" when the proxy
# hangs up first); on a refusal it stops there. Then the steps:
#   send:<ip|domain>:<port>:<payload>  send <payload> to that target (an
#       IPv6 address may be given with dashes for colons); print
#       "ECHO <payload>" for each datagram that comes back within 2 s
#       carrying it, or "NONE"
#   eof         wait up to 10 s for the proxy to close the control
#               connection; print "EOF", or "OPEN" if it did not
#   open:<s>    print "OPEN" if the control connection is still open after
#               <s> seconds, else "EOF after <t>s"
#   junk:<ip>   from now on, send b'junk' to the relay every 0.25 s from
#               a socket on <ip>, a stranger to the association
#   ping:<ip>:<port>  from now on, send a datagram to that target through
#               the relay every 0.5 s (the replies are read and dropped)
#   sleep:<s>   pause
import socket, ssl, struct, sys, threading, time

argv = sys.argv[1:]
proxy = '127.0.0.1'
src = None
use_tls = False
connect = False
while argv and argv[0].startswith('--'):
    o = argv.pop(0)
    if o == '--proxy':
        proxy = argv.pop(0)
    elif o == '--src':
        src = argv.pop(0)
    elif o == '--tls':
        use_tls = True
    elif o == '--connect':
        connect = True
    else:
        sys.exit('unknown option ' + o)
port = int(argv.pop(0))
steps = argv


def fam(ip):
    return socket.AF_INET6 if ':' in ip else socket.AF_INET


def recv_exactly(c, n):
    b = b''
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            print('HUP', flush=True)
            sys.exit(0)
        b += d
    return b


c = socket.socket(fam(proxy), socket.SOCK_STREAM)
c.settimeout(10)
if src:
    c.bind((src, 0))
c.connect((proxy, port))
if use_tls:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = ctx.wrap_socket(c)
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
if src:
    u.bind((src, 0))
if connect:
    u.connect(relay)


def target(host, p):
    host = host.replace('-', ':')
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


def send(d):
    if connect:
        u.send(d)
    else:
        u.sendto(d, relay)


ulock = threading.Lock()


def junk(ip):
    s = socket.socket(fam(ip), socket.SOCK_DGRAM)
    s.bind((ip, 0))
    while True:
        try:
            s.sendto(b'junk', relay)
        except OSError:
            pass
        time.sleep(0.25)


def ping(host, p):
    d = b'\x00\x00\x00' + target(host, p) + b'ping'
    while True:
        with ulock:
            try:
                send(d)
            except OSError:
                pass
        time.sleep(0.5)


def control_open(t):
    end = time.time() + t
    start = time.time()
    while True:
        left = end - time.time()
        if left <= 0:
            return None
        c.settimeout(left)
        try:
            if not c.recv(4096):
                return time.time() - start
        except socket.timeout:
            return None
        except OSError:
            return time.time() - start


for st in steps:
    if st.startswith('send:'):
        _, host, p, payload = st.split(':', 3)
        with ulock:
            send(b'\x00\x00\x00' + target(host, int(p)) + payload.encode())
        got = 0
        end = time.time() + 2
        while True:
            u.settimeout(max(end - time.time(), 0.01))
            try:
                d = u.recv(65535)
            except socket.timeout:
                break
            except OSError:
                continue
            if not d.endswith(payload.encode()):
                continue
            print('ECHO %s' % payload, flush=True)
            got += 1
            end = min(end, time.time() + 0.5)
        if not got:
            print('NONE', flush=True)
    elif st == 'eof':
        print('OPEN' if control_open(10) is None else 'EOF', flush=True)
    elif st.startswith('open:'):
        t = control_open(float(st[5:]))
        print('OPEN' if t is None else 'EOF after %.1fs' % t, flush=True)
    elif st.startswith('junk:'):
        threading.Thread(target=junk, args=(st[5:],), daemon=True).start()
    elif st.startswith('ping:'):
        _, host, p = st.split(':', 2)
        threading.Thread(target=ping, args=(host, int(p)),
                         daemon=True).start()
    elif st.startswith('sleep:'):
        time.sleep(float(st[6:]))
    else:
        sys.exit('unknown step ' + st)

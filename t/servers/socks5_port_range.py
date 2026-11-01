#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Drive SOCKS5 tunnels through a proxy that pins a source address, to show how
# many it can carry out of a narrow local port range. Also plays the origins:
# one listener per destination port, each accepting, recording the peer address
# and holding the connection until the proxy closes it.
#
# Three rounds, each on destination ports of its own:
#
#   retire  open a few tunnels, fewer than the range holds, and close them from
#           the client side. The proxy closes first towards the origin, so its
#           sockets end in TIME_WAIT. Then do the same again to other
#           destinations, which must not care about those TIME_WAIT sockets.
#   hold    open several times as many tunnels as the range has ports, all at
#           once. Only the 4-tuple must be unique, so with enough destinations
#           this must fit.
#   exhaust open more tunnels to one destination than the range has ports. The
#           excess is refused, and other destinations stay reachable.
#
# The client's own source port is chosen here, outside the narrow range, so the
# client side never competes for the ports under test.
#
# Usage: socks5_port_range.py <proxy-port> <origin-ip> <source-ip> <first-port>
#                             <range-size>
import selectors
import socket
import struct
import sys
import threading
import time

proxy_port = int(sys.argv[1])
origin_ip = sys.argv[2]
want_src = sys.argv[3]
next_port = int(sys.argv[4])
range_size = int(sys.argv[5])

fam = socket.AF_INET6 if ":" in origin_ip else socket.AF_INET
next_client_port = next_port + 1000
sel = selectors.DefaultSelector()
peers = []
open_conns = 0
lock = threading.Lock()


def origin_thread():
    global open_conns
    while True:
        for key, _ in sel.select():
            s = key.fileobj
            if key.data == "listen":
                c, addr = s.accept()
                with lock:
                    peers.append(addr[0])
                    open_conns += 1
                sel.register(c, selectors.EVENT_READ, "conn")
                continue
            try:
                data = s.recv(4096)
            except OSError:
                data = b""
            if not data:
                sel.unregister(s)
                s.close()
                with lock:
                    open_conns -= 1


def add_origin(port):
    s = socket.socket(fam)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((origin_ip, port))
    s.listen(128)
    sel.register(s, selectors.EVENT_READ, "listen")


def tunnel(port):
    """Open one tunnel to origin port @port; returns (socket, REP or None)."""
    global next_client_port
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(30)
    s.bind(("127.0.0.1", next_client_port))
    next_client_port += 1
    s.connect(("127.0.0.1", proxy_port))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        return s, None
    if fam == socket.AF_INET6:
        atyp = b"\x04" + socket.inet_pton(fam, origin_ip)
    else:
        atyp = b"\x01" + socket.inet_pton(fam, origin_ip)
    s.sendall(b"\x05\x01\x00" + atyp + struct.pack(">H", port))
    hdr = s.recv(4)
    return s, (hdr[1] if len(hdr) > 1 else None)


def wait_until(what, cond):
    for _ in range(600):
        with lock:
            if cond():
                return
        time.sleep(0.05)
    sys.exit("timed out waiting for " + what)


def round_of(label, nr_ports, per_port):
    """Open nr_ports * per_port tunnels; returns the open client sockets."""
    global next_port
    held = []
    with lock:
        del peers[:]
    ports = list(range(next_port, next_port + nr_ports))
    next_port += nr_ports
    for p in ports:
        add_origin(p)
    for p in ports:
        for _ in range(per_port):
            s, rep = tunnel(p)
            if rep != 0:
                sys.exit("%s: tunnel %d of %d was refused, REP %s" %
                         (label, len(held) + 1, nr_ports * per_port, rep))
            held.append(s)
    want = len(held)
    wait_until(label + ": the origins to see every tunnel",
               lambda: len(peers) == want)
    bad = [a for a in peers if a != want_src]
    if bad:
        sys.exit("%s: origin saw source %s, wanted %s" %
                 (label, bad[0], want_src))
    return held


threading.Thread(target=origin_thread, daemon=True).start()

# Round "retire": range_size // 2 + 1 tunnels each time, twice over. Together
# that is more than the range holds, so the second pass only fails if the first
# one's closed sockets still hold their ports.
for i in range(2):
    label = "retire pass %d" % (i + 1)
    conns = round_of(label, 1, range_size // 2 + 1)
    for s in conns:
        s.close()
    wait_until(label + ": the tunnels to close", lambda: open_conns == 0)

# Round "hold": three times the range's ports, over four destinations.
conns = round_of("hold", 4, range_size * 3 // 4)
print("OK %d tunnels held from %s out of %d local ports" %
      (len(conns), want_src, range_size))

# One destination really is limited to the range. Running out must cost only the
# tunnels over the limit, which are told so, and not the proxy's other work.
p = next_port
next_port += 2
add_origin(p)
add_origin(p + 1)
ok = refused = 0
for _ in range(range_size + 2):
    s, rep = tunnel(p)
    conns.append(s)
    if rep == 0:
        ok += 1
    else:
        refused += 1
if not ok or not refused:
    sys.exit("exhaust: %d tunnels opened, %d refused, out of %d local ports" %
             (ok, refused, range_size))
s, rep = tunnel(p + 1)
conns.append(s)
if rep != 0:
    sys.exit("exhaust: another destination was refused too, REP %s" % rep)
for s in conns:
    s.close()

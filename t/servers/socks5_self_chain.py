#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Ask a SOCKS5 proxy to connect to <dst> <dport>, with <n> more requests for the
# same target pipelined behind the first. If <dst> <dport> is the proxy itself
# and it goes along, each request opens another pair of sockets in it, driven by
# the bytes of this one connection.
#
# Prints "REP=0xNN PEAK=<fds>": the first reply, or CLOSED, and how many more
# descriptors the proxy process <pid> held at its peak than before this client.
#
# Usage: socks5_self_chain.py <pid> <port> <dst> <dport> <n> [<host>]
import ipaddress, os, socket, struct, sys, time

pid, port, dst, dport, n = (int(sys.argv[1]), int(sys.argv[2]), sys.argv[3],
                            int(sys.argv[4]), int(sys.argv[5]))
host = sys.argv[6] if len(sys.argv) > 6 else "127.0.0.1"


def nr_fds():
    return len(os.listdir("/proc/%d/fd" % pid))


ip = ipaddress.ip_address(dst)
atyp = b"\x01" if ip.version == 4 else b"\x04"
greet = b"\x05\x01\x00"
req = b"\x05\x01\x00" + atyp + ip.packed + struct.pack("!H", dport)

base = peak = nr_fds()
c = socket.create_connection((host, port), timeout=30)
c.sendall(greet + req + (greet + req) * n)
c.setblocking(False)

buf = b""
end = time.monotonic() + 30
settle = None
while time.monotonic() < end and (settle is None or time.monotonic() < settle):
    peak = max(peak, nr_fds())
    try:
        d = c.recv(4096)
        if not d:
            settle = settle or time.monotonic() + 0.5
        buf += d
    except BlockingIOError:
        pass
    except OSError:
        settle = settle or time.monotonic() + 0.5
    # Method selection, then at least the start of the reply.
    if len(buf) >= 4:
        settle = settle or time.monotonic() + 0.5
    time.sleep(0.01)
c.close()

rep = "REP=0x%02x" % buf[3] if len(buf) >= 4 else "CLOSED"
print("%s PEAK=%d" % (rep, peak - base))

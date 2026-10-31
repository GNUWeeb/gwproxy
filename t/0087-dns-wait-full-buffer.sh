#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that sends more than the proxy's buffer holds right behind a
# request whose name is still being resolved. What it sends waits in the
# client buffer; once that is full the proxy stops reading, but the epoll
# worker used to leave the socket's level-triggered EPOLLIN armed, so it
# woke up for the same unread data on every epoll_wait() and spun at 100%
# CPU until the lookup ended. A name whose server never answers kept a
# worker busy for the whole protocol timeout. The proxy must sit idle while
# it waits, and still deliver every byte once the answer comes.
#
# The lookup is made slow with the raw resolver and a DNS server that
# answers after 2 s, so this runs on epoll only: gwproxy refuses --raw-dns
# together with --event-loop=io_uring (whose recv is never posted into a
# full buffer anyway).

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

dp="$(pick_port)"
python3 "$SERVERS_DIR/dns_malformed.py" slow "$dp" 2>/dev/null &
_PIDS+=("$!")
sleep 0.4

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1

out="$(python3 - "$p" "$GWP_PID" <<'PY'
import socket, struct, sys, threading, time
port, pid = int(sys.argv[1]), int(sys.argv[2])
N = 1 << 20

def ticks():
    with open("/proc/%d/stat" % pid) as f:
        v = f.read().rsplit(")", 1)[1].split()
    return int(v[11]) + int(v[12])

# The origin counts what reaches it and reports the total.
lsock = socket.socket()
lsock.bind(("127.0.0.1", 0))
lsock.listen(1)
def origin():
    c, _ = lsock.accept()
    got = 0
    while got < N:
        d = c.recv(65536)
        if not d:
            break
        got += len(d)
    c.sendall(b"got %d\n" % got)
threading.Thread(target=origin, daemon=True).start()

c = socket.create_connection(("127.0.0.1", port), timeout=10)
c.sendall(b"\x05\x01\x00")
assert c.recv(2) == b"\x05\x00"
name = b"slow.example"
c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
          struct.pack(">H", lsock.getsockname()[1]))

# Push as much as the socket takes while the name is being resolved.
data = b"x" * N
c.setblocking(False)
sent = 0
try:
    while sent < N:
        sent += c.send(data[sent:sent + 65536])
except BlockingIOError:
    pass
c.setblocking(True)
c.settimeout(10)

t0 = ticks()
time.sleep(1.0)
spent = ticks() - t0
if spent > 20:
    print("the worker spun while the lookup was pending (%d ticks in 1 s)" % spent)
    sys.exit(1)

rep = c.recv(10)
if rep[:2] != b"\x05\x00":
    print("no success reply after the lookup: %r" % rep)
    sys.exit(1)
c.sendall(data[sent:])
line = b""
while not line.endswith(b"\n"):
    d = c.recv(64)
    if not d:
        break
    line += d
if line != b"got %d\n" % N:
    print("origin reported %r, want %d bytes (%d sent ahead)" % (line, N, sent))
    sys.exit(1)
print("ok: %d bytes sent ahead of the reply, %d ticks while waiting" % (sent, spent))
PY
)" || fail "$out"
diag "$out"

pass

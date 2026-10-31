#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Plain forwarding through an upstream SOCKS5 proxy (-x) must keep a client
# that talks first away from the upstream handshake. The client sends its
# data while the proxy is still negotiating with the upstream, which here
# answers each step in two halves with a pause in between, and some of it
# arrives while half an upstream reply sits in the proxy's buffer. The
# client must get back exactly what it sent (the origin echoes), never a
# piece of the upstream's replies, and a client that half-closes right
# after its data must still get the echo before the EOF.

. "$(dirname "$0")/lib.sh"
require python3

# Echo origin.
op="$(pick_port)"
python3 - "$op" >"$WORK/origin.log" 2>&1 <<-'PY' &
import socket, sys, threading
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "origin did not start on $op"

# A slow SOCKS5 upstream: every reply arrives in two halves, 0.3 s apart.
up="$(pick_port)"
python3 - "$up" >"$WORK/upstream.log" 2>&1 <<-'PY' &
import socket, sys, threading, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
def recvn(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise OSError("eof")
        b += d
    return b
def slow(c, b):
    c.sendall(b[:1])
    time.sleep(0.3)
    c.sendall(b[1:])
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
        b.shutdown(socket.SHUT_WR)
    except OSError:
        pass
def h(c):
    try:
        g = recvn(c, 2)
        recvn(c, g[1])
        slow(c, b"\x05\x00")
        req = recvn(c, 4)
        if req[3] != 1:
            return
        a = recvn(c, 6)
        o = socket.create_connection((socket.inet_ntoa(a[:4]),
                                      int.from_bytes(a[4:], "big")))
        slow(c, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        threading.Thread(target=pipe, args=(o, c), daemon=True).start()
        pipe(c, o)
        time.sleep(1)
    except OSError:
        pass
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
_PIDS+=("$!")
wait_listen "$up" "$!" || fail "upstream did not start on $up"

# probe <port> <half>: send "hel" at once and "lo" 0.15 s later, in the middle
# of the upstream's first pause (then SHUT_WR when <half> is 1), and print
# everything received until EOF or a 3 s lull, as hex.
probe()
{
	python3 - "$@" <<-'PY'
	import socket, sys, time
	c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
	c.settimeout(3)
	c.sendall(b"hel")
	time.sleep(0.15)
	c.sendall(b"lo")
	if sys.argv[2] == "1":
	    c.shutdown(socket.SHUT_WR)
	got = b""
	try:
	    while True:
	        d = c.recv(4096)
	        if not d:
	            break
	        got += d
	except socket.timeout:
	    pass
	print(got.hex() or "-")
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$op" \
		--upstream-proxy="socks5://127.0.0.1:$up" \
		--event-loop="$loop" --nr-workers=1
	for half in 0 1; do
		got="$(probe "$pp" "$half")"
		diag "[$loop] half-close=$half: got $got"
		[ "$got" = 68656c6c6f ] || \
			fail "[$loop] half-close=$half: expected the echo of hello, got $got"
	done
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

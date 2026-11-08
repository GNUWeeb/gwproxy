#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A socket hangs up once both directions have ended, and EPOLLHUP cannot be
# masked, so the proxy has to stop watching one that hung up while the pair
# still has data for the other side. It lost track of that when it had read
# the target's EOF before the client's FIN arrived: with nothing left to wait
# for on the target, its mask was empty, which read as not being registered,
# and the worker spun on the hangup until the client had read everything.
#
# t/0066 meets this order only by chance. Here the client holds back its FIN
# until the proxy has read all the target sends, and reads nothing yet, so the
# proxy still holds data for it. How much fits in the socket depends on the
# kernel's buffer tuning, so a range of sizes is tried, one connection each.
#
# The same can happen with the sides swapped: the proxy reads the client's FIN
# while it has nothing for the client, then the origin's FIN lets it shut the
# client's write side, and the client's fd hangs up while the origin, slow to
# read, has not taken all the client sent. The second half of the test sets
# that up.

. "$(dirname "$0")/lib.sh"
require python3

op="$(pick_port)"
python3 "$SERVERS_DIR/sized_close_origin.py" "$op" >"$WORK/origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "origin did not start on $op"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$op" \
		--event-loop="$loop" --nr-workers=1
	out="$(python3 - "$pp" "$GWP_PID" <<-'PY'
	import os, socket, sys, time

	port, pid = int(sys.argv[1]), sys.argv[2]
	hz = os.sysconf("SC_CLK_TCK")
	idle = 0.5

	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])     # utime + stime

	def settle():
	    quiet, waited = 0, 0.0
	    while quiet < 4 and waited < 3.0:
	        a = ticks()
	        time.sleep(0.05)
	        waited += 0.05
	        quiet = quiet + 1 if ticks() == a else 0

	conns = []
	for kib in range(24, 121, 8):
	    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
	    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1000)
	    c.settimeout(20)
	    c.connect(("127.0.0.1", port))
	    c.sendall(b"%d\n" % (kib * 1024))
	    conns.append((c, kib * 1024))

	# The proxy has now seen the target's EOF wherever the data fits.
	settle()
	time.sleep(0.2)
	for c, _ in conns:
	    c.shutdown(socket.SHUT_WR)
	settle()

	a = ticks()
	time.sleep(idle)
	used = ticks() - a

	for c, n in conns:
	    got = 0
	    while True:
	        d = c.recv(65536)
	        if not d:
	            break
	        got += len(d)
	    c.close()
	    if got != n:
	        print("short %d of %d bytes" % (got, n))
	        sys.exit(1)

	limit = int(idle * hz / 4)
	print("%d ticks while idle (limit %d, %d Hz)" % (used, limit, hz))
	sys.exit(2 if used > limit else 0)
	PY
	)"
	rc=$?
	diag "[$loop] $out"
	case $rc in
	0) ;;
	2) fail "[$loop] the worker spun on a target that hung up after its EOF was read" ;;
	*) fail "[$loop] transfer to the slow client failed: $out" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	# The client-side twin: the client sends its data and its FIN, and the
	# proxy reads both while the origin, slow to read, still has some of
	# it to take. The origin's FIN then ends the client's other direction
	# too, and the client's fd hangs up with data still owed to the
	# target. The client's buffer is made large enough to take each whole
	# request, so the FIN is read whatever the kernel's buffer tuning.
	op2="$(pick_port)"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$op2" \
		--event-loop="$loop" --nr-workers=1 --client-buf-size=4194304
	out="$(python3 - "$pp" "$GWP_PID" "$op2" <<-'PY'
	import os, socket, sys, time

	port, pid, oport = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
	hz = os.sysconf("SC_CLK_TCK")
	idle = 0.5

	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])     # utime + stime

	def settle():
	    quiet, waited = 0, 0.0
	    while quiet < 4 and waited < 3.0:
	        a = ticks()
	        time.sleep(0.05)
	        waited += 0.05
	        quiet = quiet + 1 if ticks() == a else 0

	# A small receive buffer on the origin's side keeps most of each
	# request in the proxy.
	ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
	ls.bind(("127.0.0.1", oport))
	ls.listen(16)
	ls.settimeout(20)

	conns = []
	for kib in (256, 512, 1024, 2048):
	    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    c.settimeout(20)
	    c.connect(("127.0.0.1", port))
	    o, _ = ls.accept()
	    o.settimeout(20)
	    c.sendall(b"x" * (kib * 1024))
	    c.shutdown(socket.SHUT_WR)
	    conns.append((c, o, kib * 1024))

	# The proxy has now read each client's FIN; the origin ends its side.
	settle()
	time.sleep(0.2)
	for _, o, _ in conns:
	    o.shutdown(socket.SHUT_WR)
	settle()

	a = ticks()
	time.sleep(idle)
	used = ticks() - a

	for c, o, n in conns:
	    got = 0
	    while True:
	        d = o.recv(65536)
	        if not d:
	            break
	        got += len(d)
	    o.close()
	    if c.recv(1) != b"":
	        print("the client got bytes from a silent origin")
	        sys.exit(1)
	    c.close()
	    if got != n:
	        print("short %d of %d bytes" % (got, n))
	        sys.exit(1)

	limit = int(idle * hz / 4)
	print("%d ticks while idle (limit %d, %d Hz)" % (used, limit, hz))
	sys.exit(2 if used > limit else 0)
	PY
	)"
	rc=$?
	diag "[$loop] client FIN first: $out"
	case $rc in
	0) ;;
	2) fail "[$loop] the worker spun on a client that hung up after its EOF was read" ;;
	*) fail "[$loop] transfer from the client to the slow origin failed: $out" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

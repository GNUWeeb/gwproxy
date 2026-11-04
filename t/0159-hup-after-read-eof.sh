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

. "$(dirname "$0")/lib.sh"
require python3

op="$(pick_port)"
python3 "$SERVERS_DIR/sized_close_origin.py" "$op" >"$WORK/origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "origin did not start on $op"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

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
done

pass

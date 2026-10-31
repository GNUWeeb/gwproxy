#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A target that half-closes while the proxy holds a full buffer for a client
# that is not reading must not make the worker spin. This is the ordinary
# shape of a download to a slow reader: the origin writes its response and
# closes, and the FIN sits in the proxy's receive queue behind data there is
# no room for yet. The proxy may only act on that FIN once the buffered data
# has gone out, so until then it has to wait without burning CPU.
#
# Each download is done twice: once with the client keeping its side open,
# so the proxy's target socket sees just the origin's FIN (EPOLLRDHUP), and
# once with the client half-closing after its request, so that the origin's
# close leaves the target socket fully hung up (EPOLLHUP) while unread data
# is still queued on it.
#
# The client clamps its MSS so the proxy's send queue towards it stays small
# and predictable; otherwise loopback's 64 KiB MSS lets that queue grow to
# megabytes and the FIN only arrives once nearly everything has been read.
# The size that puts the FIN in the proxy's receive queue while its buffer is
# full depends on the kernel's buffer tuning, so a range of sizes is tried at
# once, one connection each. The client stays idle for a while and then reads
# everything; the proxy's CPU time over that idle period must stay near zero,
# and every byte must arrive. Exercised on every available event loop.
#
# The idle period starts once the proxy has stopped working on the
# transfers' first part: on a slow, busy machine the origin's threads can
# still be writing when the last connection is up, and forwarding that is no
# spin. A proxy that spins never settles, so it is still measured, and a
# failure prints the ticks per tenth of a second, the epoll interest of each
# of the proxy's descriptors and the state of its sockets.

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

	conns = []
	for kib in range(48, 257, 16):
	    for half in (False, True):
	        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
	        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1000)
	        c.settimeout(20)
	        c.connect(("127.0.0.1", port))
	        c.sendall(b"%d\n" % (kib * 1024))
	        if half:
	            c.shutdown(socket.SHUT_WR)
	        conns.append((c, kib * 1024))

	# Let the forwarding of the transfers' first part finish: wait for
	# 0.2 s without a tick, for at most 3 s.
	quiet, waited = 0, 0.0
	while quiet < 4 and waited < 3.0:
	    a = ticks()
	    time.sleep(0.05)
	    waited += 0.05
	    quiet = quiet + 1 if ticks() == a else 0

	slices = []
	for _ in range(int(idle / 0.1)):
	    a = ticks()
	    time.sleep(0.1)
	    slices.append(ticks() - a)
	used = sum(slices)

	diag = []
	limit = int(idle * hz / 4)
	if used > limit:
	    diag.append("settled: %s after %.2f s; ticks per 0.1 s: %s" %
	                ("yes" if quiet >= 4 else "no", waited, slices))
	    fds = "/proc/%s/fd" % pid
	    for fd in sorted(os.listdir(fds), key=int):
	        try:
	            info = open("/proc/%s/fdinfo/%s" % (pid, fd)).read()
	        except OSError:
	            continue
	        if "tfd:" in info:
	            diag += ["epoll fd %s: %s" % (fd, l.strip())
	                     for l in info.splitlines() if l.startswith("tfd:")]
	    try:
	        import subprocess
	        out = subprocess.run(["ss", "-tanpi"], capture_output=True,
	                             text=True).stdout.splitlines()
	        # Each socket is a line naming its owner, then a line of
	        # TCP details.
	        for i, l in enumerate(out):
	            if "pid=%s," % pid in l:
	                diag += out[i:i + 2]
	    except OSError:
	        pass

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

	# Spinning shows up as most of the idle period; allow a quarter of it
	# for a loaded machine and the bookkeeping of the transfer itself.
	print("%d ticks while idle (limit %d, %d Hz)" % (used, limit, hz))
	for l in diag:
	    print("  " + l)
	sys.exit(2 if used > limit else 0)
	PY
	)"
	rc=$?
	diag "[$loop] $out"
	case $rc in
	0) ;;
	2) fail "[$loop] the worker spun while a half-closed target waited for a slow client" ;;
	*) fail "[$loop] transfer to the slow client failed: $out" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

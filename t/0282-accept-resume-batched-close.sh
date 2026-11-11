#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A worker that paused accept on EMFILE resumes ahead of its timed retry once
# enough descriptors have been closed: more than nine per worker. A pair's
# teardown credits all its descriptors at once, and the check used to look at
# the count from before that credit, so closes that came two at a time could
# reach the threshold without anything noticing: a client waiting in the
# backlog then waited for the 5 s retry although the table had room.
#
# One worker, plain forwarding (two descriptors a pair). The limit is lowered
# to what the idle proxy holds plus six pairs; six tunnels fill the table, a
# seventh client waits in the backlog, then five tunnels end, ten descriptors
# in five credits of two. The waiting client must be served well before the
# timed retry. The io_uring loop retries accept every 100 ms and has no such
# threshold, so this is epoll only.

. "$(dirname "$0")/lib.sh"
require python3

tp="$(pick_port)"
p="$(pick_port)"

python3 - "$tp" >"$WORK/target.log" 2>&1 <<-'PY' &
	import socket, sys, threading
	ls = socket.socket()
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ls.bind(("127.0.0.1", int(sys.argv[1])))
	ls.listen(64)

	def echo(c):
	    # Echo until the proxy passes the client's FIN on, then close too,
	    # so the pair ends with both sides done and nothing lingers.
	    while True:
	        try:
	            b = c.recv(4096)
	        except OSError:
	            break
	        if not b:
	            break
	        c.sendall(b)
	    c.close()

	while True:
	    c, _ = ls.accept()
	    threading.Thread(target=echo, args=(c,), daemon=True).start()
PY
tpid=$!
_PIDS+=("$tpid")
wait_listen "$tp" "$tpid" || fail "the target did not listen"

gwp_start "127.0.0.1:$p" --target="127.0.0.1:$tp" --event-loop=epoll \
	--nr-workers=1 --connect-timeout=30 --protocol-timeout=600

out="$(python3 - "$p" "$GWP_PID" <<-'PY'
	import os, resource, socket, sys, time
	port, pid = int(sys.argv[1]), int(sys.argv[2])
	PAIRS = 6

	def nr_fds():
	    return len(os.listdir("/proc/%d/fd" % pid))

	def settled():
	    last, same, end = nr_fds(), 0, time.time() + 20
	    while same < 5 and time.time() < end:
	        time.sleep(0.2)
	        cur = nr_fds()
	        same = same + 1 if cur == last else 0
	        last = cur
	    return last

	def wait_fds(cond, limit=30):
	    end = time.time() + limit
	    while time.time() < end:
	        if cond(nr_fds()):
	            return True
	        time.sleep(0.05)
	    return False

	def tunnel():
	    c = socket.create_connection(("127.0.0.1", port), timeout=30)
	    c.sendall(b"x")
	    if c.recv(1) != b"x":
	        raise RuntimeError("no echo through the tunnel")
	    return c

	base = settled()
	lim = base + 2 * PAIRS
	try:
	    resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, lim))
	except (OSError, ValueError) as e:
	    print("cannot lower the limit: %r" % e)
	    sys.exit(77)

	held = [tunnel() for _ in range(PAIRS)]
	if not wait_fds(lambda n: n >= lim):
	    print("the table did not fill: %d of %d" % (nr_fds(), lim))
	    sys.exit(1)

	# This one finds the table full: accept fails and pauses.
	w = socket.create_connection(("127.0.0.1", port), timeout=30)
	w.settimeout(30)
	time.sleep(0.5)

	for c in held[:5]:
	    c.shutdown(socket.SHUT_WR)
	    c.recv(1)		# the pair's end
	    c.close()
	t0 = time.monotonic()
	# Ten descriptors back, two of them taken again by the waiting client
	# once accept resumes.
	if not wait_fds(lambda n: n <= lim - 8, 10):
	    print("five pairs did not end: %d fds" % nr_fds())
	    sys.exit(1)

	w.sendall(b"y")
	got = w.recv(1)
	dt = time.monotonic() - t0
	if got != b"y":
	    print("the waiting client was not served: %r" % got)
	    sys.exit(1)
	if dt > 2.5:
	    print("the waiting client was served only after %.2f s "
	          "(the timed retry, not the closes)" % dt)
	    sys.exit(1)
	print("base %d limit %d, served %.2f s after the closes" % (base, lim, dt))
	PY
)"
rc=$?
[ $rc -eq 77 ] && skip "$out"
diag "$out"
kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
[ $rc -eq 0 ] || fail "$out"

kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null
grep -q 'Too many open files, pausing accept' "$WORK/gwp.$p.log" ||
	fail "accept never paused; test inconclusive"

pass

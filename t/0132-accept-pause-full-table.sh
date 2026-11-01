#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# While the descriptor table stays full, retrying accept must stay cheap and
# quiet: the worker does not spin on the queued clients and logs the pause
# once. And a descriptor that comes back must be used in the end: a queued
# client is served after one idle client leaves, though one close is far from
# what the accept throttle of the epoll loop waits for, however long that takes
# the retry. The wait outlasts the longest epoll pause, so that a retry finds
# the table still full and has to stop again.
#
# The limit is lowered once the proxy has settled, to leave a few free
# descriptor numbers, which does not depend on how it was built or what it
# inherited.

. "$(dirname "$0")/lib.sh"
require python3

run_leg()
{
	local ev="$1" p log rc out n

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$ev" \
		--nr-workers=1 --protocol-timeout=600
	log="$WORK/gwp.$p.log"

	out="$(python3 - "$p" "$GWP_PID" <<-'PY'
	import os, resource, socket, sys, time
	port, pid = int(sys.argv[1]), int(sys.argv[2])
	EXTRA = 6

	def nr_fds():
	    return len(os.listdir("/proc/%d/fd" % pid))

	def ticks():
	    with open("/proc/%d/stat" % pid) as f:
	        v = f.read().rsplit(")", 1)[1].split()
	    return int(v[11]) + int(v[12])

	def settled():
	    last, same, end = nr_fds(), 0, time.time() + 20
	    while same < 5 and time.time() < end:
	        time.sleep(0.2)
	        cur = nr_fds()
	        same = same + 1 if cur == last else 0
	        last = cur
	    return last

	def greet(c, timeout):
	    c.settimeout(timeout)
	    try:
	        return c.recv(2)
	    except socket.timeout:
	        return None
	    except OSError as e:
	        return repr(e)

	def client():
	    c = socket.create_connection(("127.0.0.1", port), timeout=30)
	    c.sendall(b"\x05\x01\x00")
	    return c

	base = settled()
	# The limit counts descriptor numbers, not open descriptors, and the
	# proxy may have inherited some far up (make's jobserver pipes): leave
	# exactly EXTRA free numbers below the limit.
	used = set(map(int, os.listdir("/proc/%d/fd" % pid)))
	lim, free = 0, 0
	while free < EXTRA:
	    free += lim not in used
	    lim += 1
	try:
	    resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, lim))
	except (OSError, ValueError) as e:
	    print("cannot lower the limit: %r" % e)
	    sys.exit(77)

	idle = []
	for i in range(EXTRA):
	    idle.append(client())
	    got = greet(idle[-1], 30)
	    if got != b"\x05\x00":
	        print("idle client %d was not served: %r" % (i, got))
	        sys.exit(1)

	# The table is full now. These two complete in the kernel and queue.
	q1, q2 = client(), client()
	time.sleep(0.5)
	t0 = ticks()
	time.sleep(6)
	spent = ticks() - t0
	if spent > 120:
	    print("the worker spun with the table full: %d ticks in 6 s" % spent)
	    sys.exit(1)
	got = greet(q1, 0.2)
	if got is not None:
	    print("served with the table full, test inconclusive: %r (%d of %d)" %
	          (got, nr_fds(), lim))
	    sys.exit(1)

	idle.pop().close()
	got = greet(q1, 60)
	if got != b"\x05\x00":
	    print("a queued client was not served after one close: %r" % got)
	    sys.exit(1)

	q1.close()
	got = greet(q2, 60)
	if got != b"\x05\x00":
	    print("the next queued client was not served: %r" % got)
	    sys.exit(1)
	print("base %d limit %d, %d ticks in 6 s" % (base, lim, spent))
	PY
	)"
	rc=$?
	[ $rc -eq 77 ] && skip "$out"
	diag "[$ev] $out"
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$ev] proxy died"
	[ $rc -eq 0 ] || fail "[$ev] $out"

	# The log is block-buffered: read it once the proxy has stopped. A
	# pause per queued client and a few more; a line per io_uring retry
	# would be some sixty for the wait alone.
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	n="$(grep -c 'Too many open files, pausing accept' "$log")"
	[ "$n" -ge 1 ] || fail "[$ev] never paused; test inconclusive"
	[ "$n" -le 6 ] || fail "[$ev] the pause was logged $n times"
}

for ev in epoll io_uring; do
	if [ "$ev" = io_uring ] && ! grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null; then
		diag "gwproxy built without io_uring; skipping that leg"
		continue
	fi
	run_leg "$ev"
done

pass

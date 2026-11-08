#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A worker that pauses accept on EMFILE must resume however the descriptors
# come back. The epoll loop resumed only once the stopped workers themselves
# had closed more than 9 descriptors per worker, so with a limit that leaves
# fewer than that to close, the listeners stayed out of the epoll set for good
# even with the flood gone and nearly nothing open: every new connection
# completed in the kernel and then hung until a restart. It must try again
# after a while, whatever was closed.
#
# The limit is lowered once the proxy has settled, to a few descriptors above
# what it holds when idle, which does not depend on how it was built. Idle
# clients fill the table, then all leave, and every new client must be served.

. "$(dirname "$0")/lib.sh"
require python3

run_leg()
{
	local ev="$1" workers="$2" extra="$3" p log rc out n

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$ev" \
		--nr-workers="$workers" --protocol-timeout=600
	log="$WORK/gwp.$p.log"

	out="$(python3 - "$p" "$GWP_PID" "$extra" "$workers" <<-'PY'
	import os, resource, socket, sys, time
	port, pid, extra, workers = (int(v) for v in sys.argv[1:5])

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

	def wait_fds(want, limit=30):
	    end = time.time() + limit
	    while time.time() < end:
	        if nr_fds() >= want:
	            return True
	        time.sleep(0.05)
	    return False

	base = settled()
	lim = base + extra
	try:
	    resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, lim))
	except (OSError, ValueError) as e:
	    print("cannot lower the limit: %r" % e)
	    sys.exit(77)

	# Well past what fits: those left over find the table full and sit in
	# the backlogs.
	flood = [socket.create_connection(("127.0.0.1", port), timeout=30)
	         for _ in range(extra + 4 * workers)]
	if not wait_fds(lim):
	    print("the table did not fill: %d of %d" % (nr_fds(), lim))
	    sys.exit(1)
	time.sleep(0.5)
	for c in flood:
	    c.close()

	for i in range(10 * workers):
	    c = socket.create_connection(("127.0.0.1", port), timeout=30)
	    c.settimeout(60)
	    try:
	        c.sendall(b"\x05\x01\x00")
	        got = c.recv(2)
	    except OSError as e:
	        got = repr(e)
	    c.close()
	    if got != b"\x05\x00":
	        print("client %d after the flood was not served: %r (%d fds)" %
	              (i, got, nr_fds()))
	        sys.exit(1)
	print("base %d limit %d" % (base, lim))
	PY
	)"
	rc=$?
	[ $rc -eq 77 ] && skip "$out"
	diag "[$ev, $workers workers] $out"
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$ev] proxy died"
	[ $rc -eq 0 ] || fail "[$ev, $workers workers] $out"

	# The log is block-buffered: read it once the proxy has stopped.
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	n="$(grep -c 'Too many open files, pausing accept' "$log")"
	[ "$n" -ge 1 ] || fail "[$ev, $workers workers] never paused; test inconclusive"
	n="$(grep -c 'Resumed accepting new connections' "$log")"
	[ "$n" -ge 1 ] || fail "[$ev, $workers workers] resumption not logged"
}

for ev in epoll io_uring; do
	if [ "$ev" = io_uring ] && ! have_io_uring; then
		diag "no usable io_uring here; skipping that leg"
		continue
	fi
	run_leg "$ev" 1 6
	run_leg "$ev" 4 20
done

pass

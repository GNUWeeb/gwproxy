#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Accept-time fd exhaustion (EMFILE) recovery, for both event loops.
#
# A low RLIMIT_NOFILE is imposed on the proxy (via ulimit, which needs no
# privilege), then it is flooded with held-open connections until accept() hits
# EMFILE. The worker must PAUSE accepting rather than die; once the flood is
# released and descriptors free up, it must resume serving new connections.
# ENFILE is handled by the very same path, so exercising EMFILE covers it too.
# Both loops log the pause and the resumption in the same words. A second leg
# per loop ends the pause by raising the limit, with every client still there.

. "$(dirname "$0")/lib.sh"
require python3

FDLIMIT=96	# low enough to exhaust quickly, high enough for the proxy to start
FLOOD=64	# > the pairs that fit under FDLIMIT, but small enough to keep the
		# kernel accept backlog (and thus the recovery drain) short

# Open one connection to <port> and succeed only if the origin banner "R\n"
# comes back through the proxy (i.e. the proxy accepted and forwarded).
probe_banner()
{
	python3 - "$1" <<-'PY'
	import socket, sys
	try:
	    c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
	    c.settimeout(1)
	    data = c.recv(2)
	    c.close()
	    sys.exit(0 if data == b"R\n" else 1)
	except OSError:
	    sys.exit(1)
	PY
}

run_leg()
{
	local ev="$1"
	local op tp glog olog flog ready origin_pid gwp_pid flood_pid i recovered

	op="$(pick_port)"
	tp="$(pick_port)"
	glog="$WORK/gwp.$ev.log"
	olog="$WORK/origin.$ev.log"
	flog="$WORK/flood.$ev.log"
	ready="$WORK/flood.$ev.ready"
	rm -f "$ready"

	diag "leg: --event-loop=$ev (fd limit=$FDLIMIT, flood=$FLOOD)"

	# Origin: greet each connection with a 2-byte banner, then hold it open
	# so the proxy keeps both descriptors of the pair allocated.
	python3 - "$op" >"$olog" 2>&1 <<-'PY' &
	import socket, sys
	p = int(sys.argv[1])
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("127.0.0.1", p))
	s.listen(4096)
	held = []
	while True:
	    c, _ = s.accept()
	    try:
	        c.sendall(b"R\n")
	    except OSError:
	        pass
	    held.append(c)
	PY
	origin_pid=$!
	_PIDS+=("$origin_pid")
	wait_listen "$op" "$origin_pid" || fail "[$ev] origin did not start"

	# Proxy with a low descriptor limit so it can be driven into EMFILE.
	( ulimit -n "$FDLIMIT"; exec "$GWPROXY" --event-loop="$ev" \
		--target="127.0.0.1:$op" --bind="127.0.0.1:$tp" \
		--acl-allow-all --nr-workers=1 --log-level=4 ) >"$glog" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$tp" "$gwp_pid" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] proxy did not listen"; }

	# Flood: open FLOOD connections and hold them, deliberately NOT reading the
	# forwarded banner. On release the unread data makes the kernel send RST, so
	# the proxy tears the pairs down immediately (freeing descriptors) instead
	# of leaving them half-closed while the origin still holds the far side.
	python3 - "$tp" "$FLOOD" "$ready" >"$flog" 2>&1 <<-'PY' &
	import socket, sys, time
	port, n, ready = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
	cs = []
	for _ in range(n):
	    try:
	        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	        c.settimeout(2)
	        c.connect(("127.0.0.1", port))
	        cs.append(c)
	    except OSError:
	        pass
	open(ready, "w").write(str(len(cs)))
	while True:
	    time.sleep(1)
	PY
	flood_pid=$!
	_PIDS+=("$flood_pid")
	for i in $(seq 1 100); do [ -f "$ready" ] && break; sleep 0.1; done
	[ -f "$ready" ] || fail "[$ev] flood did not open connections"

	# Give the worker a moment to drain the accept storm and hit EMFILE.
	sleep 0.5
	kill -0 "$gwp_pid" 2>/dev/null \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] proxy died under fd exhaustion"; }

	# Release the flood; the freed descriptors must let the proxy resume.
	kill -9 "$flood_pid" 2>/dev/null
	wait "$flood_pid" 2>/dev/null

	recovered=0
	for i in $(seq 1 150); do
		if probe_banner "$tp"; then recovered=1; break; fi
		sleep 0.1
	done

	# Stop the proxy so its block-buffered log is flushed, then confirm it
	# really hit the limit (otherwise the test proved nothing).
	kill -TERM "$gwp_pid" 2>/dev/null
	for i in $(seq 1 50); do kill -0 "$gwp_pid" 2>/dev/null || break; sleep 0.1; done
	kill -9 "$gwp_pid" 2>/dev/null

	grep -q "Too many open files" "$glog" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] never hit EMFILE; test inconclusive"; }
	[ "$recovered" = 1 ] \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] did not recover after fds were freed"; }
	grep -q "Too many open files, pausing accept (tidx=0)" "$glog" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] the accept pause was not logged"; }
	grep -q "Resumed accepting new connections (tidx=0)" "$glog" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev] the accept resumption was not logged"; }

	kill "$origin_pid" 2>/dev/null
	wait "$origin_pid" 2>/dev/null
	diag "[$ev] paused on EMFILE and recovered"
}

# A pause that only time can end: every client stays connected, and the limit
# is raised from outside instead. No descriptor comes back to the proxy, so
# nothing but its own retry (a timer on both loops) can bring accept back, and
# the clients left waiting in the listen backlog meanwhile must all be served
# once it does.
run_raise_leg()
{
	local ev="$1" op tp glog gwp_pid out

	op="$(pick_port)"
	tp="$(pick_port)"
	glog="$WORK/gwp.raise.$ev.log"

	python3 - "$op" >"$WORK/origin.raise.$ev.log" 2>&1 <<-'PY' &
	import socket, sys
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("127.0.0.1", int(sys.argv[1])))
	s.listen(4096)
	held = []
	while True:
	    c, _ = s.accept()
	    try:
	        c.sendall(b"R\n")
	    except OSError:
	        pass
	    held.append(c)
	PY
	_PIDS+=("$!")
	wait_listen "$op" "$!" || fail "[$ev raise] origin did not start"

	# gwproxy raises its soft limit to the hard one at startup, so the
	# limit is lowered once it runs, and the hard one left where it can be
	# raised back to.
	"$GWPROXY" --event-loop="$ev" \
		--target="127.0.0.1:$op" --bind="127.0.0.1:$tp" \
		--acl-allow-all --nr-workers=1 --log-level=3 >"$glog" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$tp" "$gwp_pid" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev raise] proxy did not listen"; }

	out="$(timeout 90 python3 - "$tp" "$gwp_pid" "$glog" "$FLOOD" "$FDLIMIT" <<-'PY'
	import resource, select, socket, sys, time
	port, pid, glog, n, lim = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
	hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)[1]
	resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, hard))

	def paused():
	    with open(glog) as f:
	        return "Too many open files, pausing accept" in f.read()

	cs = []
	for _ in range(n):
	    cs.append(socket.create_connection(("127.0.0.1", port), timeout=5))
	end = time.monotonic() + 10
	while not paused():
	    if time.monotonic() > end:
	        print("accept never paused; inconclusive")
	        sys.exit(1)
	    time.sleep(0.05)
	# The banners that made it before the pause, to tell the waiting ones.
	time.sleep(0.5)
	waiting = [c for c in cs if not select.select([c], [], [], 0)[0]]
	if not waiting:
	    print("no client was left waiting; inconclusive")
	    sys.exit(1)

	soft = 1024 if hard == resource.RLIM_INFINITY else min(1024, hard)
	resource.prlimit(pid, resource.RLIMIT_NOFILE, (soft, hard))
	end = time.monotonic() + 30
	for c in waiting:
	    c.settimeout(max(end - time.monotonic(), 0.01))
	    try:
	        got = c.recv(2)
	    except OSError as e:
	        got = repr(e)
	    if got != b"R\n":
	        print("a client left waiting by the pause got %r after the "
	              "limit was raised" % got)
	        sys.exit(1)
	print("%d waiting clients served" % len(waiting))
	PY
	)" 2>&1 || { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev raise] $out"; }
	kill -0 "$gwp_pid" 2>/dev/null || fail "[$ev raise] proxy died"
	grep -q "Resumed accepting new connections (tidx=0)" "$glog" \
		|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$ev raise] the accept resumption was not logged"; }
	diag "[$ev raise] $out"
	kill "$gwp_pid" 2>/dev/null
	wait "$gwp_pid" 2>/dev/null
}

# The test needs to open FLOOD descriptors of its own; skip if the harness
# itself is too constrained to do so.
soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt $((FLOOD + 64)) ]; then
	skip "harness fd limit ($soft) too low to flood $FLOOD connections"
fi

run_leg epoll
run_raise_leg epoll

if grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null; then
	run_leg io_uring
	run_raise_leg io_uring
else
	diag "gwproxy built without io_uring; skipping that leg"
fi

pass

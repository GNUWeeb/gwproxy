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
		--nr-workers=1 --log-level=4 ) >"$glog" 2>&1 &
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

	kill "$origin_pid" 2>/dev/null
	wait "$origin_pid" 2>/dev/null
	diag "[$ev] paused on EMFILE and recovered"
}

# The test needs to open FLOOD descriptors of its own; skip if the harness
# itself is too constrained to do so.
soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt $((FLOOD + 64)) ]; then
	skip "harness fd limit ($soft) too low to flood $FLOOD connections"
fi

run_leg epoll

if grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null; then
	run_leg io_uring
else
	diag "gwproxy built without io_uring; skipping that leg"
fi

pass

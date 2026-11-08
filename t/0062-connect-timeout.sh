#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --connect-timeout: when the target never completes the TCP handshake, the
# proxy must give up after the timeout and release the connection -- closing
# the client and reclaiming both descriptors. Asserting only that a timeout is
# logged is not enough: an event loop can log it and still hold the pair
# forever, which leaks two fds per attempt and is remotely triggerable. So this
# checks the client-visible outcome (the proxy closes us) and that the
# descriptor count returns to its baseline. Exercised on every available loop.
#
# It also checks that the client is told WHY, in whichever protocol it speaks:
# SOCKS5 REP 0x06 (TTL expired) or HTTP 504. The protocol-handshake timeout
# shares this timer but must stay silent -- the client has not asked for
# anything yet, so there is nothing to answer.

. "$(dirname "$0")/lib.sh"
require python3

# A target that leaves every connect() hanging in SYN_SENT.
python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh.port" 2>"$WORK/bh.log" &
_PIDS+=("$!")
for i in $(seq 1 50); do
	tport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$tport" ] && break
	sleep 0.1
done
[ -n "${tport:-}" ] || fail "blackhole listener did not report its port"

# Connect, then wait for the proxy to close us. Prints the wait in seconds, or
# "OPEN" if the proxy was still holding the connection at the deadline.
# NOTE: <<- strips leading tabs, so the Python below indents with spaces.
wait_for_close() {			# $1=port $2=deadline_secs
	python3 - "$1" "$2" <<-'PY'
	import socket, sys, time
	port, deadline = int(sys.argv[1]), float(sys.argv[2])
	s = socket.create_connection(('127.0.0.1', port))
	s.settimeout(deadline)
	t0 = time.time()
	try:
	    data = s.recv(1)
	except socket.timeout:
	    print('OPEN')
	    sys.exit(0)
	if data:
	    print('DATA')
	    sys.exit(0)
	print('%.2f' % (time.time() - t0))
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tport" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=1

	# The proxy must drop us once the connect timeout expires. A loop that
	# never releases the pair leaves the client hanging instead.
	got="$(wait_for_close "$pp" 8)"
	case "$got" in
	OPEN)	fail "[$loop] proxy never closed the client after --connect-timeout=1" ;;
	DATA)	fail "[$loop] proxy sent payload for a target that never connected" ;;
	[0-9]*)	;;			# closed after $got seconds: correct
	*)	fail "[$loop] connect-timeout probe failed: '$got'" ;;
	esac

	# Descriptors must come back: a pair that is logged as timed out but
	# never freed burns the client fd and the target fd on every attempt.
	nfd() { ls "/proc/$GWP_PID/fd" 2>/dev/null | wc -l; }
	base="$(nfd)"
	# Concurrently: ten independent attempts, each waiting out the same
	# one-second timeout, so this costs about a second rather than ten.
	# Collect only these pids, so the wait below does not block on the
	# servers lib.sh spawned.
	pids=()
	for i in $(seq 1 10); do
		wait_for_close "$pp" 8 >/dev/null &
		pids+=("$!")
	done
	for p in "${pids[@]}"; do
		wait "$p"
	done
	sleep 2
	after="$(nfd)"
	[ "$after" -le $((base + 4)) ] \
		|| fail "[$loop] descriptors leaked on connect timeout: $base -> $after"

	kill "$GWP_PID" 2>/dev/null

	# The client is told why it was dropped, in its own protocol.
	sp="$(pick_port)"
	gwp_start "127.0.0.1:$sp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 --connect-timeout=1 \
		--protocol-timeout=2

	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --dst 127.0.0.1 \
		"$sp" "$tport")"
	[ "$rep" = "REP=0x06" ] \
		|| fail "[$loop] SOCKS5 connect timeout got '$rep' (want REP=0x06)"

	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		-x "http://127.0.0.1:$sp" "http://127.0.0.1:$tport/x")"
	[ "$code" = 504 ] \
		|| fail "[$loop] HTTP connect timeout got $code (want 504)"

	# The same timer also bounds the protocol handshake. A client that
	# never sends a request must simply be closed: answering a CONNECT
	# that was never made would be a protocol violation.
	got="$(python3 - "$sp" <<-'PY'
	import socket, sys
	s = socket.create_connection(('127.0.0.1', int(sys.argv[1])))
	s.settimeout(15)
	try:
	    data = s.recv(64)
	except socket.timeout:
	    print('HUNG')
	    raise SystemExit
	print(repr(data) if data else 'CLOSED')
	PY
	)"
	[ "$got" = CLOSED ] \
		|| fail "[$loop] idle client got '$got' on handshake timeout (want a silent close)"

	kill "$GWP_PID" 2>/dev/null
done

pass

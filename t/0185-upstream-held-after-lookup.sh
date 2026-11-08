#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Through a socks5:// upstream, a client that asks for a name has it looked up
# by the proxy, which then connects to the upstream. On io_uring the pair kept
# saying "lookup" through that connect, so what asks whether a connect is
# under way got it wrong, in two ways checked here on every event loop:
#
#  - held: a SOCKS5 client gets its method reply while the name is looked up
#    and the upstream connected. If that reply is still being sent when the
#    connect completes, the handshake with the upstream waits for it, as it is
#    built in the same buffer, and must start once the reply is out. After a
#    lookup it never did on io_uring: the upstream never got its greeting, and
#    the client waited for --connect-timeout, for ever at 0. A TLS client makes
#    the reply wait on demand: it asks for many KeyUpdates and reads the
#    proxy's answers slowly (t/servers/tls_held_reply.py). The rounds repeat
#    until one held the handshake up (the client had to read before the
#    upstream got its greeting); each must see the upstream greeted and all
#    the client's data through.
#  - timeout: an upstream that never completes the connect is cut short by
#    --connect-timeout. That is the upstream's failure, to be counted against
#    its health, for a SOCKS5 and an HTTP CONNECT alike; after a lookup,
#    io_uring took the timeout for the lookup's and did not count it.

. "$(dirname "$0")/lib.sh"
require python3
require curl
require_opt --upstream-proxy

# held <loop>: the held rounds on one event loop, with a proxy of their own.
held()
{
	local loop="$1" pp up out rc=0

	if ! "$GWPROXY" --help 2>&1 | grep -q -- --tls-cert ||
	   ! command -v openssl >/dev/null 2>&1; then
		skip "$loop held: no TLS listener or no openssl"
	fi
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-nodes -keyout "$WORK/$loop.key" -out "$WORK/$loop.pem" -days 2 \
		-subj '/CN=localhost' >/dev/null 2>&1 ||
		skip "$loop held: openssl could not generate a test certificate"

	pp="$(pick_port)"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/$loop.pem" --tls-key="$WORK/$loop.key" \
		--nr-workers=1 --connect-timeout=0 \
		--upstream-proxy="socks5://127.0.0.1:$up"
	# The client gives up once nothing has moved for a while: the timeout
	# only catches one that hangs.
	timeout 150 python3 "$SERVERS_DIR/tls_held_reply.py" "$pp" "$up" 5 \
		>"$WORK/$loop.held" 2>&1 || rc=$?
	out="$(cat "$WORK/$loop.held")"
	[ "$rc" = 77 ] && skip "$loop held: $out"
	[ "$out" = "not held" ] &&
		skip "$loop held: the client's reply never held the handshake up"
	[ "$out" = ok ] || fail "$loop held: rc=$rc $out"
	return 0
}

# timed_out <loop>: a SOCKS5 and an HTTP CONNECT to a name through an
# upstream that never answers the connect.
timed_out()
{
	local loop="$1" pp bh="" rep code n i

	python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 \
		>"$WORK/$loop.bh" 2>&1 &
	_PIDS+=("$!")
	for i in $(seq 1 100); do
		bh="$(head -n 1 "$WORK/$loop.bh")"
		[ -n "$bh" ] && break
		sleep 0.1
	done
	[ -n "$bh" ] || fail "$loop timeout: the black hole did not start"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=1 \
		--log-level=4 --upstream-proxy="socks5://127.0.0.1:$bh"
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --atyp domain \
		--dst localhost "$pp" 80 2>&1)"
	[ "$rep" = "REP=0x06" ] || fail "$loop timeout: SOCKS5 got $rep"
	code="$(curl -s --max-time 30 --proxytunnel -o /dev/null \
		-w '%{http_connect}' -x "http://127.0.0.1:$pp" \
		http://localhost:80/ 2>&1)"
	[ "$code" = 504 ] || fail "$loop timeout: HTTP CONNECT got $code"
	n="$(grep -c "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$bh, end=timeout, class=upstream)" \
		"$WORK/gwp.$pp.log")"
	[ "$n" = 2 ] ||
		fail "$loop timeout: $n of 2 timeouts counted against the upstream"
	return 0
}

# part <loop>:<check>
part()
{
	"${1#*:}" "${1%:*}"
}

parts=(epoll:held epoll:timed_out)
have_io_uring &&
	parts+=(io_uring:held io_uring:timed_out)
gwp_parallel part "${parts[@]}"

pass

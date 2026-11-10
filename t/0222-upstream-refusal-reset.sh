#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy that refuses a CONNECT and resets the connection right
# behind its refusal: the refusal is the upstream's answer, read before the
# reset, on every event loop. The client gets the upstream's code, the request
# is not redialled, and the servers of a pool are not ejected for it: the
# failure is the destination's, not the server's.
#
# The refusal and the reset reach the proxy while it is stopped, so both wait
# in its socket together (t/servers/refuse_rst_upstream.py).

. "$(dirname "$0")/lib.sh"
require python3
require_opt --upstream-proxy

N=6

# up_start <name> <kind> [<status>]: a refusing upstream; sets UP_PORT.
up_start()
{
	local port

	port="$(pick_port)"
	: >"$WORK/up.$1.log"
	python3 "$SERVERS_DIR/refuse_rst_upstream.py" "$2" "$port" \
		"$WORK/gwp.pid" "$WORK/up.$1.log" ${3:+"$3"} \
		>"$WORK/up.$1.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $1 upstream did not listen"
	UP_PORT="$port"
}

# run_case <loop> <kind> <want REP> [<status>]
run_case()
{
	local loop="$1" kind="$2" want="$3" status="${4:-}" a b pp i out conns
	local acl="$WORK/pool.acl" reps=""

	up_start a "$kind" "$status";	a="$UP_PORT"
	up_start b "$kind" "$status";	b="$UP_PORT"
	{
		echo 'upstream p {'
		echo "	server $kind://127.0.0.1:$a;"
		echo "	server $kind://127.0.0.1:$b;"
		echo '}'
		echo '-A OUTPUT -j UPSTREAM --to p'
		echo '-P OUTPUT ACCEPT'
	} >"$acl"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --acl-file="$acl"
	echo "$GWP_PID" >"$WORK/gwp.pid"
	for i in $(seq 1 "$N"); do
		out="$(timeout 60 python3 "$SERVERS_DIR/socks5_probe.py" "$pp" 9)"
		reps="$reps $out"
	done
	gwp_stop_pids "$GWP_PID"
	conns="$(cat "$WORK/up.a.log" "$WORK/up.b.log" | wc -l)"

	local what="[$loop $kind${status:+ $status}]"
	for out in $reps; do
		[ "$out" = "REP=$want" ] || fail "$what client got:$reps, not REP=$want"
	done
	[ "$conns" = "$N" ] || \
		fail "$what $conns connections to the upstreams for $N requests"
	if grep -q 'ejected for' "$WORK/gwp.$pp.log"; then
		grep 'ejected for' "$WORK/gwp.$pp.log" | sed 's/^/# /' >&2
		fail "$what a server was ejected for its refusals"
	fi
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	run_case "$loop" socks5 0x05
	run_case "$loop" http 0x01 "403 Forbidden"
	run_case "$loop" http 0x05 "504 Gateway Timeout"
	run_case "$loop" http 0x05 "502 Bad Gateway"
done

pass

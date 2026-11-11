#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A peer that sends data and then resets the connection: what it sent before
# the reset is not lost. The kernel keeps it readable ahead of the error, and
# it must reach the other side, followed by an end of stream, on every event
# loop, in plain, SOCKS5 and HTTP CONNECT tunnels and in both directions.
#
#  - The proxy is stopped while the peer sends and resets, so both wait in its
#    socket when it looks again (t/servers/reset_after_data.py "stopped").
#  - A client that does not read while the target fills every buffer on the
#    way and resets: the proxy waits without using the CPU, and the client
#    then gets every byte the proxy acknowledged ("slow").

. "$(dirname "$0")/lib.sh"
require python3

# run_case <loop> <mode> <kind> [<dir>]: one helper run on a proxy of its own.
run_case()
{
	local loop="$1" mode="$2" kind="$3" dir="${4:-}" pp tp out
	local -a args

	pp="$(pick_port)"
	tp="$(pick_port)"
	case "$mode" in
	plain)	args=(--target="127.0.0.1:$tp") ;;
	socks5)	args=(--as-socks5=1) ;;
	http)	args=(--as-http=1) ;;
	esac
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 "${args[@]}"
	out="$(timeout 300 python3 "$SERVERS_DIR/reset_after_data.py" "$kind" \
		"$mode" ${dir:+"$dir"} "$pp" "$GWP_PID" "$tp" 2>&1)"
	gwp_stop_pids "$GWP_PID"
	[ "$out" = ok ] || fail "[$loop $mode $kind $dir] $out"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for mode in plain socks5 http; do
		for dir in tgt cli; do
			run_case "$loop" "$mode" stopped "$dir"
		done
		run_case "$loop" "$mode" slow
	done
done

pass

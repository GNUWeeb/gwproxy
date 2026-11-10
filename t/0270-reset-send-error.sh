#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A peer that resets while the proxy still holds data for it, and whose reset
# the proxy learns of from a failed send: only that peer's side ends. What it
# sent before the reset, which the proxy's kernel acknowledged, still reaches
# the other side in full, followed by an end of stream, on every event loop,
# in plain, SOCKS5 and HTTP CONNECT tunnels and in both directions
# (t/servers/pair_end.py "send-error").

. "$(dirname "$0")/lib.sh"
require python3

# run_case <loop> <mode> <dir>: one helper run on a proxy of its own.
run_case()
{
	local loop="$1" mode="$2" dir="$3" pp tp out
	local -a args

	pp="$(pick_port)"
	tp="$(pick_port)"
	case "$mode" in
	plain)	args=(--target="127.0.0.1:$tp") ;;
	socks5)	args=(--as-socks5=1) ;;
	http)	args=(--as-http=1) ;;
	esac
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 "${args[@]}"
	out="$(timeout 300 python3 "$SERVERS_DIR/pair_end.py" send-error \
		"$mode" "$dir" "$pp" "$GWP_PID" "$tp" 2>&1)"
	gwp_stop_pids "$GWP_PID"
	[ "$out" = ok ] || fail "[$loop $mode $dir] $out"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for mode in plain socks5 http; do
		for dir in tgt cli; do
			run_case "$loop" "$mode" "$dir"
		done
	done
done

pass

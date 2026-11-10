#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A plaintext peer's reset is passed on to the other side as a reset (TCP
# RST), not as a normal end of stream that a protocol delimited by the close
# would take for complete: here with nothing pending, the target or the client
# resetting a plain, SOCKS5 or HTTP CONNECT tunnel, on every event loop
# (t/servers/pair_end.py "reset-idle"). t/0274 covers a reset with data still
# on its way, which is delivered first.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for mode in plain socks5 http; do
		pp="$(pick_port)"
		tp="$(pick_port)"
		case "$mode" in
		plain)	args=(--target="127.0.0.1:$tp") ;;
		socks5)	args=(--as-socks5=1) ;;
		http)	args=(--as-http=1) ;;
		esac
		gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
			"${args[@]}"
		for dir in tgt cli; do
			out="$(timeout 120 python3 "$SERVERS_DIR/pair_end.py" \
				reset-idle "$mode" "$dir" "$pp" "$tp" 2>&1)"
			[ "$out" = ok ] || fail "[$loop $mode $dir] $out"
		done
		gwp_stop_pids "$GWP_PID"
	done
done

pass

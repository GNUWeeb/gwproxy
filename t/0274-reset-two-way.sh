#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A two-way transfer where the target resets: the client, still uploading,
# gets every byte of the response the proxy had acknowledged, and then a
# reset, as the target's stream was cut. Closing its socket while the upload
# goes on, or resetting it at once, would make the kernel throw away what is
# still queued for the client; the proxy waits until the client has taken it
# all. On every event loop, in plain, SOCKS5 and HTTP CONNECT tunnels
# (t/servers/pair_end.py "two-way").

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
		out="$(timeout 300 python3 "$SERVERS_DIR/pair_end.py" two-way \
			"$mode" "$pp" "$tp" rst 2>&1)"
		gwp_stop_pids "$GWP_PID"
		[ "$out" = ok ] || fail "[$loop $mode] $out"
	done
done

pass

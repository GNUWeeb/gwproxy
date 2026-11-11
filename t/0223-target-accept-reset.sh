#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A target that accepts, sends a banner and resets before the proxy has
# looked at its connect: the connect succeeded, so the client gets a success
# reply (REP 0x00, a 200 to a CONNECT) and the banner, then an end of stream,
# in plain, SOCKS5 and HTTP CONNECT mode; an HTTP forwarding request gets the
# response the origin sent before its reset. It must not be taken for a failed
# connect, which would answer the client with a failure (a 502) or dial
# another address. See t/servers/accept_reset_target.py for how the proxy is made to
# see the connect's result only after the reset. On epoll the connect's
# SO_ERROR then reads ECONNRESET, on io_uring the connect completes with it.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue
	for mode in plain socks5 http fwd; do
		pp="$(pick_port)"
		tp="$(pick_port)"
		case "$mode" in
		plain)	args=(--target="127.0.0.1:$tp") ;;
		socks5)	args=(--as-socks5=1) ;;
		http|fwd) args=(--as-http=1) ;;
		esac
		gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
			"${args[@]}"
		out="$(timeout 300 python3 "$SERVERS_DIR/accept_reset_target.py" \
			"$mode" "$pp" "$GWP_PID" "$tp" 2>&1)"
		gwp_stop_pids "$GWP_PID"
		[ "$out" = ok ] || fail "[$loop $mode] $out"
	done
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A target that accepts, sends a banner and resets before the proxy has
# looked at its connect: the connect succeeded, so the client gets a success
# reply (REP 0x00, a 200 to a CONNECT) and the banner, then an end of stream,
# in plain, SOCKS5 and HTTP CONNECT mode. It must not be taken for a failed
# connect, which would answer the client with a failure or dial another
# address. See t/servers/accept_reset_target.py for how the proxy is made to
# see the connect's result only after the reset.
#
# epoll only, for now: io_uring's connect completes with the reset as its
# result in this case too (ECONNRESET), and is still taken for a failure.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll; do
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
		out="$(timeout 300 python3 "$SERVERS_DIR/accept_reset_target.py" \
			"$mode" "$pp" "$GWP_PID" "$tp" 2>&1)"
		gwp_stop_pids "$GWP_PID"
		[ "$out" = ok ] || fail "[$loop $mode] $out"
	done
done

pass

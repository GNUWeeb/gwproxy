#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that sends its request and closes its write side while the
# proxy is still connecting to the target must have both its bytes and
# its FIN delivered once the target is up. The epoll loop takes in what
# the client sends during the connect, and a FIN read then was lost: the
# target, waiting for the end of the request, never answered. With no
# bytes buffered it was worse: the FIN was "sent" before the target
# socket existed, or, in plain forwarding, shut down a socket still in
# SYN_SENT, which aborts the connect. Exercised on every event loop,
# through a SOCKS5 CONNECT, in plain forwarding, and in plain forwarding
# through an upstream SOCKS5 proxy.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1
	for d in data nodata; do
		got="$(timeout 30 python3 "$SERVERS_DIR/connect_eof.py" socks5 "$pp" "$d")"
		[ "$got" = OK ] || fail "[$loop] SOCKS5, $d: $got"
	done
	kill "$GWP_PID" 2>/dev/null

	for d in data nodata; do
		pp="$(pick_port)"
		tp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tp" \
			--event-loop="$loop" --nr-workers=1
		got="$(timeout 30 python3 "$SERVERS_DIR/connect_eof.py" plain "$pp" "$tp" "$d")"
		[ "$got" = OK ] || fail "[$loop] plain forwarding, $d: $got"
		kill "$GWP_PID" 2>/dev/null
	done

	# Through an upstream SOCKS5 proxy, the FIN arrives during the
	# upstream handshake, which waits for the upstream's connect.
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1
	up_pid="$GWP_PID"
	for d in data nodata; do
		pp="$(pick_port)"
		tp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tp" \
			--upstream-proxy="socks5://127.0.0.1:$up" \
			--event-loop="$loop" --nr-workers=1
		got="$(timeout 30 python3 "$SERVERS_DIR/connect_eof.py" plain "$pp" "$tp" "$d")"
		[ "$got" = OK ] || fail "[$loop] via an upstream proxy, $d: $got"
		kill "$GWP_PID" 2>/dev/null
	done
	kill "$up_pid" 2>/dev/null
done

pass

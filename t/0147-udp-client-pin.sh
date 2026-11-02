#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Who the SOCKS5 UDP relay takes for its client. A datagram that does not parse
# must not pin the association to its sender, or anyone sharing the client's IP
# address can blackhole it with one junk byte. Exercised on every available
# event loop.

. "$(dirname "$0")/lib.sh"
require python3

pin() { python3 "$SERVERS_DIR/socks5_udp_pin.py" "$@"; }

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop"
	for c in junk-first first-wins; do
		pin "$pp" "$ep" "$c" || fail "[$loop] $c"
	done
	kill "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Who the SOCKS5 UDP relay takes for its client. A datagram that does not parse
# must not pin the association to its sender, or anyone sharing the client's IP
# address can blackhole it with one junk byte. A request that declares the
# control connection's IP and a port names the client outright, so another port
# on that IP cannot take the association by sending first; anything else it may
# declare can be a NAT's inside view and binds nothing. Exercised on every
# available event loop.

. "$(dirname "$0")/lib.sh"
require python3

pin() { python3 "$SERVERS_DIR/socks5_udp_pin.py" "$@"; }

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

have_v6=0
if python3 -c 'import socket; socket.socket(socket.AF_INET6,socket.SOCK_DGRAM).bind(("::1",0))' 2>/dev/null; then
	have_v6=1
fi

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop"
	for c in junk-first first-wins declared declared-other-ip \
		 declared-port-only declared-addr-only declared-mapped; do
		pin "$pp" "$ep" "$c" || fail "[$loop] $c"
	done
	kill "$GWP_PID" 2>/dev/null

	# An IPv6 client declares its own address.
	if [ "$have_v6" = 1 ]; then
		pp="$(pick_port)"
		gwp_start "[::1]:$pp" --as-socks5=1 --event-loop="$loop"
		for c in first-wins declared; do
			pin --proxy-host ::1 --echo-host 127.0.0.1 "$pp" "$ep" "$c" \
				|| fail "[$loop] IPv6 client: $c"
		done
		kill "$GWP_PID" 2>/dev/null
	fi
done

pass

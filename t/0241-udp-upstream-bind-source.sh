#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Through a pool's socks5:// server, gwproxy's own UDP ASSOCIATE declares
# the address of its control connection to the server, which follows
# --bind-source, and the server takes datagrams only from there (gwproxy
# as the server pins a declared address of the control connection's IP).
# The datagrams left the wildcard-bound relay socket from whichever source
# routing picked, so with --bind-source on another address than that the
# server dropped every one of them.
#
# A front proxy with --bind-source=127.0.0.2 sends a client's datagrams
# through a gwproxy upstream on 127.0.0.1, which routing would reach from
# 127.0.0.1: they must echo back. Then with --bind-iface=lo as well, where
# the kernel lets an unprivileged process bind a socket to an interface. On
# every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --acl-file
require_opt --bind-source

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

iface=
python3 -c 'import socket; socket.socket().setsockopt(socket.SOL_SOCKET, 25, b"lo")' \
	2>/dev/null && iface=--bind-iface=lo

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4
	up_pid="$GWP_PID"
	cat >"$WORK/pool.acl" <<-EOF
	upstream p {
		server socks5://127.0.0.1:$up;
	}
	-A OUTPUT -j UPSTREAM --to p
	-P OUTPUT ACCEPT
	EOF
	chmod 600 "$WORK/pool.acl"
	for opts in --bind-source=127.0.0.2 \
		    ${iface:+"--bind-source=127.0.0.2 $iface"}; do
		fp="$(pick_port)"
		# shellcheck disable=SC2086 # $opts is a list of options
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --log-level=4 \
			--acl-file="$WORK/pool.acl" $opts
		out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" \
			"$fp" send:127.0.0.1:"$ep":one send:127.0.0.1:"$ep":two)"
		want="REP 0
ECHO one
ECHO two"
		if [ "$out" != "$want" ]; then
			sed 's/^/# front: /' "$WORK/gwp.$fp.log" | tail -n 20 >&2
			sed 's/^/# up: /' "$WORK/gwp.$up.log" | tail -n 20 >&2
			fail "[$loop $opts] got '$(echo $out)', want '$(echo $want)'"
		fi
		grep -q 'Upstream UDP association established' \
			"$WORK/gwp.$fp.log" || \
			fail "[$loop $opts] the association did not go through the upstream"
		gwp_stop_pids "$GWP_PID"
	done
	gwp_stop_pids "$(cat /dev/null)"
done

pass

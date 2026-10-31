#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The SOCKS5 UDP relay passes a datagram on to the client as a target's
# reply only when it comes from an address and port the client has sent to,
# and only while the ACL still lets the client send there. Anyone else who
# learns the relay's port must not be able to inject datagrams into the
# association. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	sync="$WORK/sync.$loop"
	mkdir -p "$sync"
	echo '-P OUTPUT ACCEPT' >"$WORK/udp.acl"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp.acl"
	python3 "$SERVERS_DIR/socks5_udp_reply_src.py" "$pp" "$sync" \
		>"$WORK/client.out" 2>&1 &
	cpid=$!
	_PIDS+=("$cpid")

	for _ in $(seq 1 200); do
		[ -s "$sync/port" ] && break
		kill -0 "$cpid" 2>/dev/null || break
		sleep 0.1
	done
	[ -s "$sync/port" ] || { sed 's/^/# /' "$WORK/client.out" >&2;
		fail "[$loop] replies were relayed from the wrong sources"; }

	# Deny the second target and wait for the reload to land.
	printf -- '%s\n' "-A OUTPUT -p udp --dports $(cat "$sync/port") -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/udp.new"
	mv -f "$WORK/udp.new" "$WORK/udp.acl"
	for _ in $(seq 1 100); do
		grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" && break
		sleep 0.1
	done
	grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" \
		|| fail "[$loop] ACL was not reloaded"
	touch "$sync/go"

	wait "$cpid" || { sed 's/^/# /' "$WORK/client.out" >&2;
		fail "[$loop] replies were relayed from the wrong sources"; }
	kill "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The UDP relay reuses an association's last OUTPUT verdict while the target
# and the ACL stay the same. Within ONE association that reuse must never be
# visible: (a) a verdict is per target, (b) an ACL reload takes effect for the
# next datagram, and (c) a -m statistic rule still counts every datagram.
# Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

start_udp_echo 127.0.0.1
e1="$UDP_ECHO_PORT"
start_udp_echo 127.0.0.1
e2="$UDP_ECHO_PORT"
steps="$SERVERS_DIR/socks5_udp_steps.py"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# (a) + (b): e2 is denied, e1 allowed until the reload denies it too.
	printf -- '%s\n' "-A OUTPUT -p udp --dports $e2 -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/udp.acl"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/udp.acl"
	rm -f "$WORK/reached" "$WORK/go"
	python3 "$steps" "$pp" "echo:$e1" "drop:$e2" "echo:$e1" "echo:$e1" \
		"touch:$WORK/reached" "wait:$WORK/go" "drop:$e1" \
		>"$WORK/steps.out" 2>&1 &
	cpid=$!
	_PIDS+=("$cpid")
	for _ in $(seq 1 200); do
		[ -e "$WORK/reached" ] && break
		kill -0 "$cpid" 2>/dev/null || break
		sleep 0.1
	done
	[ -e "$WORK/reached" ] || { cat "$WORK/steps.out" >&2;
		fail "[$loop] per-target UDP verdicts were wrong"; }
	printf -- '%s\n' "-A OUTPUT -p udp --dports $e1 -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/udp.new"
	mv -f "$WORK/udp.new" "$WORK/udp.acl"
	for _ in $(seq 1 100); do
		grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" && break
		sleep 0.1
	done
	grep -q "Reloaded ACL file" "$WORK/gwp.$pp.log" \
		|| fail "[$loop] ACL was not reloaded"
	touch "$WORK/go"
	wait "$cpid" || { cat "$WORK/steps.out" >&2;
		fail "[$loop] a reloaded ACL did not apply to the association"; }
	kill "$GWP_PID" 2>/dev/null

	# (c) Every other datagram to e1 is rejected, not every other flow.
	printf -- '%s\n' \
		"-A OUTPUT -p udp --dports $e1 -m statistic --mode nth --every 2 -j REJECT" \
		'-P OUTPUT ACCEPT' >"$WORK/stat.acl"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--acl-file="$WORK/stat.acl"
	out="$(python3 "$steps" "$pp" "count:8:$e1")" \
		|| fail "[$loop] statistic UDP client failed: $out"
	echo "$out" | grep -qx 'count=4' \
		|| fail "[$loop] -m statistic over UDP: $out (want count=4)"
	kill "$GWP_PID" 2>/dev/null
done

pass

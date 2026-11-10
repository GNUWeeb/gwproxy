#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A failure reply is followed by a normal close (FIN), not a reset, also when
# the client sent more behind its request than the proxy read: a close with
# unread input, or more input after it, resets the connection, which throws
# away the reply on stacks that drop received data on a reset, or when it
# still needs to be retransmitted. The proxy lingers on the socket instead:
# it shuts its write side, discards the input until the client is done, and
# then closes. On every event loop (t/servers/pair_end.py "fail-reply"):
#
#  - SOCKS5 and HTTP CONNECT to a target that never answers, with data sent
#    during the connect, below and above --client-buf-size: REP 0x06 or 504;
#  - an HTTP POST still uploading its 4 MiB body when refused with 407.

. "$(dirname "$0")/lib.sh"
require python3

python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh.port" \
	2>"$WORK/bh.log" &
_PIDS+=("$!")
for i in $(seq 1 50); do
	tport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$tport" ] && break
	sleep 0.1
done
[ -n "${tport:-}" ] || fail "blackhole listener did not report its port"

printf 'user:pass\n' >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-socks5=1 --as-http=1 --connect-timeout=1 \
		--client-buf-size=16384
	for c in "s5-late 50" "s5-late 300000" "http-late 50" \
		 "http-late 300000"; do
		# shellcheck disable=SC2086
		out="$(timeout 120 python3 "$SERVERS_DIR/pair_end.py" \
			fail-reply $c "$pp" "$tport" 2>&1)"
		[ "$out" = ok ] || fail "[$loop] $out"
	done
	gwp_stop_pids "$GWP_PID"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --auth-file="$WORK/auth"
	out="$(timeout 120 python3 "$SERVERS_DIR/pair_end.py" \
		fail-reply http-upload $((4 << 20)) "$pp" "$tport" 2>&1)"
	[ "$out" = ok ] || fail "[$loop] $out"
	gwp_stop_pids "$GWP_PID"
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A connect timeout that runs out in the same batch of events as the
# upstream's refusal, the refusal first, must not answer the client a second
# time. The io_uring loop handled the timer of a pair it had already failed:
# it logged "Connection timeout!", charged the upstream a timeout, and wrote
# a 504 into target.buf under the send of the 502 that was prepared but not
# yet submitted, so the client got the first 66 bytes of the 504, without its
# final CRLF CRLF. The proxy is stopped across its deadline while the
# upstream refuses, so both come in together; an HTTP client through an
# http:// upstream and a SOCKS5 client through a socks5:// one must each get
# one complete answer, and the log may say "Connection timeout!" only when
# that answer is the timeout's. Both loops.

. "$(dirname "$0")/lib.sh"
require python3

ROUNDS=3
CT=2

run()					# $1=loop/mode
{
	local loop="${1%/*}" mode="${1#*/}" p up i got n

	[ "$loop" = io_uring ] && ! have_io_uring && skip "no io_uring"
	p="$(pick_port)"
	up="$(pick_port)"
	if [ "$mode" = http ]; then
		set -- --as-http=1 --upstream-proxy="http://127.0.0.1:$up"
	else
		set -- --as-socks5=1 --upstream-proxy="socks5://127.0.0.1:$up"
	fi
	gwp_start "127.0.0.1:$p" "$@" --event-loop="$loop" --nr-workers=1 \
		--connect-timeout="$CT"
	for i in $(seq 1 "$ROUNDS"); do
		n="$(wc -l <"$WORK/gwp.$p.log")"
		got="$(timeout 60 python3 \
			"$SERVERS_DIR/upstream_refuses_at_deadline.py" \
			"$mode" "$p" "$up" "$GWP_PID" "$CT")"
		diag "[$loop/$mode] round $i: $got"
		case "$got" in
		"OK upstream")
			if tail -n "+$((n + 1))" "$WORK/gwp.$p.log" |
			   grep -q 'Connection timeout!'; then
				sed 's/^/# gwp: /' "$WORK/gwp.$p.log" >&2
				fail "[$loop/$mode] a timeout logged for a pair the upstream refused"
			fi ;;
		"OK timeout") ;;
		*)
			sed 's/^/# gwp: /' "$WORK/gwp.$p.log" >&2
			fail "[$loop/$mode] round $i: $got" ;;
		esac
	done
}

gwp_parallel run epoll/http epoll/socks5 io_uring/http io_uring/socks5
pass

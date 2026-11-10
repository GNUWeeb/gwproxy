#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A connect timeout during the handshake with a plaintext upstream proxy, on
# io_uring, while a recv of the upstream's reply is in flight. The reply is
# read into target.buf, and the timeout wrote the client's answer (SOCKS5 REP
# 0x06, HTTP 504) into target.buf as well, at its start, and queued its send
# from there. Whatever the upstream sent before that send went out landed on
# the answer: the client got the upstream's grant and the start of the
# tunnel in its place (a SOCKS5 "05 00", an HTTP 200), followed by EOF.
#
# A preload shim (t/servers/hold_at_log_line.c) holds the worker right after
# the timer's handling has written the answer, at its debug line "Timer event
# handled (... res=-62)", while the upstream sends its grant; then the worker
# goes on. An HTTP client through an http:// upstream and a SOCKS5 client
# through a socks5:// one must each get the timeout answer, complete, and
# nothing else.

. "$(dirname "$0")/lib.sh"
require python3
require_io_uring

[ "$(uname -m)" = x86_64 ] || skip "the shim is x86-64 only"
built=""
for cc in cc gcc clang; do
	command -v "$cc" >/dev/null 2>&1 || continue
	"$cc" -shared -fPIC -O1 -o "$WORK/shim.so" \
		"$SERVERS_DIR/hold_at_log_line.c" 2>"$WORK/cc.log" && built=1 && break
done
[ -n "$built" ] || skip "cannot build the shim: $(head -1 "$WORK/cc.log" 2>/dev/null)"

CT=2

run()					# $1=mode
{
	local mode="$1" p up hold real wrap got

	p="$(pick_port)"
	up="$(pick_port)"
	hold="$WORK/hold.$mode"
	real="$GWPROXY"
	wrap="$WORK/gwproxy-shim.$mode"
	# The shim goes into the proxy alone, as in t/0250.
	cat >"$wrap" <<-WRAP
		#!/bin/sh
		HOLD_AT_LOG="Timer event handled" HOLD_AT_LOG2="res=-62)" \
		HOLD_FILE="$hold" LD_PRELOAD="$WORK/shim.so" \
		ASAN_OPTIONS="\${ASAN_OPTIONS:+\$ASAN_OPTIONS:}verify_asan_link_order=0" \
		exec "$real" "\$@"
	WRAP
	chmod +x "$wrap"
	HOLD_AT_LOG=x HOLD_FILE="$hold" "$wrap" --help >/dev/null 2>&1
	[ "$?" != 99 ] || skip "the shim cannot install its seccomp filter here"

	if [ "$mode" = http ]; then
		set -- --as-http=1 --upstream-proxy="http://127.0.0.1:$up"
	else
		set -- --as-socks5=1 --upstream-proxy="socks5://127.0.0.1:$up"
	fi
	GWPROXY="$wrap" gwp_start "127.0.0.1:$p" "$@" --event-loop=io_uring \
		--nr-workers=1 --connect-timeout="$CT" --log-level=4
	got="$(timeout 90 python3 "$SERVERS_DIR/upstream_answers_while_held.py" \
		"$mode" "$p" "$up" "$hold")"
	diag "[$mode] $got"
	if [ "$got" != "OK timeout" ]; then
		grep -v 'Put connection pair\|Get connection pair' \
			"$WORK/gwp.$p.log" | tail -n 60 | sed 's/^/# gwp: /' >&2
		fail "[$mode] $got"
	fi
	kill "$GWP_PID" 2>/dev/null
}

gwp_parallel run http socks5
pass

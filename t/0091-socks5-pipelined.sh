#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 client that does not wait for each reply sends its greeting,
# credentials, request and first tunnel bytes in one write. The proxy
# parsed it all on the first read but only answered the greeting: the
# request was acted on when the client sent more, which a client waiting
# for its reply never does, so the connection hung until the protocol
# timeout. A pipelined CONNECT (with and without authentication) must be
# answered and tunnelled, and a pipelined UDP ASSOCIATE answered.
# Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

printf 'pipe:lined\n' >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1
	for cmd in connect udp; do
		got="$(python3 "$SERVERS_DIR/socks5_pipeline.py" "$p" "$cmd")"
		[ "$got" = OK ] || fail "[$loop] pipelined $cmd: $got"
	done
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 \
		--auth-file="$WORK/auth" --event-loop="$loop" --nr-workers=1
	got="$(python3 "$SERVERS_DIR/socks5_pipeline.py" "$p" connect \
		--user pipe --pass lined)"
	[ "$got" = OK ] || fail "[$loop] pipelined authenticated connect: $got"
	kill "$GWP_PID" 2>/dev/null
done

pass

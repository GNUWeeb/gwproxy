#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTP CONNECT proxy authentication (RFC 7617 "Basic"): a proxy started with
# an --auth-file must (a) accept a client that presents the correct
# username/password and tunnel the payload byte-exact, (b) reject a client
# with a wrong password, and (c) reject a client that presents no credentials
# at all. The credential store is the same one used for SOCKS5. Exercised on
# every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# Credential store shared with SOCKS5: one "username:password" line.
printf 'testuser:s3cr3t\n' >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-http=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2

	# (a) Correct credentials: the CONNECT tunnel is established (curl answers
	#     the 407 challenge with a Basic Proxy-Authorization) and the bytes
	#     arrive intact.
	curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" -U testuser:s3cr3t \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/ok.bin" \
		|| fail "[$loop] curl with correct HTTP proxy credentials failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/ok.bin" \
		"[$loop] authenticated HTTP CONNECT proxy corrupted the payload"

	# (b) Wrong password: curl must fail and must not receive the payload.
	rm -f "$WORK/bad.bin"
	if curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" -U testuser:wrong \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/bad.bin"; then
		fail "[$loop] curl with wrong HTTP proxy password unexpectedly succeeded"
	fi
	if cmp -s "$WORK/payload.bin" "$WORK/bad.bin"; then
		fail "[$loop] wrong-password client received the correct payload"
	fi

	# (c) No credentials at all: curl must fail and must not receive the payload.
	rm -f "$WORK/none.bin"
	if curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/none.bin"; then
		fail "[$loop] curl with no HTTP proxy credentials unexpectedly succeeded"
	fi
	if cmp -s "$WORK/payload.bin" "$WORK/none.bin"; then
		fail "[$loop] unauthenticated client received the correct payload"
	fi

	kill "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream HTTP-proxy chaining (--upstream-proxy=http://...): a front proxy
# routes every outgoing connection through an upstream HTTP proxy via an HTTP
# CONNECT handshake. Verify a payload survives the chain byte-for-byte with a
# SOCKS5 and an HTTP front, across every available front-end event loop, and
# that upstream Basic auth is honoured (correct creds relay, wrong creds fail).

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp
require_opt "--upstream-proxy"

hp="$(pick_port)"
up="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# A single upstream HTTP proxy shared by the no-auth cases below.
gwp_start "[::1]:$up" --as-http=1 --event-loop=epoll --nr-workers=2
up_pid="$GWP_PID"

for front in socks5 http; do
	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

		fp="$(pick_port)"
		gwp_start "[::1]:$fp" --as-$front=1 --event-loop="$loop" \
			--nr-workers=2 --upstream-proxy="http://[::1]:$up"
		if [ "$front" = socks5 ]; then
			cproxy="socks5h://[::1]:$fp"
		else
			cproxy="http://[::1]:$fp"
		fi
		curl -s --max-time 20 --proxy "$cproxy" \
			"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
			|| fail "[$front/$loop] curl through HTTP chain failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$front/$loop] HTTP chain corrupted the payload"
		kill "$GWP_PID" 2>/dev/null
	done
done

kill "$up_pid" 2>/dev/null	# stop the no-auth upstream before reusing the port
wait "$up_pid" 2>/dev/null

# Authenticated upstream: the HTTP proxy demands RFC 7617 Basic credentials,
# which the front carries in its --upstream-proxy URL.
up="$(pick_port)"
printf 'up:pw\n' >"$WORK/auth"
gwp_start "[::1]:$up" --as-http=1 --auth-file="$WORK/auth" \
	--event-loop=epoll --nr-workers=2

# (a) Correct upstream credentials: the chain relays the payload intact.
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=2 \
	--upstream-proxy="http://up:pw@[::1]:$up"
curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/ok.bin" \
	|| fail "curl through authenticated HTTP chain failed"
assert_files_equal "$WORK/payload.bin" "$WORK/ok.bin" \
	"authenticated HTTP chain corrupted the payload"
kill "$GWP_PID" 2>/dev/null

# (b) Wrong upstream password: the upstream 407s the CONNECT, so the fetch
# fails and must not yield the payload.
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=2 \
	--upstream-proxy="http://up:bad@[::1]:$up"
rm -f "$WORK/bad.bin"
if curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/bad.bin"; then
	fail "curl with wrong upstream HTTP password unexpectedly succeeded"
fi
if cmp -s "$WORK/payload.bin" "$WORK/bad.bin"; then
	fail "wrong-upstream-password front received the correct payload"
fi

pass

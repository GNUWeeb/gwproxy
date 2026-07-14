#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream SOCKS5 chaining with authentication: a front SOCKS5 proxy routes
# every outgoing connection through an upstream SOCKS5 proxy that enforces
# RFC1929 username/password auth. The front carries the upstream credentials
# embedded in its --upstream-socks5 URL. Verify that (a) a front presenting the
# CORRECT upstream credentials relays a payload through the chain byte-exact,
# and (b) a front presenting the WRONG upstream password cannot complete the
# fetch. The client speaks plain (unauthenticated) SOCKS5 to the front; only
# the upstream demands auth. The front runs on epoll.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp
require_opt "--upstream-socks5"

hp="$(pick_port)"
up="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# The upstream SOCKS5 proxy requires one RFC1929 "username:password" line.
printf 'up:pw\n' >"$WORK/auth"
gwp_start "[::1]:$up" --as-socks5=1 --socks5-auth-file="$WORK/auth" \
	--event-loop=epoll --nr-workers=2

# (a) Front configured with the CORRECT upstream credentials: the transfer
# succeeds and the bytes survive the whole chain intact.
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=2 \
	--upstream-socks5="socks5://up:pw@[::1]:$up"
curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/ok.bin" \
	|| fail "curl through authenticated SOCKS5 chain failed"
assert_files_equal "$WORK/payload.bin" "$WORK/ok.bin" \
	"authenticated SOCKS5 chain corrupted the payload"
kill "$GWP_PID" 2>/dev/null

# (b) Front configured with the WRONG upstream password: the upstream rejects
# the front's RFC1929 auth, so the fetch must fail and must not yield the
# payload.
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=2 \
	--upstream-socks5="socks5://up:bad@[::1]:$up"
rm -f "$WORK/bad.bin"
if curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/bad.bin"; then
	fail "curl with wrong upstream SOCKS5 password unexpectedly succeeded"
fi
if cmp -s "$WORK/payload.bin" "$WORK/bad.bin"; then
	fail "wrong-upstream-password front received the correct payload"
fi
kill "$GWP_PID" 2>/dev/null

pass

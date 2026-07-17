#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Forwarding HTTP proxy (absolute-form requests, not CONNECT): curl in plain
# proxy mode sends "GET http://host/path HTTP/1.1" to gwproxy, which rewrites
# it to origin-form, fetches it from the origin and relays the response. Verify
# the payload arrives intact for an IPv4-literal target and a hostname target
# (which makes gwproxy resolve the name), on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-http=1 --event-loop="$loop" --nr-workers=2

	# IPv4-literal target. No --proxytunnel: curl issues a plain forward-proxy
	# GET with an absolute-form request-target.
	curl -s --max-time 20 -x "http://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl via HTTP forward proxy to IPv4 target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] HTTP forward proxy corrupted the payload (ipv4)"

	# Hostname target -> gwproxy resolves "localhost" before connecting.
	curl -s --max-time 20 -x "http://[::1]:$pp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out2.bin" \
		|| fail "[$loop] curl via HTTP forward proxy to hostname target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out2.bin" \
		"[$loop] HTTP forward proxy corrupted the payload (hostname)"

	kill "$GWP_PID" 2>/dev/null
done

pass

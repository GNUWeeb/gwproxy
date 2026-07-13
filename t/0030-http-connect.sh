#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTP CONNECT proxy: force curl to open a CONNECT tunnel through gwproxy's
# HTTP mode to an IPv4 target and verify the tunneled payload arrives intact.
# HTTP mode is only implemented on the epoll event loop, so it is the only
# loop exercised here.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

pp="$(pick_port)"
gwp_start "[::1]:$pp" --as-http=1 --event-loop=epoll --nr-workers=2
curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
	|| fail "curl via HTTP CONNECT tunnel failed"
assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
	"HTTP CONNECT proxy corrupted the payload"
kill "$GWP_PID" 2>/dev/null

pass

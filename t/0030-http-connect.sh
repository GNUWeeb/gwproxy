#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTP CONNECT proxy: force curl to open a CONNECT tunnel through gwproxy's
# HTTP mode and verify the tunneled payload arrives intact, on every available
# event loop. Both an IPv4-literal target and a hostname target (which makes
# gwproxy resolve the name itself) are exercised.

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

	# IPv4-literal target.
	curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl via HTTP CONNECT to IPv4 target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] HTTP CONNECT proxy corrupted the payload (ipv4)"

	# Hostname target -> gwproxy resolves "localhost" before connecting.
	curl -s --max-time 20 --proxytunnel -x "http://[::1]:$pp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out2.bin" \
		|| fail "[$loop] curl via HTTP CONNECT to hostname target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out2.bin" \
		"[$loop] HTTP CONNECT proxy corrupted the payload (hostname)"

	kill "$GWP_PID" 2>/dev/null
done

pass

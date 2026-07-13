#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Peer-close data integrity: when the target sends its response and then closes
# the connection (HTTP/1.0 / Connection: close) with data still buffered in the
# proxy, every byte must still reach the client before the pair is torn down.
# The payload is larger than the proxy's forwarding buffer so a truncation on
# close is visible. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 300000
# HTTP/1.0 makes the server close the connection right after the response.
start_httpd "$hp" "$WORK" "1.0"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1
	curl -s --max-time 20 --proxy "socks5h://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl via SOCKS5 (HTTP/1.0 close) failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] proxy truncated data when the target closed"
	kill "$GWP_PID" 2>/dev/null
done

pass

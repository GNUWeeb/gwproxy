#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Plain TCP proxy (--target): bytes must be forwarded verbatim in both
# directions. Verified end to end by fetching a payload through the proxy.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
pp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=2 \
		--target="127.0.0.1:$hp"
	curl -s --max-time 20 "http://127.0.0.1:$pp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl through plain proxy failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] plain proxy corrupted the payload"
	kill "$GWP_PID" 2>/dev/null
done

pass

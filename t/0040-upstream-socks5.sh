#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream SOCKS5 chaining (--upstream-socks5): a front SOCKS5 proxy routes
# every outgoing connection through a second (upstream) SOCKS5 proxy. Verify a
# payload survives the whole chain byte-for-byte for both URL schemes --
# socks5:// (the front resolves the target) and socks5h:// (the upstream
# resolves it) -- across every available front-end event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-socks5"

hp="$(pick_port)"
up="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# A single upstream SOCKS5 proxy shared by every front-end below. Killed
# automatically on exit; GWP_PID is reassigned to each front-end as it starts.
gwp_start "[::1]:$up" --as-socks5=1 --event-loop=epoll --nr-workers=2

for scheme in socks5 socks5h; do
	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

		fp="$(pick_port)"
		gwp_start "[::1]:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --upstream-socks5="$scheme://[::1]:$up"
		curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
			"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
			|| fail "[$scheme/$loop] curl through SOCKS5 chain failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$scheme/$loop] SOCKS5 chain corrupted the payload"
		kill "$GWP_PID" 2>/dev/null
	done
done

pass

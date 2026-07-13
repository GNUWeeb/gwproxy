#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Client half-close data integrity: a client that sends its request, shuts
# down its own write side (SHUT_WR), and then reads the response must still
# receive the whole response. The proxy must treat the client's write-side EOF
# as a half-close -- propagating the FIN to the target while continuing to
# deliver the target's (larger) response -- rather than tearing the pair down
# and dropping the reply. The payload is larger than the forwarding buffer so
# any dropped bytes are visible. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 300000
# HTTP/1.0 so the target closes after the response, combining a client
# half-close with a target close in one exchange.
start_httpd "$hp" "$WORK" "1.0"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--target="127.0.0.1:$hp"
	timeout 20 python3 "$SERVERS_DIR/halfclose_client.py" \
		127.0.0.1 "$pp" "/payload.bin" "$WORK/out.bin" \
		|| fail "[$loop] half-close client failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] proxy dropped response data on client half-close"
	kill "$GWP_PID" 2>/dev/null
done

pass

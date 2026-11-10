#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The lingering close costs little and is bounded: 100 clients refused with
# 407 while they keep uploading each get the reply and an EOF; the proxy holds
# their sockets while they send, gives up on them after its bound, and is
# then back at the descriptors it had before, with no CPU used, on every event
# loop (t/servers/pair_end.py "linger-load").

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --auth-file="$WORK/auth"
	out="$(timeout 120 python3 "$SERVERS_DIR/pair_end.py" linger-load 100 \
		"$pp" "$GWP_PID" 2>&1)"
	gwp_stop_pids "$GWP_PID"
	[ "$out" = ok ] || fail "[$loop] $out"
done

pass

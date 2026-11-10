#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An origin that resets before it has sent a complete response header to a
# forwarded request ("GET http://..."): the client gets a 502, as it does from
# an origin that closes at that point, not an empty reply, on every event
# loop. The origin resets after reading the request, after part of a header,
# or right after the accept, before the request has reached it, which the
# proxy may learn of from a failed send of the request
# (t/servers/pair_end.py "origin-reset").

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	op="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1
	for how in rst part-rst accept-rst part-fin; do
		out="$(timeout 300 python3 "$SERVERS_DIR/pair_end.py" \
			origin-reset "$how" "$pp" "$op" 10 2>&1)"
		[ "$out" = ok ] || fail "[$loop $how] $out"
	done
	gwp_stop_pids "$GWP_PID"
done

pass

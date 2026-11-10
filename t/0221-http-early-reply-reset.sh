#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An origin that answers an upload before reading it (413, 401, a redirect)
# and closes: the unread body turns its close() into a reset, right behind the
# reply. The reply must reach the client, every time and on every event loop,
# not an empty reply: the reset is an end of the origin's stream like a FIN,
# after what came before it (t/servers/early_reply_upload.py, 40 rounds).

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1
	out="$(timeout 300 python3 "$SERVERS_DIR/early_reply_upload.py" \
		"$pp" 40 2>&1)"
	gwp_stop_pids "$GWP_PID"
	[ "$out" = ok ] || fail "[$loop] $out"
done

pass

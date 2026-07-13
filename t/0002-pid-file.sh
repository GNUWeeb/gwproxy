#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --pid-file: a SOCKS5 proxy started with --pid-file must write its own PID to
# that file. Assert the file exists, holds a single positive integer, that the
# process is alive (kill -0), and that the recorded PID matches the one we
# started. No HTTP traffic is needed; checked on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3
require grep
require kill

pidf="$WORK/gwp.pid"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	rm -f "$pidf"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--pid-file="$pidf"

	[ -f "$pidf" ] || fail "[$loop] pid file was not created: $pidf"

	pid="$(<"$pidf")"
	printf '%s' "$pid" | grep -Eq '^[1-9][0-9]*$' \
		|| fail "[$loop] pid file does not hold a positive integer: '$pid'"

	kill -0 "$pid" 2>/dev/null \
		|| fail "[$loop] pid $pid from pid file is not a live process"

	[ "$pid" = "$GWP_PID" ] \
		|| fail "[$loop] pid file has $pid but gwproxy pid is $GWP_PID"

	kill "$GWP_PID" 2>/dev/null
done

pass

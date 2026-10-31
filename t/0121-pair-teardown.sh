#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# How a forwarded pair ends. Each half-close must reach the other peer while
# the reverse direction keeps flowing, both peers must get all data and a
# clean EOF (no RST), whichever side finishes first, and a reset on either
# side must end the other one. The proxy must then hold no more descriptors
# than before: a teardown that missed a request still in flight would keep
# the pair, and both its sockets, open for good.
#
# On io_uring the teardown cancels only on sockets with I/O in flight and
# leaves the last FIN to the close; this pins down that nothing is lost by
# either. Run on both event loops; epoll serves as the reference.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	tp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--target="127.0.0.1:$tp"
	res="$(timeout 120 python3 "$SERVERS_DIR/teardown_probe.py" \
		"$pp" "$tp" "$GWP_PID" 25 2>&1)"
	case "$res" in
	OK*)	diag "[$loop] $res" ;;
	*)	sed 's/^/# gwp: /' "$WORK/gwp.$pp.log" >&2
		fail "[$loop] $res" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

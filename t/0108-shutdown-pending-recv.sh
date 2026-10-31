#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Shutdown must not free a connection pair while the event loop can still
# complete I/O into it. With io_uring, closing a socket's fd does not end a
# recv the ring has pending on it: the request holds its own reference to
# the socket. Shutdown used to free every pair (buffers included) before
# tearing down the ring, so a client that sent data in that window had the
# kernel write it into freed memory.
#
# The helper holds the proxy in the middle of freeing its pairs (its log
# writes block on a full pipe) and checks that each pair freed by then is
# closed on the client's side, which it cannot be while the ring still has a
# recv armed on it. Run on both event loops; epoll has nothing in flight and
# serves as the reference.

. "$(dirname "$0")/lib.sh"
require python3

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# Both ports come from pick_port: a listener bound to port 0 could
	# take a port another test has reserved but not bound yet.
	pp="$(pick_port)"
	op="$(pick_port)"
	fifo="$WORK/log.$loop"
	mkfifo "$fifo" || fail "mkfifo failed"
	res="$(python3 "$SERVERS_DIR/shutdown_stall.py" "$GWPROXY" "$pp" "$op" \
		"$fifo" --event-loop="$loop" 2>&1)"
	case "$res" in
	OK*)	diag "[$loop] $res" ;;
	*)	sed 's/^/# gwp: /' "$fifo.log" >&2
		fail "[$loop] $res" ;;
	esac
done

pass

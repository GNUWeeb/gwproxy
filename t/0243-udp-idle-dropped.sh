#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Only datagrams the SOCKS5 UDP relay passes on count as activity for
# --idle-timeout. Every event of the relay socket used to refresh the idle
# clock before the datagram was even looked at, so anyone who knew or
# scanned the relay port could keep a quiet association, its descriptors and
# its per-IP credit open for good by sending it junk that was dropped.
#
# With --idle-timeout=2, an association whose client has gone quiet while a
# stranger on 127.0.0.3 sends junk to its relay every 0.25 s must still be
# closed; one whose client keeps sending through it must not. On every event
# loop.

. "$(dirname "$0")/lib.sh"
require python3

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4 --idle-timeout=2

	out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" "$pp" \
		send:127.0.0.1:"$ep":hi junk:127.0.0.3 open:20)"
	case "$out" in
	"REP 0
ECHO hi
EOF after "*) ;;
	*)	sed 's/^/# gwp: /' "$WORK/gwp.$pp.log" | tail -n 20 >&2
		fail "[$loop junk] got '$(echo $out)', want it closed" ;;
	esac

	out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" "$pp" \
		send:127.0.0.1:"$ep":hi ping:127.0.0.1:"$ep" open:6)"
	want="REP 0
ECHO hi
OPEN"
	if [ "$out" != "$want" ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$pp.log" | tail -n 20 >&2
		fail "[$loop busy] got '$(echo $out)', want '$(echo $want)'"
	fi
	gwp_stop_pids "$GWP_PID"
done

pass

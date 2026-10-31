#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 error replies (RFC 1928 Section 6): the proxy must answer a request it
# cannot satisfy with a reply carrying the matching REP code, not just hang up.
# A client that gets a bare FIN cannot tell "the target refused" from "the proxy
# died", and curl reports both identically -- so these need a raw client that
# reads the reply byte.
#
# Covered: a refused target (REP 0x05), an unsupported command (REP 0x07), and
# a successful CONNECT as the control. Exercised on every available event loop.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1024
start_httpd "$hp" "$WORK" "1.1"

# A port with nothing listening: connect() is refused rather than timing out.
closed_port
closed="$CLOSED_PORT"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=2

	# Control: a target that does accept still succeeds, so a proxy that
	# answered every request with an error could not pass this file.
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --dst 127.0.0.1 "$pp" "$hp")"
	[ "$rep" = "REP=0x00" ] \
		|| fail "[$loop] CONNECT to a live target got '$rep' (want REP=0x00)"

	# A refused target must come back as REP 0x05 (connection refused).
	# Both loops used to close without replying at all here.
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --dst 127.0.0.1 "$pp" "$closed")"
	[ "$rep" = "REP=0x05" ] \
		|| fail "[$loop] CONNECT to a refused port got '$rep' (want REP=0x05)"

	# BIND is not implemented: REP 0x07 (command not supported).
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --cmd 2 "$pp" "$hp")"
	[ "$rep" = "REP=0x07" ] \
		|| fail "[$loop] BIND got '$rep' (want REP=0x07)"

	kill "$GWP_PID" 2>/dev/null
done

pass

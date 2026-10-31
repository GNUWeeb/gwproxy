#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# With --as-socks5 and --as-http on one port, a connection whose first
# byte is not SOCKS5 goes to the HTTP parser. One that sent a SOCKS5
# greeting has chosen SOCKS5, and a later failure in the same read (a
# wrong password, no acceptable method) must end it: the bytes behind it
# used to be handed to the HTTP parser, which answered after the SOCKS5
# replies and gave the client a second password guess. Exercised on
# every event loop.

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

greet=05020002
bad=0104757365720478787878
http="$(printf 'CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n' | od -An -tx1 | tr -d ' \n')"

probe() { python3 "$SERVERS_DIR/socks5_oneshot.py" "$@"; }

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 \
		--auth-file="$WORK/auth" --event-loop="$loop" --nr-workers=1

	got="$(probe "$p" "$greet$bad$http")"
	[ "$got" = "05020101 CLOSED" ] ||
		fail "[$loop] wrong password, then HTTP: $got"

	got="$(probe "$p" "050100$http")"
	[ "$got" = "05ff CLOSED" ] ||
		fail "[$loop] no acceptable method, then HTTP: $got"

	# A plain HTTP request still falls back and is asked for credentials.
	got="$(probe "$p" "$http")"
	case "$got" in
	"$(printf 'HTTP/1.1 407' | od -An -tx1 | tr -d ' \n')"*" CLOSED") ;;
	*) fail "[$loop] plain HTTP: $got" ;;
	esac

	kill "$GWP_PID" 2>/dev/null
done

pass

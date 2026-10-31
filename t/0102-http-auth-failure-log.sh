#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A failed HTTP proxy login is logged at info level like a SOCKS5 one: the
# client address and the username it tried, with bytes outside printable
# ASCII, '"' and '\' escaped so a client cannot write lines of its own into
# the log. A request without credentials only learns that they are needed
# and is not logged as a failure. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

# req <Proxy-Authorization value or empty>: a CONNECT request, as hex.
req()
{
	python3 - "$1" <<-'PY'
	import sys
	r = b'CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n'
	if sys.argv[1]:
	    r += b'Proxy-Authorization: ' + sys.argv[1].encode() + b'\r\n'
	print((r + b'\r\n').hex())
	PY
}

# b64 <python bytes literal>: base64 of those bytes.
b64()
{
	python3 -c 'import base64, sys; print(base64.b64encode(eval(sys.argv[1])).decode())' "$1"
}

no_cred="$(req '')"
bad="$(req "Basic $(b64 "b'user:wrong'")")"
# User "us<CR><LF>[forged]<backslash>"<NUL>" with a wrong password.
evil="$(req "Basic $(b64 "b'us\\r\\n[forged]\\\\\"\\x00:x'")")"
malformed="$(req 'Basic !!!!')"
# "HTTP/1.1 407"
r407="$(printf 'HTTP/1.1 407' | od -An -tx1 | tr -d ' \n')"

probe() { python3 "$SERVERS_DIR/socks5_oneshot.py" "$@"; }

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-http=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=1

	for r in "$no_cred" "$bad" "$evil" "$malformed" "$bad"; do
		got="$(probe "$p" "$r")"
		case "$got" in
		"$r407"*" CLOSED") ;;
		*) fail "[$loop] expected a 407 and a close: $got" ;;
		esac
	done

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	log="$WORK/gwp.$p.log"

	n="$(grep -c 'HTTP proxy authentication failed' "$log")"
	[ "$n" = 4 ] || fail "[$loop] $n failures logged, expected 4"
	n="$(grep -c 'HTTP proxy authentication failed (ca=127\.0\.0\.1:[0-9]*, user="user")$' "$log")"
	[ "$n" = 2 ] || fail "[$loop] $n of 2 wrong passwords logged"
	grep -qF 'user="us\x0d\x0a[forged]\x5c\x22\x00")' "$log" ||
		fail "[$loop] odd username not logged escaped"
	grep -q '^\[forged\]' "$log" &&
		fail "[$loop] username broke the log line"
	grep -q 'HTTP proxy authentication failed (ca=127\.0\.0\.1:[0-9]*, malformed credentials)$' "$log" ||
		fail "[$loop] malformed credentials not logged"
done

pass

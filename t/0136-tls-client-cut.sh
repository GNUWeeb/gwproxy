#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client's stream that ended in anything but a clean end must not look
# like one to the target, which may take the EOF for a complete upload: a record
# that fails to verify, a fatal alert, a TCP reset or half a record have to reach
# it as a reset, behind all that was properly received, even if that came in the
# same segment. An end the client meant, with a close_notify, is an EOF, and so is
# a FIN at the end of a record, as too many clients do just that. The proxy stopping
# in the middle of an upload is no end either, and neither is any of this while the
# proxy is still connecting to the target, or its giving up on that connect just as
# it went through. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_cut_client.py" "$pp" 2>&1)"
	[ "$out" = ok ] || fail "[$loop] $out"
	kill "$GWP_PID" 2>/dev/null

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_cut_client.py" "$pp" "$GWP_PID" 2>&1)"
	[ "$out" = ok ] || fail "[$loop] stopping: $out"

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --connect-timeout=2
	out="$(timeout 150 python3 "$SERVERS_DIR/tls_cut_client.py" "$pp" "$GWP_PID" 2 2>&1)"
	[ "$out" = ok ] || fail "[$loop] timed out connect: $out"
	kill "$GWP_PID" 2>/dev/null
done

pass

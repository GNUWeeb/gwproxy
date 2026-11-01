#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Ciphertext the proxy will never decrypt or use must not pile up in memory.
#
# Nothing can be decrypted behind a close_notify, so a client that sends one
# before its request is complete has given up, as with a FIN: the proxy must
# hang up rather than keep receiving what follows. Checked with and without
# the start of a request ahead of the close_notify, with the client flooding
# the connection afterwards and with it going silent. --protocol-timeout=0
# leaves nothing else to end the connection. A close_notify right behind a
# complete request, on the other hand, only ends the client's sending, and
# the request is still served. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --protocol-timeout=0
	out="$(timeout 120 python3 "$SERVERS_DIR/tls_unread_input.py" closenotify \
		"$pp" "$GWP_PID" 2>&1)"
	[ "$out" = ok ] || fail "[$loop] $out"
	kill "$GWP_PID" 2>/dev/null
done

pass

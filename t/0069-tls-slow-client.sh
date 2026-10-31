#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client that reads slowly. The origin sends a few MB through a TLS
# CONNECT tunnel and closes; the client starts reading only after a pause.
# The proxy must keep the ciphertext the client has not taken yet and shut
# the client's write side only after all of it (and the close_notify) has
# gone out, so the client gets every byte and a clean end of stream.
#
# A TLS client that does not read at all, behind an origin that never stops
# sending. The proxy must stop reading from the origin instead of queueing
# ever more ciphertext for the client: its memory must stay flat.
# Exercised on every event loop.

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
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	timeout 60 python3 "$SERVERS_DIR/tls_tunnel_client.py" slowread \
		"$pp" 8000000 \
		|| fail "[$loop] slow TLS client did not get the whole response"
	# RSS may grow by at most 8 MiB while the client does not read.
	timeout 60 python3 "$SERVERS_DIR/tls_tunnel_client.py" noread \
		"$pp" "$GWP_PID" 8192 \
		|| fail "[$loop] proxy memory grew with a TLS client that does not read"
	kill "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client uploads through a CONNECT tunnel to an origin that reads with
# short pauses, then waits for the origin to confirm it got everything. The
# proxy decrypts only as much as its buffer to the origin holds; whatever the
# TLS engine still has once that buffer drains must be delivered too, even
# though the client sends nothing more to wake the proxy up. Exercised on
# every event loop.

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
	for i in 1 2 3; do
		timeout 30 python3 "$SERVERS_DIR/tls_tunnel_client.py" upload \
			"$pp" 2000000 \
			|| fail "[$loop] TLS upload stalled before reaching the origin"
	done
	kill "$GWP_PID" 2>/dev/null
done

pass

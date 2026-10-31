#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client whose TLS handshake fails must not take down other TLS sessions on
# the same worker. OpenSSL keeps its error queue per thread, and a stale entry
# left there by one connection's failure makes SSL_get_error() report a fatal
# error for the next, unrelated, SSL call on that thread. Hold a TLS CONNECT
# tunnel open on a single worker, make a second client fail its handshake,
# then check the tunnel still echoes. Run at the default log level, where no
# debug message happens to drain the queue. Exercised on every event loop.

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
	timeout 30 python3 "$SERVERS_DIR/tls_tunnel_client.py" isolation "$pp" \
		|| fail "[$loop] a failed TLS handshake broke another TLS session"
	kill "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client's tunnel to a plaintext target that sends data and resets: the
# data reaches the client, and the reset is still not passed on as a clean end.
# The client gets no close_notify, so it can tell the stream was cut, where a
# target that closes normally gets it one. Also with the data and the reset
# both waiting while the proxy is stopped, on every event loop
# (t/servers/tls_target_reset.py).

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
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 300 python3 "$SERVERS_DIR/tls_target_reset.py" \
		"$pp" "$GWP_PID" 2>&1)"
	gwp_stop_pids "$GWP_PID"
	[ "$out" = ok ] || fail "[$loop] $out"
done

pass

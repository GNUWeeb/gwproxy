#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The TLS engine may hold records that have left the socket already, and that no
# receive will bring up again. Whatever waits for something else first has to go
# back to the engine when that is done, before it waits for the socket again.
#
# A tunnel through an upstream proxy is one such thing: a close_notify, or tunnel
# bytes, sent along with the request must not wait for the client to send more.
#
# The control connection of a SOCKS5 UDP association is another: a close_notify
# or a bad record there has to end the association like a FIN, and not only when
# the engine gets to see it. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

HELPER="$SERVERS_DIR/tls_held_records.py"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for kind in http socks5h; do
		for mode in close_notify exact_fill; do
			pp="$(pick_port)"
			up="$(pick_port)"
			gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
				--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
				--nr-workers=1 --client-buf-size=256 \
				--upstream-proxy="$kind://127.0.0.1:$up"
			out="$(timeout 100 python3 "$HELPER" upstream "${kind%h}" \
				"$mode" "$pp" "$up" 2>&1)"
			[ "$out" = ok ] || fail "[$loop, $kind, $mode] $out"
			kill "$GWP_PID" 2>/dev/null
		done
	done

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 120 python3 "$HELPER" udp "$pp" 2>&1)"
	[ "$out" = ok ] || fail "[$loop, udp] $out"
	kill "$GWP_PID" 2>/dev/null
done

pass

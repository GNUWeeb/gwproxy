#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A reply that gwproxy itself sends a TLS client before it closes the
# connection, a 407, a 400, a 502, a SOCKS5 refusal, or a 502 in place of the
# response of an origin that reset, ends with a close_notify, as forwarded
# responses do: a strict client (Python with suppress_ragged_eofs=False)
# reads a clean end, not a truncated stream, on every event loop
# (t/servers/pair_end.py "tls-reply").

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"
printf 'user:pass\n' >"$WORK/auth"
closed_port

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	tls=(--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem")
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --auth-file="$WORK/auth" "${tls[@]}"
	out="$(timeout 60 python3 "$SERVERS_DIR/pair_end.py" tls-reply 407 \
		"$pp" "$CLOSED_PORT" 2>&1)"
	[ "$out" = ok ] || fail "[$loop] $out"
	gwp_stop_pids "$GWP_PID"

	pp="$(pick_port)"
	op="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--as-http=1 --as-socks5=1 "${tls[@]}"
	for how in 400 502 s5 fwd-rst; do
		port="$CLOSED_PORT"
		[ "$how" = fwd-rst ] && port="$op"
		out="$(timeout 60 python3 "$SERVERS_DIR/pair_end.py" tls-reply \
			"$how" "$pp" "$port" 2>&1)"
		[ "$out" = ok ] || fail "[$loop] $out"
	done
	gwp_stop_pids "$GWP_PID"
done

pass

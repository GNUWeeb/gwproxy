#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Before the handshake is over, the proxy works through the records a TLS
# client's engine already holds while the client buffer has room. In some
# states it drops what the client sends, and the buffer never fills: on a
# UDP association's control connection, and behind a forwarding request
# whose name is still being resolved. If that loop read the socket too, a
# client sending faster than the worker decrypts would keep the worker in it
# for as long as it kept sending, and every other connection of the worker
# would wait. With a small client buffer, two such clients flood one worker
# while another client pings an echo server through it: the pings must keep
# being answered. The forwarding case needs --raw-dns, which only the epoll
# loop has; the association runs on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --tls-cert
require openssl

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# A DNS server that holds back the flooders' names for good.
start_dns_hold()
{
	local try log

	for try in 1 2 3 4 5; do
		log="$WORK/dns.$try.log"
		DNS_PORT="$(pick_port)"
		python3 "$SERVERS_DIR/dns_hold.py" "$DNS_PORT" "$WORK/names" \
			"$WORK/release" >"$log" 2>&1 &
		_PIDS+=("$!")
		for _ in $(seq 1 100); do
			grep -q READY "$log" 2>/dev/null && return 0
			kill -0 "$!" 2>/dev/null || break
			sleep 0.05
		done
	done
	fail "the DNS server did not start"
}

# run <loop> <mode> [<proxy option>...]
run()
{
	local loop="$1" mode="$2" pp out rc=0
	shift 2

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --client-buf-size=4096 "$@"
	out="$(timeout 120 python3 "$SERVERS_DIR/tls_flood_ping.py" "$mode" \
		"$pp" 3 2>"$WORK/ping.err")" || rc=$?
	sed "s/^/# [$loop $mode] /" "$WORK/ping.err" >&2
	[ "$rc" = 77 ] && skip "[$loop $mode] $out"
	[ "$out" = ok ] || fail "[$loop $mode] rc=$rc $out"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

if grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null; then
	start_dns_hold
	run epoll http --as-http=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$DNS_PORT" --protocol-timeout=60
else
	echo "# [epoll http] skipped: built without the raw DNS resolver" >&2
fi
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue
	run "$loop" udp
done

pass

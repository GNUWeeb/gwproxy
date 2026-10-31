#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A --raw-dns reply must answer the question that was asked: the same name
# (in any case), QTYPE and QCLASS (RFC 5452 Section 9.1). A reply about
# some other name or type is not ours to use, even with the right ID on
# the right port; the lookup ignores it and goes on waiting, here until
# the protocol timeout. Before, only the ID was compared, and an answer
# for any name steered the connection.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

for mode in upper-name wrong-name wrong-type; do
	dp="$(pick_port)"
	python3 "$SERVERS_DIR/dns_malformed.py" "$mode" "$dp" 2>/dev/null &
	dns_pid=$!
	_PIDS+=("$dns_pid")
	sleep 0.4

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$dp" --nr-workers=1 \
		--protocol-timeout=2
	rep="$(timeout 10 python3 "$SERVERS_DIR/socks5_probe.py" \
		--host 127.0.0.1 --atyp domain --dst probe.example "$p" "$hp")"
	case "$mode" in
	upper-name)
		[ "$rep" = "REP=0x00" ] \
			|| fail "an answer naming the host in upper case was refused ('$rep')" ;;
	*)
		[ "$rep" != "REP=0x00" ] \
			|| fail "a $mode answer was used to connect" ;;
	esac
	kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died on a $mode answer"
	kill "$GWP_PID" 2>/dev/null
	kill "$dns_pid" 2>/dev/null
done

pass

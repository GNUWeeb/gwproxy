#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A --raw-dns answer may hold record types the resolver has no use for: a name
# under a DNAME comes back as DNAME, CNAME, A, and a server may add a TXT or an
# RRSIG next to the address. The address is still good. These used to fail the
# whole answer: the lookup asked for the other family too, then the client got
# a failure, though the system resolver handles the same answer. An answer with
# no address at all must still fail, once per family and no more.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

for mode in dname-chain a-then-txt txt-then-a txt-only; do
	dp="$(pick_port)"
	count="$WORK/queries.$mode"
	ready="$WORK/ready.$mode"
	python3 "$SERVERS_DIR/dns_malformed.py" "$mode" "$dp" "$count" 2>"$ready" &
	dns_pid=$!
	_PIDS+=("$dns_pid")
	for _ in $(seq 300); do
		[ -s "$ready" ] && break
		sleep 0.1
	done
	[ -s "$ready" ] || fail "the DNS responder did not start ($mode)"

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$dp" --nr-workers=1 \
		--protocol-timeout=30
	rep="$(timeout 60 python3 "$SERVERS_DIR/socks5_probe.py" \
		--host 127.0.0.1 --atyp domain --dst probe.example "$p" "$hp")"
	queries="$(cat "$count" 2>/dev/null || echo 0)"
	case "$mode" in
	txt-only)
		[ "$rep" != "REP=0x00" ] \
			|| fail "an answer with no address was used to connect"
		[ "$queries" = 2 ] \
			|| fail "$queries queries for an answer with no address, not one per family"
		;;
	*)
		[ "$rep" = "REP=0x00" ] \
			|| fail "the address in a $mode answer was not used ('$rep')"
		[ "$queries" = 1 ] \
			|| fail "$queries queries for a $mode answer that held an address"
		;;
	esac
	kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died on a $mode answer"
	kill "$GWP_PID" 2>/dev/null
	kill "$dns_pid" 2>/dev/null
done

pass

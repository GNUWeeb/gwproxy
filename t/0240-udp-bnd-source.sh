#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The SOCKS5 UDP relay's datagrams to the client must come from the address
# the client was told, BND.ADDR: the address it reached the proxy at. The
# relay socket is bound to the wildcard address, and its datagrams left from
# whichever source routing picked toward the client. On a host with several
# addresses a client that checks where they come from, with a connect()ed
# UDP socket as PySocks has or behind a stateful firewall, got none of them.
#
# The client reaches the proxy at 127.0.0.2 from 127.0.0.1, whose route
# prefers the source 127.0.0.1, and connect()s its UDP socket to the relay:
# the echo must come back. Then, in a private network namespace where one
# can be had (skipped otherwise), the same over IPv6 with a second address
# on lo, and an IPv4 client of a dual-stack listener. On every event loop.

. "$(dirname "$0")/lib.sh"
require python3

# check <tag> <proxy ip> <proxy port> <client ip> <echo ip> <echo port>
check()
{
	local out want

	want="REP 0
ECHO $1"
	out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" \
		--connect --proxy "$2" --src "$4" "$3" \
		"send:${5//:/-}:$6:$1")"
	if [ "$out" != "$want" ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$3.log" | tail -n 20 >&2
		fail "$1: got '$(echo $out)', want '$(echo $want)'"
	fi
}

loops()
{
	echo epoll
	have_io_uring && echo io_uring
}

if [ "${1:-}" = --inner ]; then
	ns_inner_work "$2"
	GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
	# The work directory is the outer half's: leave its removal to it.
	trap 'gwp_stop_pids "${_PIDS[@]}"; _release_ports' EXIT

	ip link set lo up || fail "cannot bring up lo in the namespace"
	ip -6 addr add fd00::2/128 dev lo nodad 2>/dev/null || {
		echo SKIP-INNER
		exit 0
	}
	start_udp_echo ::1
	ep6="$UDP_ECHO_PORT"
	start_udp_echo 127.0.0.1
	ep4="$UDP_ECHO_PORT"
	for loop in $(loops); do
		pp="$(pick_port)"
		gwp_start "[::]:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --log-level=4
		check "$loop-v6" fd00::2 "$pp" ::1 ::1 "$ep6"
		check "$loop-v4-dual" 127.0.0.2 "$pp" 127.0.0.1 127.0.0.1 "$ep4"
		gwp_stop_pids "$GWP_PID"
	done
	echo PASS-INNER
	exit 0
fi

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"
for loop in $(loops); do
	pp="$(pick_port)"
	gwp_start "127.0.0.2:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4
	check "$loop-v4" 127.0.0.2 "$pp" 127.0.0.1 127.0.0.1 "$ep"
	gwp_stop_pids "$GWP_PID"
done

require unshare
require ip
ns_drop_setup
$NS_DROP unshare -rn true 2>/dev/null || \
	skip "IPv4 passed; no user+net namespaces (unshare -rn) for IPv6"
out="$(timeout 300 $NS_DROP unshare -rn "$0" --inner "$WORK" 2>&1)"
printf '%s\n' "$out" | sed 's/^/# /' >&2
case "$out" in
*PASS-INNER*) pass ;;
*SKIP-INNER*) skip "IPv4 passed; no IPv6 address can be added in a namespace" ;;
esac
fail "inner run failed (see above)"

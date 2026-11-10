#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pool server that refuses a UDP ASSOCIATE is retried once on another
# server of the pool, and when that one is an http:// or https:// server,
# which cannot carry UDP, the retry is spent and the client is answered as
# the first server refused: REP 0x03 to 0x06 as it is. The switch to the
# second server cleared how the first attempt ended, so the client got the
# generic 0x01 instead.
#
# A pool of a socks5h:// stand-in that refuses with 0x05 (or 0x03) and an
# http:// server, each proxy asked once so that the stand-in is picked
# first: the client must get the stand-in's REP. On every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --acl-file

closed_port

for rep in 5 3; do
	: >"$WORK/up$rep.log"
	python3 "$SERVERS_DIR/socks5_udp_upstream.py" "$WORK/up$rep.log" \
		--rep "$rep" >"$WORK/up$rep.out" 2>&1 &
	_PIDS+=("$!")
done

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for rep in 5 3; do
		up=
		for i in $(seq 1 100); do
			up="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' \
				"$WORK/up$rep.out")"
			[ -n "$up" ] && break
			sleep 0.05
		done
		[ -n "$up" ] || fail "the stand-in upstream did not start"
		cat >"$WORK/pool.acl" <<-EOF
		upstream p {
			server socks5h://127.0.0.1:$up;
			server http://127.0.0.1:$CLOSED_PORT;
		}
		-A OUTPUT -j UPSTREAM --to p
		-P OUTPUT ACCEPT
		EOF
		chmod 600 "$WORK/pool.acl"

		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --log-level=4 --acl-file="$WORK/pool.acl"
		log="$WORK/gwp.$pp.log"
		out="$(timeout 60 python3 "$SERVERS_DIR/socks5_udp_script.py" "$pp")"
		grep -q 'landed on a server that cannot carry UDP' "$log" || {
			sed 's/^/# gwp: /' "$log" | tail -n 20 >&2
			fail "[$loop 0x0$rep] the retry did not land on the http server"
		}
		[ "$out" = "REP $rep" ] || {
			sed 's/^/# gwp: /' "$log" | tail -n 20 >&2
			fail "[$loop 0x0$rep] got '$out', want 'REP $rep'"
		}
		gwp_stop_pids "$GWP_PID"
	done
done

pass

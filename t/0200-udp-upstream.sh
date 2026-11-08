#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A SOCKS5 UDP ASSOCIATE of a client that an ACL -j UPSTREAM rule sends
# through a pool goes through the pool's socks5:// or socks5h:// server:
# gwproxy asks the server for a UDP ASSOCIATE of its own on a control
# connection, answers the client only once the server has answered, and
# relays the client's datagrams, SOCKS5 header and all, to the server's
# relay and back.
#
# With gwproxy itself as the upstream, datagrams of several sizes echo back
# whole, and the upstream is asked with credentials. With a stand-in server
# (t/servers/socks5_udp_upstream.py), which grants with BND.ADDR 0.0.0.0 and
# echoes datagrams as they come: a socks5h:// pool is sent a domain target as
# it is and a socks5:// one is not, a datagram from another source than the
# server's relay never reaches the client, nor one from another source than
# the client the server, the OUTPUT chain still judges each datagram, and
# either control connection closing ends the other. A server that refuses
# the UDP ASSOCIATE gets the client its answer (REP 0x07 as 0x01) without
# being ejected, and the association is retried on another server of the
# pool; a server that refuses the connection counts as for TCP. An http://
# pool refuses UDP ASSOCIATE (REP 0x07). On every event loop that has it.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--acl-file"

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"
closed_port
cport="$CLOSED_PORT"

# fake_start <name> [opts]: a stand-in upstream logging to $WORK/<name>.log;
# sets FAKE_PORT.
fake_start()
{
	local name="$1" out="$WORK/$1.out" pid i
	shift

	: >"$WORK/$name.log"
	python3 "$SERVERS_DIR/socks5_udp_upstream.py" "$WORK/$name.log" "$@" \
		>"$out" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	for i in $(seq 1 100); do
		FAKE_PORT="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$out")"
		[ -n "$FAKE_PORT" ] && return 0
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	fail "the $name upstream did not start"
}

# acl <file> <server URL>...: a pool of those servers for every client.
acl()
{
	local f="$WORK/$1" u
	shift
	{
		echo 'upstream p {'
		for u in "$@"; do
			echo "	server $u;"
		done
		echo '}'
		echo '-A OUTPUT -s 127.0.0.1 -j UPSTREAM --to p'
		echo '-A OUTPUT -p udp --dports 9999 -j REJECT'
		echo '-P OUTPUT ACCEPT'
	} >"$f"
	chmod 600 "$f"
}

client() { timeout 60 python3 "$SERVERS_DIR/socks5_udp_up_client.py" "$@"; }

# front <loop> <acl>: a proxy in front; sets FP and LOG.
front()
{
	FP="$(pick_port)"
	gwp_start "127.0.0.1:$FP" --as-socks5=1 --event-loop="$1" \
		--nr-workers=1 --log-level=4 --acl-file="$WORK/$2"
	LOG="$WORK/gwp.$FP.log"
}

# expect <tag> <want> <got>
expect()
{
	[ "$2" = "$3" ] || fail "$1: got '$(echo $3)', want '$(echo $2)'"
}

# wait_log <file> <pattern>: up to 10 s for a line to show.
wait_log()
{
	timeout 10 bash -c 'until grep -q -- "$1" "$2"; do sleep 0.1; done' \
		_ "$2" "$1"
}

run_loop()
{
	local loop="$1" up out i

	# gwproxy as the upstream, with credentials.
	printf 'up:pw\n' >"$WORK/up.auth"
	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop" \
		--auth-file="$WORK/up.auth"
	acl gw.acl "socks5://up:pw@127.0.0.1:$up"
	front "$loop" gw.acl
	python3 "$SERVERS_DIR/socks5_udp_client.py" "$FP" "$ep" 1 1400 60000 \
		>/dev/null || fail "[$loop] UDP through gwproxy as the upstream"
	grep -q 'Upstream UDP association established' "$LOG" || \
		fail "[$loop] the association did not go through the upstream"
	grep -q 'SOCKS5 UDP ASSOCIATE relay bound' "$WORK/gwp.$up.log" || \
		fail "[$loop] the upstream did not relay"
	grep -q 'pool p server 1, .*, 1 open' "$LOG" || \
		fail "[$loop] the association did not count against its server"
	wait_log "$LOG" "released by idx=.*, 0 open" || \
		fail "[$loop] the association did not give its server back"
	! grep -q ':pw' "$LOG" || fail "[$loop] the password was logged"
	kill "$GWP_PID" 2>/dev/null

	# A socks5h:// pool: names go as they are; the stand-in's relay is
	# 0.0.0.0, its own address. Only the relay is heard from.
	fake_start h
	acl h.acl "socks5h://127.0.0.1:$FAKE_PORT"
	front "$loop" h.acl
	out="$(client "$FP" send:127.0.0.1:"$ep":hello \
		send:example.com:53:dom send:127.0.0.1:9:xstray \
		send:127.0.0.1:9999:denied)"
	expect "[$loop socks5h]" "REP 0
ECHO hello
ECHO dom
ECHO xstray
NONE" "$out"
	grep -q 'atyp=3 dst=example.com:53 ' "$WORK/h.log" || \
		fail "[$loop socks5h] the name was not sent as it is"
	grep -q 'assoc dst=127.0.0.1:[1-9][0-9]* cmd=3' "$WORK/h.log" || \
		fail "[$loop socks5h] the request did not name where from"
	! grep -q 'dst=127.0.0.1:9999 ' "$WORK/h.log" || \
		fail "[$loop socks5h] a datagram the ACL denies went out"
	# The client closing ends the upstream's association.
	wait_log "$WORK/h.log" '^closed' || \
		fail "[$loop socks5h] the upstream's control connection stayed"

	# Another source than the client does not get through.
	r="$(python3 "$SERVERS_DIR/socks5_udp_probe.py" --src-ip 127.0.0.2 \
		"$FP" "$ep")"
	expect "[$loop socks5h stranger]" DROPPED "$r"

	# The upstream closing ends the client's association.
	out="$(client "$FP" send:127.0.0.1:9:bye eof)"
	expect "[$loop socks5h bye]" "REP 0
ECHO bye
EOF" "$out"
	kill "$GWP_PID" 2>/dev/null

	# A socks5:// pool: gwproxy resolves names, and has no lookup for
	# datagrams, so a name is dropped.
	fake_start s
	acl s.acl "socks5://127.0.0.1:$FAKE_PORT"
	front "$loop" s.acl
	out="$(client "$FP" send:example.com:53:dom send:127.0.0.1:9:ip)"
	expect "[$loop socks5]" "REP 0
NONE
ECHO ip" "$out"
	! grep -q 'atyp=3' "$WORK/s.log" || \
		fail "[$loop socks5] a name went to a socks5:// pool"
	kill "$GWP_PID" 2>/dev/null

	# A server that refuses UDP ASSOCIATE: the client hears it, and the
	# server is not ejected for it, however often.
	fake_start r --rep 7
	acl r.acl "socks5://127.0.0.1:$FAKE_PORT"
	front "$loop" r.acl
	for i in 1 2 3 4; do
		expect "[$loop refused $i]" "REP 1" "$(client "$FP")"
	done
	grep -q 'UDP ASSOCIATE failed (rep=0x07, class=neutral' "$LOG" || \
		fail "[$loop refused] the refusal was not logged as neutral"
	! grep -q 'ejected' "$LOG" || \
		fail "[$loop refused] a refused UDP ASSOCIATE ejected the server"
	kill "$GWP_PID" 2>/dev/null

	# With another server in the pool, the refusal is retried there.
	fake_start g
	acl rg.acl "socks5://127.0.0.1:$(sed -n 's/^READY //p' "$WORK/r.out")" \
		"socks5://127.0.0.1:$FAKE_PORT"
	front "$loop" rg.acl
	for i in 1 2 3 4; do
		out="$(client "$FP" send:127.0.0.1:9:x$i)"
		expect "[$loop retry $i]" "REP 0
ECHO x$i" "$out"
	done
	grep -q 'Upstream retry for idx=' "$LOG" || \
		fail "[$loop retry] no retry was logged"
	kill "$GWP_PID" 2>/dev/null

	# A server that refuses the connection fails as for TCP, and counts.
	acl c.acl "socks5://127.0.0.1:$cport"
	front "$loop" c.acl
	for i in 1 2 3; do
		expect "[$loop closed $i]" "REP 1" "$(client "$FP")"
	done
	grep -q 'ejected for' "$LOG" || \
		fail "[$loop closed] refused connections did not eject the server"
	kill "$GWP_PID" 2>/dev/null

	# An http:// pool cannot carry UDP.
	acl w.acl "http://127.0.0.1:$cport"
	front "$loop" w.acl
	expect "[$loop http]" "REP 7" "$(client "$FP")"
	kill "$GWP_PID" 2>/dev/null
}

run_loop epoll

pass

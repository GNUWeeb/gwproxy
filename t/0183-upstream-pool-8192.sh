#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream pool may hold up to 8192 servers, and a pick reaches all of
# them. The pool "big" has 8192 servers given as IP literals: three
# recording SOCKS5 upstreams at its start, middle and end (servers 1, 4097
# and 8192), and between them servers of distinct identities (each its own
# user) that all refuse the TCP connection. It loads at startup; one more
# server is refused at startup (non-zero exit, the message naming the
# pool) and on a SIGHUP reload, which keeps the rules in force. Then 8193
# connections go round-robin once around the pool and on to its first
# server again: each refusing server fails its own connection and the
# retry of the one before it (never 3 failures, so none is ejected), the
# connections whose turn falls on the recording servers or on the server
# just before them get through, and the debug log shows every pick, the
# picks of servers 1, 4097 and 8192, and the retries onto 4097 and 8192.
# A least_conn pool of the same servers loads too and picks its idle first
# server. On every available event loop, at once.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

NR=8192
MID=4096	# server 4097, counted from 1

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"
hp2="$(pick_port)"
start_httpd "$hp2" "$WORK" "1.1"

# rec_start <dir> <name>: a recording SOCKS5 upstream logging to
# <dir>/rec.<name>.log; sets REC_PORT.
rec_start()
{
	local port log="$1/rec.$2.log"

	port="$(pick_port)"
	: >"$log"
	python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$port" \
		"$log" >"$1/rec.$2.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $2 upstream did not listen"
	REC_PORT="$port"
}

# write_pool <name> <nr> <first> <mid> <last> <dead> [least_conn]: a pool
# of <nr> servers: ports <first>, <mid> and <last> at the start, at MID
# and at NR - 1, the others refusing on port <dead>.
write_pool()
{
	local i

	echo "upstream $1 {"
	for ((i = 0; i < $2; i++)); do
		case "$i" in
		0) echo "	server socks5h://127.0.0.1:$3;" ;;
		"$MID") echo "	server socks5h://127.0.0.1:$4;" ;;
		$((NR - 1))) echo "	server socks5h://127.0.0.1:$5;" ;;
		*) echo "	server socks5h://f$i:x@127.0.0.1:$6;" ;;
		esac
	done
	[ -n "${7:-}" ] && echo "	$7;"
	echo "}"
}

# write_acl <file> <nr> <ports...>: pools of <nr> servers: "lc" for
# targets on port hp2, "big" for the rest (the last rule that matches
# names the pool).
write_acl()
{
	local f="$1" nr="$2"

	shift 2
	{
		write_pool big "$nr" "$@"
		write_pool lc "$nr" "$@" least_conn
		echo '-A OUTPUT -j UPSTREAM --to big'
		echo "-A OUTPUT -p tcp --dports $hp2 -j UPSTREAM --to lc"
	} >"$f"
	chmod 600 "$f"
}

lines()
{
	wc -l <"$1"
}

pool_loop()
{
	local loop="$1" d="$WORK/$1" fp log rc n out r1 r2 r3 dead

	mkdir -p "$d"
	rec_start "$d" r1
	r1="$REC_PORT"
	rec_start "$d" r2
	r2="$REC_PORT"
	rec_start "$d" r3
	r3="$REC_PORT"
	closed_port
	dead="$CLOSED_PORT"
	write_acl "$d/ok.acl" "$NR" "$r1" "$r2" "$r3" "$dead"
	write_acl "$d/over.acl" $((NR + 1)) "$r1" "$r2" "$r3" "$dead"

	# One server too many: refused at startup, naming the pool.
	fp="$(pick_port)"
	rc=0
	timeout 120 "$GWPROXY" --bind="127.0.0.1:$fp" --as-socks5=1 \
		--event-loop="$loop" --acl-file="$d/over.acl" \
		>"$d/over.log" 2>&1 || rc=$?
	[ "$rc" != 0 ] && [ "$rc" != 124 ] || \
		fail "[$loop] a pool of $((NR + 1)) servers was not refused at startup (exit $rc)"
	grep -q "over.acl: line $((NR + 2)): upstream pool big has more than $NR servers" \
		"$d/over.log" || {
		sed 's/^/# gwp: /' "$d/over.log" >&2
		fail "[$loop] the startup refusal does not name the pool"
	}

	cp "$d/ok.acl" "$d/main.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --acl-file="$d/main.acl"
	log="$WORK/gwp.$fp.log"

	# ...and on a reload, which keeps the rules.
	cp "$d/over.acl" "$d/main.acl"
	gwp_hup "$GWP_PID" "$log" 1
	grep -q "Failed to reload ACL file: .*; keeping current rules" "$log" &&
	grep -q "main.acl: line $((NR + 2)): upstream pool big has more than $NR servers" \
		"$log" || fail "[$loop] the reload of $((NR + 1)) servers was not refused"

	# Round-robin once around and back to the first server.
	out="$(timeout 300 python3 "$SERVERS_DIR/socks5_burst.py" "$fp" "$hp" \
		$((NR + 1)) 32)" || fail "[$loop] the burst client failed: $out"
	[ "$out" = "rep0=6 fail=$((NR - 5)) err=0" ] || \
		fail "[$loop] the burst got $out, want rep0=6 fail=$((NR - 5)) err=0"
	n="$(grep -c "Upstream for idx=[0-9]*: pool big server " "$log")"
	[ "$n" = $((NR + 1)) ] || fail "[$loop] $n picks of the pool, want $((NR + 1))"
	[ "$(grep -c ": pool big server 1, 127\.0\.0\.1:$r1 " "$log")" = 2 ] &&
	[ "$(grep -c ": pool big server $((MID + 1)), 127\.0\.0\.1:$r2 " "$log")" = 1 ] &&
	[ "$(grep -c ": pool big server $NR, 127\.0\.0\.1:$r3 " "$log")" = 1 ] || \
		fail "[$loop] the first, middle and last servers were not picked in their turns"
	[ "$(grep -c "Upstream retry for idx=[0-9]*: .* trying server $((MID + 1)) (127\.0\.0\.1:$r2)" "$log")" = 1 ] &&
	[ "$(grep -c "Upstream retry for idx=[0-9]*: .* trying server $NR (127\.0\.0\.1:$r3)" "$log")" = 1 ] || \
		fail "[$loop] the retries did not reach the middle and last servers"
	! grep -q "ejected for" "$log" || fail "[$loop] a server was ejected"
	[ "$(lines "$d/rec.r1.log")" = 2 ] && [ "$(lines "$d/rec.r2.log")" = 2 ] &&
	[ "$(lines "$d/rec.r3.log")" = 2 ] || \
		fail "[$loop] the upstreams saw $(lines "$d/rec.r1.log"), $(lines "$d/rec.r2.log") and $(lines "$d/rec.r3.log") connections, want 2 each"

	# least_conn at the same size: every server idle, so its first one.
	out="$(timeout 60 python3 "$SERVERS_DIR/socks5_burst.py" "$fp" "$hp2" 1 1)"
	[ "$out" = "rep0=1 fail=0 err=0" ] || fail "[$loop] least_conn got $out"
	grep -q "Upstream for idx=[0-9]*: pool lc server 1, 127\.0\.0\.1:$r1 " "$log" ||
		fail "[$loop] least_conn did not pick its idle first server"
	[ "$(lines "$d/rec.r1.log")" = 3 ] || fail "[$loop] r1 did not see the least_conn connection"

	! grep -q "s3cret\|f[0-9]*:x@" "$log" || fail "[$loop] credentials were logged"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	return 0
}

loops=epoll
have_io_uring && loops="$loops io_uring"
gwp_parallel pool_loop $loops

pass

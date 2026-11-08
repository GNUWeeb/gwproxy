#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# max_conns= on pool servers, on every available event loop.
#
#  - Tunnels held open through a pool of two servers capped at 2 and 1
#    fill them; the next client is refused as an unreachable host (SOCKS5
#    REP 0x04, HTTP 502, also for a UDP ASSOCIATE), and logged, rather than
#    overloading a server.
#  - The open count is the server's: a tunnel through another pool that
#    lists the first server with a cap of 3 still gets through (its cap
#    allows it), and keeps the first pool full.
#  - Once tunnels close, the pool takes clients again, on the server with
#    room.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"
url="http://127.0.0.1:$hp/payload.bin"

# rec_start <name>: a recording SOCKS5 upstream; sets REC_PORT.
rec_start()
{
	local port log="$WORK/rec.$1.log"

	port="$(pick_port)"
	: >"$log"
	python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$port" \
		"$log" >"$WORK/rec.$1.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $1 upstream did not listen"
	REC_PORT="$port"
}

rec_start g1;	g1="$REC_PORT"
rec_start g2;	g2="$REC_PORT"

printf '%s\n' m:p n:p >"$WORK/auth"
acl="$WORK/main.acl"
{
	echo 'upstream p_m {'
	echo "	server socks5h://127.0.0.1:$g1 max_conns=2;"
	echo "	server socks5h://127.0.0.1:$g2 max_conns=1;"
	echo '}'
	echo 'upstream p_n {'
	echo "	server socks5h://127.0.0.1:$g1 max_conns=3;"
	echo '}'
	echo '-A OUTPUT -m user --user m -j UPSTREAM --to p_m'
	echo '-A OUTPUT -m user --user n -j UPSTREAM --to p_n'
} >"$acl"
chmod 600 "$acl"

# picks <pool>: the servers <pool> was picked for, in order, as "1 2 1".
picks()
{
	sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" \
		"$log" | tr '\n' ' ' | sed 's/ $//'
}

# want <tag> <what> <got> <want>
want()
{
	[ "$3" = "$4" ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$1] $2: got '$3', want '$4'"
	}
}

# hold <tag> <user>: a tunnel held open through <user>'s pool; sets HELD.
hold()
{
	local out="$WORK/held.$1.out" pid

	python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" "$2" p \
		localhost "$hp" /payload.bin "$WORK/go.never" >"$out" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $pid 2>/dev/null; do sleep 0.1; done"
	grep -q '^FIRST 20000$' "$out" || {
		sed 's/^/# client: /' "$out" >&2
		fail "[$1] the held tunnel did not get through"
	}
	HELD="$pid"
}

# release <pid> <n>: the held tunnel <pid> goes; wait until the log shows
# <n> releases in all.
release()
{
	kill "$1" 2>/dev/null
	wait "$1" 2>/dev/null
	timeout 30 bash -c "until [ \"\$(grep -c 'released by idx=' '$log')\" -ge $2 ]; do sleep 0.1; done" ||
		fail "the tunnel's server was not released"
}

# rep <user>: the SOCKS5 REP the front answers <user>'s CONNECT with.
rep()
{
	python3 "$SERVERS_DIR/socks5_probe.py" --user "$1" --pass p \
		--atyp domain --dst localhost "$fp" "$hp"
}

# stop_front <pid>: SIGTERM the front and wait (bounded) for it to exit.
stop_front()
{
	local pid="$1" i

	wait_sigterm_handled "$pid" || fail "front $pid never set up SIGTERM"
	kill -TERM "$pid" 2>/dev/null
	for i in $(seq 1 200); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$pid" 2>/dev/null && fail "front $pid did not exit on SIGTERM"
	wait "$pid" 2>/dev/null
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 --log-level=4 \
		--auth-file="$WORK/auth" --acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	hold "$loop m1" m;	m1="$HELD"
	hold "$loop m2" m;	m2="$HELD"
	hold "$loop m3" m;	m3="$HELD"
	want "$loop m" "picks" "$(picks p_m)" "1 2 1"

	# Both full: refused as unreachable, through either front.
	want "$loop full" "reply" "$(rep m)" "REP=0x04"
	got="$(curl -s --max-time 20 --proxytunnel \
		--proxy "http://m:p@127.0.0.1:$fp" -w '%{http_connect}' \
		"$url" -o /dev/null)"
	want "$loop full" "CONNECT reply" "$got" "502"
	# A UDP ASSOCIATE through the full pool gets the same answer.
	got="$(SOCKS5_USER=m SOCKS5_PASS=p python3 \
		"$SERVERS_DIR/socks5_udp_up_client.py" "$fp")"
	want "$loop full" "UDP ASSOCIATE reply" "$got" "REP 4"
	want "$loop full" "refusals logged" \
		"$(grep -c "Upstream pool p_m has no server with room for idx=[0-9]*: all are full or out" "$log")" 3

	# p_n's cap for g1 is 3: one more through it, and p_m stays full.
	hold "$loop n1" n;	n1="$HELD"
	want "$loop n" "picks" "$(picks p_n)" "1"
	want "$loop full again" "reply" "$(rep m)" "REP=0x04"

	# Two of g1's tunnels go: g1 has room for p_m again.
	nrel="$(grep -c 'released by idx=' "$log")"
	release "$m1" $((nrel + 1))
	release "$n1" $((nrel + 2))
	hold "$loop m4" m;	m4="$HELD"
	got="$(picks p_m)"
	want "$loop room" "last pick" "${got##* }" "1"
	want "$loop room" "refusals" \
		"$(grep -c "Upstream pool p_m has no server with room" "$log")" 4

	for pid in "$m2" "$m3" "$m4"; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

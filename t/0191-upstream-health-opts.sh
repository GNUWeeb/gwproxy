#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pool's own passive health settings for its servers (max_fails=,
# fail_timeout=, eject_time=), on every available event loop.
#
#  - One server that refuses connections is listed by three pools: with
#    max_fails=1 in p_a, which ejects it at its first failure; with
#    max_fails=0 in p_b, which never ejects it and keeps retrying its
#    clients elsewhere; and with the defaults in p_c. The failures are the
#    server's, whichever pool they came through: the third, through p_b,
#    takes it out of p_c before p_c ever tried it.
#  - eject_time=1s: the server is back in its turn a second later, logged.
#  - fail_timeout=3s with max_fails=2: two failures further apart do not
#    eject, two closer together do.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"
url="http://127.0.0.1:$hp/payload.bin"

# rec_start <socks5|http> <name>: a recording upstream; sets REC_PORT.
rec_start()
{
	local port log="$WORK/rec.$2.log"

	port="$(pick_port)"
	: >"$log"
	python3 "$SERVERS_DIR/recording_proxy.py" "$1" 127.0.0.1 "$port" \
		"$log" >"$WORK/rec.$2.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $2 upstream did not listen"
	REC_PORT="$port"
}

rec_start socks5 g1;	g1="$REC_PORT"
rec_start socks5 g2;	g2="$REC_PORT"
closed_port;	dead1="$CLOSED_PORT"
closed_port;	dead2="$CLOSED_PORT"
closed_port;	dead3="$CLOSED_PORT"

printf '%s\n' a:p b:p c:p e:p f:p >"$WORK/auth"
acl="$WORK/main.acl"
{
	echo 'upstream p_a {'
	echo "	server socks5h://127.0.0.1:$dead1 max_fails=1;"
	echo "	server socks5h://127.0.0.1:$g1;"
	echo '}'
	echo 'upstream p_b {'
	echo "	server socks5h://127.0.0.1:$dead1 max_fails=0;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '}'
	echo 'upstream p_c {'
	echo "	server socks5h://127.0.0.1:$dead1;"
	echo "	server socks5h://127.0.0.1:$g1;"
	echo '}'
	echo 'upstream p_e {'
	echo "	server socks5h://127.0.0.1:$dead2 max_fails=1 eject_time=1s;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '}'
	echo 'upstream p_f {'
	echo "	server socks5h://127.0.0.1:$dead3 fail_timeout=3s max_fails=2;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '}'
	for p in a b c e f; do
		echo "-A OUTPUT -m user --user $p -j UPSTREAM --to p_$p"
	done
} >"$acl"
chmod 600 "$acl"

# picks <pool>: the servers <pool> was picked for, in order, as "1 2 1".
picks()
{
	sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" \
		"$log" | tr '\n' ' ' | sed 's/ $//'
}

# nretry <pool>: how many pairs of <pool> were retried on another server.
nretry()
{
	grep -c "Upstream retry for idx=[0-9]*: pool $1 server " "$log"
}

# count <pattern>: the log lines that match.
count()
{
	grep -c "$1" "$log"
}

# get <tag> <user>: the payload must arrive intact through <user>'s pool.
get()
{
	rm -f "$WORK/out.bin"
	curl -s --max-time 20 --proxy "socks5h://$2:p@127.0.0.1:$fp" "$url" \
		-o "$WORK/out.bin" || fail "[$1] the transfer failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$1] the payload was corrupted"
}

# want <tag> <what> <got> <want>
want()
{
	[ "$3" = "$4" ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$1] $2: got '$3', want '$4'"
	}
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
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	d1="(127\.0\.0\.1:$dead1)"

	# max_fails=1: out of p_a at its first failure.
	for i in 1 2 3 4; do
		get "$loop a $i" a
	done
	want "$loop a" "picks" "$(picks p_a)" "1 2 2 2"
	want "$loop a" "retries" "$(nretry p_a)" 1
	want "$loop a" "ejections" \
		"$(count "Upstream pool p_a server 1 $d1 ejected for 300 s after 1 failures in 30 s")" 1

	# max_fails=0: never out of p_b, though out of p_a.
	for i in 1 2 3 4; do
		get "$loop b $i" b
	done
	want "$loop b" "picks" "$(picks p_b)" "1 2 1 2"
	want "$loop b" "retries" "$(nretry p_b)" 2

	# Three failures in 30 s, through p_a and p_b: out of p_c too.
	want "$loop c" "ejections" \
		"$(count "Upstream 127\.0\.0\.1:$dead1 ejected for 300 s after 3 failures in 30 s, in the pools that list it with these settings")" 1
	for i in 1 2 3 4; do
		get "$loop c $i" c
	done
	want "$loop c" "picks" "$(picks p_c)" "2 2 2 2"
	want "$loop c" "retries" "$(nretry p_c)" 0
	want "$loop c" "failures" \
		"$(count "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$dead1, ")" 3

	# eject_time=1s: back in its turn after a second.
	get "$loop e 1" e
	want "$loop e" "ejections" \
		"$(count "Upstream pool p_e server 1 (127\.0\.0\.1:$dead2) ejected for 1 s after 1 failures in 30 s")" 1
	sleep 1.5
	get "$loop e 2" e
	get "$loop e 3" e
	want "$loop e" "picks" "$(picks p_e)" "1 2 1"
	want "$loop e" "retries" "$(nretry p_e)" 2
	want "$loop e" "returns" \
		"$(count "Upstream pool p_e server 1 (127\.0\.0\.1:$dead2) is back in service")" 1
	want "$loop e" "ejections" \
		"$(count "Upstream pool p_e server 1 (127\.0\.0\.1:$dead2) ejected for 1 s")" 2

	# fail_timeout=3s, max_fails=2: two failures 3.5 s apart do not
	# eject; the next, right after the second, does.
	get "$loop f 1" f
	sleep 3.5
	for i in 2 3 4 5 6 7; do
		get "$loop f $i" f
	done
	want "$loop f" "picks" "$(picks p_f)" "1 2 1 2 1 2 2"
	want "$loop f" "retries" "$(nretry p_f)" 3
	want "$loop f" "ejections" \
		"$(count "Upstream pool p_f server 1 (127\.0\.0\.1:$dead3) ejected for 300 s after 2 failures in 3 s")" 1

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

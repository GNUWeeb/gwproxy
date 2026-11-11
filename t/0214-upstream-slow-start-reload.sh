#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# slow_start= when a reload brings a server into a pool, on every available
# event loop. "Few" below means at most 2 of 20 connections (with
# slow_start=1h the chance is a few thousandths each), where the server's
# turns would give it 10.
#
#  - A SIGHUP reload that adds g2 to p_a with slow_start=1h: g2 gets few of
#    p_a's connections, and the start is logged. The same reload adds g2 to
#    p_b with no slow start: p_b takes it in turn at once.
#  - A reload that keeps p_a's settings for g2 keeps its ramp: still few,
#    and no new start is logged.
#  - A reload that changes g2's settings in p_a to no slow start gives it
#    its turns back.
#  - A server that a reload takes out of down, with slow_start=1h (p_c's
#    g3), ramps as a newcomer does.

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
rec_start g3;	g3="$REC_PORT"

printf '%s\n' a:p b:p c:p >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <p_a's g2 line, or nothing> <p_b's g2 line> <p_c's g3 options>
write_acl()
{
	{
		echo "# $RANDOM"
		echo 'upstream p_a {'
		echo "	server socks5h://127.0.0.1:$g1;"
		[ -n "$1" ] && echo "	server socks5h://127.0.0.1:$g2 $1;"
		echo '}'
		echo 'upstream p_b {'
		echo "	server socks5h://127.0.0.1:$g1;"
		[ -n "$2" ] && echo "	server socks5h://127.0.0.1:$g2 $2;"
		echo '}'
		echo 'upstream p_c {'
		echo "	server socks5h://127.0.0.1:$g1;"
		echo "	server socks5h://127.0.0.1:$g3 $3;"
		echo '}'
		for p in a b c; do
			echo "-A OUTPUT -m user --user $p -j UPSTREAM --to p_$p"
		done
	} >"$acl.tmp"
	chmod 600 "$acl.tmp"
	mv -f "$acl.tmp" "$acl"
}

# picks <pool>: the servers <pool> was picked for, in order, as "1 2 1".
picks()
{
	sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" \
		"$log" | tr '\n' ' ' | sed 's/ $//'
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

# few <tag> <pool> <server>: of <pool>'s last 20 picks, <server> took few.
few()
{
	local got

	got="$(picks "$2" | tr ' ' '\n' | tail -n 20 | grep -c "^$3\$")"
	[ "$got" -le 2 ] || {
		tail -n 60 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$1] server $3 of $2, in its slow start, took $got of 20"
	}
}

# reload <tag>: SIGHUP and wait for the ACL to be reloaded.
reload()
{
	local n

	n="$(count 'Reloaded ACL file')"
	gwp_hup "$front" "$log" 2
	want "$1" "reloads" "$(count 'Reloaded ACL file')" "$((n + 1))"
	# A reload starts each pool's turns again; the picks count from here.
	MARK="$(wc -l <"$log")"
}

# picks_since <pool>: picks of <pool> after the last reload.
picks_since()
{
	tail -n "+$((MARK + 1))" "$log" |
		sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" |
		tr '\n' ' ' | sed 's/ $//'
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

	write_acl "" "" "down slow_start=1h"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	get "$loop a 0" a
	want "$loop" "starts" "$(count 'comes into service on a slow start')" 0

	# g2 comes into p_a on a slow start, into p_b without.
	write_acl "slow_start=1h" "max_fails=2" "down slow_start=1h"
	reload "$loop add"
	want "$loop add" "starts" \
		"$(count "Upstream 127\.0\.0\.1:$g2 comes into service on a slow start of 3600 s")" 1
	for i in $(seq 1 20); do
		get "$loop add a $i" a
	done
	few "$loop add" p_a 2
	for i in 1 2 3 4; do
		get "$loop add b $i" b
	done
	want "$loop add b" "picks" "$(picks_since p_b)" "1 2 1 2"

	# The same settings: the ramp goes on.
	write_acl "slow_start=1h" "max_fails=2" "down slow_start=1h"
	reload "$loop same"
	for i in $(seq 1 20); do
		get "$loop same a $i" a
	done
	few "$loop same" p_a 2
	want "$loop same" "starts" "$(count 'comes into service on a slow start')" 1

	# Settings changed to no slow start: its turns at once.
	write_acl "slow_start=0" "max_fails=2" "down slow_start=1h"
	reload "$loop off"
	for i in 1 2 3 4; do
		get "$loop off a $i" a
	done
	want "$loop off" "picks" "$(picks_since p_a)" "1 2 1 2"

	# Out of down: a slow start too.
	write_acl "slow_start=0" "max_fails=2" "slow_start=1h"
	reload "$loop up"
	want "$loop up" "starts" \
		"$(count "Upstream 127\.0\.0\.1:$g3 comes into service on a slow start of 3600 s")" 1
	for i in $(seq 1 20); do
		get "$loop up c $i" c
	done
	few "$loop up" p_c 2

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

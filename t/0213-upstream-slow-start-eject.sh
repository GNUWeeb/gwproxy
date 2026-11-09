#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# slow_start= after an ejection, on every available event loop.
#
#  - A pool server that refuses connections is ejected at its first failure
#    (max_fails=1, eject_time=1s); it is then started for real. Without a
#    slow start it is back in its turn once the second is over (pool p_n:
#    1 2 1 2). With slow_start=1h (p_s) it comes back with next to nothing
#    of its weight: of 20 connections it takes at most 2 (the chance is a
#    few thousandths each), not its 10, and its return is logged with the
#    slow start.
#  - With slow_start=2s (p_q) the ramp runs out: 4 seconds after the
#    ejection ends the server has its turns back (1 2 1 2).
#  - At startup nothing ramps: a pool whose servers all have slow_start=1h
#    takes them in turn from its first connection.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"
url="http://127.0.0.1:$hp/payload.bin"

# rec_on <name> <port>: a recording SOCKS5 upstream on <port>.
rec_on()
{
	local log="$WORK/rec.$1.log"

	: >"$log"
	python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$2" \
		"$log" >"$WORK/rec.$1.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$2" "$!" || fail "the $1 upstream did not listen"
}

g1="$(pick_port)";	rec_on g1 "$g1"
g2="$(pick_port)";	rec_on g2 "$g2"

printf '%s\n' n:p s:p q:p z:p >"$WORK/auth"

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

	# Nothing listens on these yet: refused, so ejected at once.
	dn="$(pick_port)"
	ds="$(pick_port)"
	dq="$(pick_port)"
	acl="$WORK/main.$loop.acl"
	{
		echo 'upstream p_n {'
		echo "	server socks5h://127.0.0.1:$dn max_fails=1 eject_time=1s;"
		echo "	server socks5h://127.0.0.1:$g1;"
		echo '}'
		echo 'upstream p_s {'
		echo "	server socks5h://127.0.0.1:$ds max_fails=1 eject_time=1s slow_start=1h;"
		echo "	server socks5h://127.0.0.1:$g1;"
		echo '}'
		echo 'upstream p_q {'
		echo "	server socks5h://127.0.0.1:$dq max_fails=1 eject_time=1s slow_start=2s;"
		echo "	server socks5h://127.0.0.1:$g1;"
		echo '}'
		echo 'upstream p_z {'
		echo "	server socks5h://127.0.0.1:$g1 slow_start=1h;"
		echo "	server socks5h://127.0.0.1:$g2 slow_start=1h max_fails=0;"
		echo '}'
		for p in n s q z; do
			echo "-A OUTPUT -m user --user $p -j UPSTREAM --to p_$p"
		done
	} >"$acl"
	chmod 600 "$acl"

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	# A first load: nothing ramps, the turns as usual.
	for i in 1 2 3 4; do
		get "$loop z $i" z
	done
	want "$loop z" "picks" "$(picks p_z)" "1 2 1 2"
	want "$loop" "ramps at startup" "$(count 'on a slow start')" 0

	# Each first server fails once and is ejected; its client retried.
	for p in n s q; do
		get "$loop $p 1" "$p"
	done
	for p in n s q; do
		want "$loop $p" "ejections" \
			"$(count "Upstream pool p_$p server 1 (.*) ejected for 1 s after 1 failures")" 1
	done
	rec_on "n.$loop" "$dn"
	rec_on "s.$loop" "$ds"
	rec_on "q.$loop" "$dq"
	sleep 1.5

	# No slow start: back in its turn.
	for i in 2 3 4 5; do
		get "$loop n $i" n
	done
	want "$loop n" "picks" "$(picks p_n)" "1 2 1 2 1"
	want "$loop n" "returns" \
		"$(count "Upstream pool p_n server 1 (127\.0\.0\.1:$dn) is back in service after its ejection$")" 1

	# slow_start=1h: next to nothing of its turns.
	for i in $(seq 2 21); do
		get "$loop s $i" s
	done
	got="$(picks p_s | tr ' ' '\n' | sed 1d | grep -c '^1$')"
	[ "$got" -le 2 ] || {
		tail -n 60 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$loop s] the returning server took $got of 20 connections"
	}
	want "$loop s" "returns" \
		"$(count "Upstream pool p_s server 1 (127\.0\.0\.1:$ds) is back in service after its ejection, on a slow start of 3600 s")" 1

	# slow_start=2s: over 4 s after the end of the ejection.
	sleep 3
	for i in 2 3 4 5; do
		get "$loop q $i" q
	done
	want "$loop q" "picks" "$(picks p_q)" "1 2 1 2 1"
	want "$loop q" "returns" \
		"$(count "Upstream pool p_q server 1 (127\.0\.0\.1:$dq) is back in service after its ejection, on a slow start of 2 s")" 1

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

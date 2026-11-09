#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# slow_start= with least_conn, on every available event loop.
#
#  - Six tunnels held open through g1, the only server of a least_conn
#    pool; a SIGHUP reload adds an idle g2 with slow_start=1h. Of six more
#    held tunnels g2 takes one: it counts its open tunnels against next to
#    nothing of its weight, so with one open it is far busier than g1 with
#    six. Without a slow start (p_n, the same steps) g2 takes all six.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"

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

printf '%s\n' s:p n:p >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <g2 too, 0 or 1>
write_acl()
{
	{
		echo 'upstream p_s {'
		echo "	server socks5h://127.0.0.1:$g1;"
		[ "$1" = 1 ] && echo "	server socks5h://127.0.0.1:$g2 slow_start=1h;"
		echo '	least_conn;'
		echo '}'
		echo 'upstream p_n {'
		echo "	server socks5h://127.0.0.1:$g1;"
		[ "$1" = 1 ] && echo "	server socks5h://127.0.0.1:$g2 max_fails=2;"
		echo '	least_conn;'
		echo '}'
		echo '-A OUTPUT -m user --user s -j UPSTREAM --to p_s'
		echo '-A OUTPUT -m user --user n -j UPSTREAM --to p_n'
	} >"$acl.tmp"
	chmod 600 "$acl.tmp"
	mv -f "$acl.tmp" "$acl"
}

# picks_since <pool>: the servers <pool> was picked for after the mark, as
# per-server counts "<n> <server>;".
picks_since()
{
	tail -n "+$((MARK + 1))" "$log" |
		sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" |
		sort | uniq -c | tr -s ' ' | tr '\n' ';'
}

# want <tag> <what> <got> <want>
want()
{
	[ "$3" = "$4" ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$1] $2: got '$3', want '$4'"
	}
}

# hold <tag> <user> <n>: <n> more tunnels held open through <user>'s pool.
hold()
{
	local i out pid

	for i in $(seq 1 "$3"); do
		out="$WORK/held.$1.$i.out"
		python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" "$2" p \
			localhost "$hp" /payload.bin "$WORK/go.never" \
			>"$out" 2>&1 &
		pid=$!
		_PIDS+=("$pid")
		held+=("$pid")
		timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $pid 2>/dev/null; do sleep 0.1; done"
		grep -q '^FIRST 20000$' "$out" || {
			sed 's/^/# client: /' "$out" >&2
			fail "[$1 $i] the held tunnel did not get through"
		}
	done
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

	write_acl 0
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	held=()

	for u in s n; do
		MARK=0
		hold "$loop $u before" "$u" 6
		want "$loop $u" "picks before" "$(picks_since "p_$u")" " 6 1;"
	done

	write_acl 1
	gwp_hup "$front" "$log" 1
	MARK="$(wc -l <"$log")"
	hold "$loop s after" s 6
	want "$loop s" "picks after" "$(picks_since p_s)" " 5 1; 1 2;"
	MARK="$(wc -l <"$log")"
	hold "$loop n after" n 6
	want "$loop n" "picks after" "$(picks_since p_n)" " 6 2;"

	for pid in "${held[@]}"; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

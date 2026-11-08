#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# weight= on pool servers, on every available event loop.
#
#  - Round-robin: a server of weight 3 next to one of weight 1 gets three
#    of every four connections, its turns spread (1 1 1 2, then again).
#  - least_conn: with tunnels held open, a server of weight 3 next to one
#    of weight 1 ends up holding three times as many.

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

printf '%s\n' w:p l:p >"$WORK/auth"
acl="$WORK/main.acl"
{
	echo 'upstream p_w {'
	echo "	server socks5h://127.0.0.1:$g1 weight=3;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '}'
	echo 'upstream p_l {'
	echo "	server socks5h://127.0.0.1:$g1 weight=1;"
	echo "	server socks5h://127.0.0.1:$g2 weight=3;"
	echo '	least_conn;'
	echo '}'
	echo '-A OUTPUT -m user --user w -j UPSTREAM --to p_w'
	echo '-A OUTPUT -m user --user l -j UPSTREAM --to p_l'
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

	for i in 1 2 3 4 5 6 7 8; do
		rm -f "$WORK/out.bin"
		curl -s --max-time 20 --proxy "socks5h://w:p@127.0.0.1:$fp" \
			"$url" -o "$WORK/out.bin" ||
			fail "[$loop w $i] the transfer failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$loop w $i] the payload was corrupted"
	done
	want "$loop w" "picks" "$(picks p_w)" "1 1 1 2 1 1 1 2"

	# Eight tunnels held open, one after the other.
	held=()
	for i in 1 2 3 4 5 6 7 8; do
		out="$WORK/held.$loop.$i.out"
		python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" l p \
			localhost "$hp" /payload.bin "$WORK/go.never" \
			>"$out" 2>&1 &
		pid=$!
		_PIDS+=("$pid")
		held+=("$pid")
		timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $pid 2>/dev/null; do sleep 0.1; done"
		grep -q '^FIRST 20000$' "$out" || {
			sed 's/^/# client: /' "$out" >&2
			fail "[$loop l $i] the held tunnel did not get through"
		}
	done
	got="$(picks p_l | tr ' ' '\n' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
	want "$loop l" "picks per server" "$got" " 2 1; 6 2;"
	for pid in "${held[@]}"; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

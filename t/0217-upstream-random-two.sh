#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The "random two" pool method by load, and the random methods with
# slow_start=, on every available event loop.
#
#  - Ten tunnels held open through g1 (by p_h, which lists only it). Of 12
#    more held through p_2 (random two over g1, g2 and g3), g1 takes at
#    most one, where "random" would give it about four: of two servers drawn the one with fewer open wins, and g1
#    loses to either idle one (it wins only when every draw but one lands
#    on it, a chance of about 1 in 700 a tunnel).
#  - A SIGHUP reload adds g4 with slow_start=1h to p_r (random): of 20
#    connections it takes at most 2 (the chance is a few thousandths each),
#    where its draws would give it about 10.

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
rec_start g4;	g4="$REC_PORT"

printf '%s\n' h:p t:p r:p >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <g4 in p_r, 0 or 1>
write_acl()
{
	{
		echo 'upstream p_h {'
		echo "	server socks5h://127.0.0.1:$g1;"
		echo '}'
		echo 'upstream p_2 {'
		echo "	server socks5h://127.0.0.1:$g1;"
		echo "	server socks5h://127.0.0.1:$g2;"
		echo "	server socks5h://127.0.0.1:$g3;"
		echo '	random two;'
		echo '}'
		echo 'upstream p_r {'
		echo '	random;'
		echo "	server socks5h://127.0.0.1:$g3;"
		[ "$1" = 1 ] && echo "	server socks5h://127.0.0.1:$g4 slow_start=1h;"
		echo '}'
		echo '-A OUTPUT -m user --user h -j UPSTREAM --to p_h'
		echo '-A OUTPUT -m user --user t -j UPSTREAM --to p_2'
		echo '-A OUTPUT -m user --user r -j UPSTREAM --to p_r'
	} >"$acl.tmp"
	chmod 600 "$acl.tmp"
	mv -f "$acl.tmp" "$acl"
}

# npicks <pool> <server>: how many times <pool> picked <server>.
npicks()
{
	sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" \
		"$log" | grep -c "^$2\$"
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

	# g1 busy: random two leaves it alone.
	hold "$loop h" h 10
	hold "$loop t" t 12
	n="$(npicks p_2 1)"
	[ "$n" -le 1 ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$loop t] the busy server took $n of 12 tunnels"
	}
	for pid in "${held[@]}"; do
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done

	# A newcomer on a slow start is drawn but next to never taken.
	write_acl 1
	gwp_hup "$front" "$log" 1
	grep -q "Upstream 127\.0\.0\.1:$g4 comes into service on a slow start of 3600 s" "$log" ||
		fail "[$loop r] the slow start was not logged"
	for i in $(seq 1 20); do
		get "$loop r $i" r
	done
	n="$(npicks p_r 2)"
	[ "$n" -le 2 ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$loop r] the server in its slow start took $n of 20"
	}

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

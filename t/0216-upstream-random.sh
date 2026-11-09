#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The "random" pool method, on every available event loop.
#
#  - p_r (random; weights 1, 1, 2; a server down; a backup): of 60
#    connections each main server gets some; the down server and the
#    backup none.
#  - p_f (random two): its g1 has max_conns=1 and a tunnel held through
#    p_h, which lists it too, fills it: every connection goes to g2.
#  - p_e (random): a server that refuses connections, max_fails=1, is
#    ejected at its first draw, its client retried on another server, and
#    never drawn again.
#  - p_x (random two): the same with max_fails=0: drawn again and again,
#    each time retried on another server, never on itself.

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
rec_start g5;	g5="$REC_PORT"
closed_port;	dead1="$CLOSED_PORT"
closed_port;	dead2="$CLOSED_PORT"

printf '%s\n' r:p f:p h:p e:p x:p >"$WORK/auth"
acl="$WORK/main.acl"
{
	echo 'upstream p_r {'
	echo "	server socks5h://127.0.0.1:$g1;"
	echo "	server socks5h://127.0.0.1:$g4 down;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo "	server socks5h://127.0.0.1:$g5 backup;"
	echo "	server socks5h://127.0.0.1:$g3 weight=2;"
	echo '	random;'
	echo '}'
	echo 'upstream p_h {'
	echo "	server socks5h://127.0.0.1:$g1;"
	echo '}'
	echo 'upstream p_f {'
	echo '	random two;'
	echo "	server socks5h://127.0.0.1:$g1 max_conns=1;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '}'
	echo 'upstream p_e {'
	echo "	server socks5h://127.0.0.1:$dead1 max_fails=1;"
	echo "	server socks5h://127.0.0.1:$g1;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '	random;'
	echo '}'
	echo 'upstream p_x {'
	echo "	server socks5h://127.0.0.1:$dead2 max_fails=0;"
	echo "	server socks5h://127.0.0.1:$g1;"
	echo "	server socks5h://127.0.0.1:$g2;"
	echo '	random two;'
	echo '}'
	for p in r f h e x; do
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

# npicks <pool> <server>: how many times <pool> picked <server>.
npicks()
{
	picks "$1" | tr ' ' '\n' | grep -c "^$2\$"
}

# retries <pool>: the servers <pool>'s retries went to, as "2 3".
retries()
{
	sed -n "s/.*Upstream retry for idx=[0-9]*: pool $1 server [0-9]* (.*) failed, trying server \([0-9]*\) .*/\1/p" \
		"$log" | tr '\n' ' ' | sed 's/ $//'
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

	# Drawn by weight among the main servers that are not down.
	for i in $(seq 1 60); do
		get "$loop r $i" r
	done
	for s in 1 3 5; do
		n="$(npicks p_r "$s")"
		[ "$n" -ge 3 ] || fail "[$loop r] server $s was picked $n times of 60: $(picks p_r)"
	done
	want "$loop r" "picks of the down server" "$(npicks p_r 2)" 0
	want "$loop r" "picks of the backup" "$(npicks p_r 4)" 0

	# A full server is not drawn.
	out="$WORK/held.$loop.out"
	python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" h p localhost "$hp" \
		/payload.bin "$WORK/go.never" >"$out" 2>&1 &
	held=$!
	_PIDS+=("$held")
	timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $held 2>/dev/null; do sleep 0.1; done"
	grep -q '^FIRST 20000$' "$out" || {
		sed 's/^/# client: /' "$out" >&2
		fail "[$loop f] the held tunnel did not get through"
	}
	for i in $(seq 1 10); do
		get "$loop f $i" f
	done
	want "$loop f" "picks" "$(picks p_f)" "2 2 2 2 2 2 2 2 2 2"
	kill "$held" 2>/dev/null
	wait "$held" 2>/dev/null

	# Ejected at its first draw, retried elsewhere, never drawn again.
	for i in $(seq 1 20); do
		get "$loop e $i" e
	done
	want "$loop e" "picks of the dead server" "$(npicks p_e 1)" 1
	want "$loop e" "retries on it" \
		"$(retries p_e | tr ' ' '\n' | grep -c '^1$')" 0
	want "$loop e" "retries" "$(retries p_e | wc -w)" 1

	# Never ejected: retried on another server each time it is drawn.
	for i in $(seq 1 20); do
		get "$loop x $i" x
	done
	n="$(npicks p_x 1)"
	[ "$n" -ge 1 ] || fail "[$loop x] the dead server was never drawn"
	want "$loop x" "retries" "$(retries p_x | wc -w)" "$n"
	want "$loop x" "retries on it" \
		"$(retries p_x | tr ' ' '\n' | grep -c '^1$')" 0

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

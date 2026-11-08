#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# backup and down on pool servers, on every available event loop.
#
#  - A server marked down is never picked or contacted; a backup idles
#    while a main server is in service.
#  - When the only main server fails, its client is retried on the backup,
#    and once the main server is ejected the backup takes every client.
#  - A SIGHUP reload that marks the main server down moves the clients to
#    the other server.

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
closed_port;	dead1="$CLOSED_PORT"
closed_port;	dead2="$CLOSED_PORT"

printf '%s\n' b:p c:p >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <p_b's first server line's tail>
write_acl()
{
	{
		echo 'upstream p_b {'
		echo "	server socks5h://127.0.0.1:$g1$1;"
		echo "	server socks5h://127.0.0.1:$dead1 down;"
		echo "	server socks5h://127.0.0.1:$g2 backup;"
		echo '}'
		echo 'upstream p_c {'
		echo "	server socks5h://127.0.0.1:$dead2 max_fails=1;"
		echo "	server socks5h://127.0.0.1:$g2 backup;"
		echo "	server socks5h://127.0.0.1:$g1 down;"
		echo '}'
		echo '-A OUTPUT -m user --user b -j UPSTREAM --to p_b'
		echo '-A OUTPUT -m user --user c -j UPSTREAM --to p_c'
	} >"$acl.tmp"
	chmod 600 "$acl.tmp"
	mv "$acl.tmp" "$acl"
}

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

	write_acl ""
	: >"$WORK/rec.g2.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	# The main server takes all; down and backup take nothing.
	for i in 1 2 3 4; do
		get "$loop b $i" b
	done
	want "$loop b" "picks" "$(picks p_b)" "1 1 1 1"
	want "$loop b" "the backup's connections" \
		"$(wc -l <"$WORK/rec.g2.log")" 0

	# The main server fails: retried on the backup, then ejected.
	for i in 1 2 3; do
		get "$loop c $i" c
	done
	want "$loop c" "picks" "$(picks p_c)" "1 2 2"
	want "$loop c" "retries" "$(nretry p_c)" 1
	want "$loop c" "the backup's connections" \
		"$(wc -l <"$WORK/rec.g2.log")" 3

	# A reload marks p_b's main server down: the backup takes over.
	write_acl " down"
	gwp_hup "$front" "$log" 2
	grep -q "Failed to reload" "$log" && fail "[$loop] the reload failed"
	for i in 1 2; do
		get "$loop down $i" b
	done
	want "$loop down" "picks" "$(picks p_b)" "1 1 1 1 3 3"

	# Never a connection to a server that is down.
	grep -q "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$dead1," \
		"$log" && fail "[$loop] a down server was tried"

	stop_front "$front"
	grep -q "BUG:" "$log" && fail "[$loop] gwproxy found an accounting bug"
done

pass

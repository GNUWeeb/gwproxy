#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream pools across ACL reloads, which SIGHUP asks for. A reload that
# moves a user to another pool sends that user's new connections through
# the new pool, while a tunnel already open through the old one keeps
# working; the old pool's server outlives its pool for as long as the
# tunnel does, and every reference to it is given back by the time gwproxy
# exits, which it checks and says at debug level (the t/0049 style). A pool
# server that cannot be used (a host that is no name or address, a name
# that does not resolve) fails the load at startup, naming the file and
# line and never the password, and on reload leaves the rules in force. On
# every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 30000
start_httpd "$hp" "$WORK" "1.1"

acl_ok="Reloaded ACL file"
acl_bad="Failed to reload ACL file"

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

rec_start socks5 old
ro="$REC_PORT"
rec_start http new
rn="$REC_PORT"

lines()
{
	wc -l <"$WORK/rec.$1.log"
}

# wait_lines <log> <text> <count>: poll until <text> is logged <count> times.
wait_lines()
{
	local i

	for i in $(seq 1 300); do
		[ "$(grep -c "$2" "$1")" -ge "$3" ] && return 0
		sleep 0.1
	done
	return 1
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

# start_bad <name> <acl>: gwproxy must refuse to start with <acl>.
start_bad()
{
	local ec=0

	timeout --foreground 60 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
		--as-socks5=1 --acl-file="$2" >"$WORK/$1.log" 2>&1 || ec=$?
	{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
		fail "$1: gwproxy accepted the ACL (exit $ec)"
	! grep -q s3cret "$WORK/$1.log" || fail "$1: a password was logged"
}

printf 'alice:pa\n' >"$WORK/auth"
d="$WORK/acl"
mkdir -p "$d"

# Refused at startup, with the file and line at fault.
for host in - 999.999.1.1 no-such-host.invalid; do
	why="the host is not a valid name or address"
	[ "$host" = no-such-host.invalid ] && why="host $host does not resolve"
	printf -- '%s\n' 'upstream p {' '	server socks5://127.0.0.1:1;' \
		"	server socks5://u:s3cret@$host:1080;" '}' >"$d/bad.acl"
	chmod 600 "$d/bad.acl"
	start_bad "bad-$host" "$d/bad.acl"
	grep -q "bad.acl: line 3: upstream pool p server 2 (socks5://$host:1080): $why" \
		"$WORK/bad-$host.log" || {
		sed 's/^/# gwp: /' "$WORK/bad-$host.log" >&2
		fail "the bad server $host was not reported"
	}
done

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	printf -- '%s\n' 'upstream p {' "	server socks5h://127.0.0.1:$ro;" \
		'}' '-A OUTPUT -m user --user alice -j UPSTREAM --to p' \
		>"$d/main.acl"
	chmod 600 "$d/main.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$d/main.acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	n_old="$(lines old)"
	n_new="$(lines new)"

	# A tunnel through the old pool, held open across the reload.
	go="$WORK/go.$loop"
	out="$WORK/held.$loop.out"
	rm -f "$go"
	python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" alice pa \
		localhost "$hp" /payload.bin "$go" >"$out" 2>&1 &
	held=$!
	_PIDS+=("$held")
	timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $held 2>/dev/null; do sleep 0.1; done"
	grep -q '^FIRST 30000$' "$out" || {
		sed 's/^/# client: /' "$out" >&2
		fail "[$loop] the held tunnel did not get through"
	}
	[ "$(lines old)" -eq $((n_old + 1)) ] || \
		fail "[$loop] the old pool did not carry the held tunnel"

	# Move alice to another pool.
	n_ok="$(grep -c "$acl_ok" "$log")"
	printf -- '%s\n' 'upstream p {' "	server http://127.0.0.1:$rn;" \
		'}' '-A OUTPUT -m user --user alice -j UPSTREAM --to p' \
		>"$d/main.acl"
	gwp_hup "$front" "$log" 2
	wait_lines "$log" "$acl_ok" $((n_ok + 1)) || \
		fail "[$loop] the edit was not reloaded"
	curl -s --max-time 20 --proxy "socks5h://alice:pa@127.0.0.1:$fp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out.bin" || \
		fail "[$loop] a new connection after the reload failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] a new connection after the reload was corrupted"
	[ "$(lines new)" -eq $((n_new + 1)) ] && \
	[ "$(lines old)" -eq $((n_old + 1)) ] || \
		fail "[$loop] a new connection did not follow alice to the new pool"

	# The held tunnel still works, through the server of a pool now gone.
	touch "$go"
	timeout 60 bash -c "until grep -q '^HELD' '$out' || ! kill -0 $held 2>/dev/null; do sleep 0.1; done"
	grep -q '^SECOND 30000$' "$out" || {
		sed 's/^/# client: /' "$out" >&2
		fail "[$loop] the held tunnel broke at the reload"
	}

	# A bad server fails the reload, and alice stays where she is.
	for host in - 999.999.1.1; do
		n_bad="$(grep -c "$acl_bad" "$log")"
		printf -- '%s\n' 'upstream p {' \
			"	server http://u:s3cret@$host:1;" '}' \
			'-A OUTPUT -m user --user alice -j UPSTREAM --to p' \
			>"$d/main.acl"
		gwp_hup "$front" "$log" 2
		wait_lines "$log" "$acl_bad" $((n_bad + 1)) || \
			fail "[$loop] the bad server $host did not fail the reload"
		grep -q "main.acl: line 2: upstream pool p server 1 (http://$host:1): the host is not a valid name or address" \
			"$log" || fail "[$loop] the bad server $host was not reported"
	done
	n_new="$(lines new)"
	curl -s --max-time 20 --proxy "socks5h://alice:pa@127.0.0.1:$fp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out.bin" || \
		fail "[$loop] a connection after the failed reload failed"
	[ "$(lines new)" -eq $((n_new + 1)) ] || \
		fail "[$loop] a failed reload changed alice's pool"
	! grep -q s3cret "$log" || fail "[$loop] a password was logged"

	# Stop with the tunnel through the old pool's server still open.
	stop_front "$front"
	kill "$held" 2>/dev/null
	wait "$held" 2>/dev/null
	if grep -q "BUG: .* upstream pool server(s) still referenced" "$log"; then
		grep "BUG: .* upstream pool server(s)" "$log" | sed 's/^/# gwp: /' >&2
		fail "[$loop] connections left pool servers' references off"
	fi
	grep -q "Upstream pool servers: all connection references dropped" \
		"$log" || {
		tail -n 20 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$loop] no verdict on the pool servers' references at exit"
	}
done

pass

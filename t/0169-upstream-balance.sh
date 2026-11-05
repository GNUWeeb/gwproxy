#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pool of several upstream servers spreads its connections over them.
# Three recording upstreams make up two pools: a round-robin one, through
# which sequential connections go to each server in turn, and a least_conn
# one, through which new connections avoid the servers that long-held
# tunnels keep busy. The open-pair counts that least_conn reads belong to
# the servers, not to the pool, so a reload that rebuilds the pool (and
# lists its servers in another order) keeps them: connections after it
# still avoid the busy servers, and the tunnels opened before it give
# their slots back when they close. Every way a pair ends gives its slot
# back, once: the client closing, the target refused by the upstream, the
# upstream refusing or answering garbage, the upstream refusing the TCP
# connection, and the idle timeout; afterwards every count is back to 0,
# which the next picks show, and gwproxy finds every reference given back
# at exit. Counts are read from the debug log: a pick says how many pairs
# its server then has open, a release how many it has left. On every
# available event loop.

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

rec_start r1
r1="$REC_PORT"
rec_start r2
r2="$REC_PORT"
rec_start r3
r3="$REC_PORT"

# An upstream that goes wrong as told (upstream_faults.py), and one that
# refuses the TCP connection; and a target that does.
rf="$(pick_port)"
echo refuse >"$WORK/fault"
python3 "$SERVERS_DIR/upstream_faults.py" socks5 "$rf" "$WORK/fault" \
	>"$WORK/faults.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$rf" "$!" || fail "the faulty upstream did not listen"
closed_port
rdead="$CLOSED_PORT"
closed_port
tdead="$CLOSED_PORT"

printf '%s\n' alice:pa bob:pb carol:pc >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <lc servers...>: the rules, with the least_conn pool's servers
# in the order given.
write_acl()
{
	local p

	{
		echo 'upstream rr {'
		for p in "$r1" "$r2" "$r3"; do
			echo "	server socks5h://127.0.0.1:$p;"
		done
		echo '}'
		echo 'upstream lc {'
		for p in "$@"; do
			echo "	server socks5h://127.0.0.1:$p;"
		done
		echo '	least_conn;'
		echo '}'
		echo 'upstream bad {'
		echo "	server socks5h://127.0.0.1:$rf;"
		echo "	server socks5h://127.0.0.1:$rdead;"
		echo '}'
		echo '-A OUTPUT -m user --user alice -j UPSTREAM --to rr'
		echo '-A OUTPUT -m user --user bob -j UPSTREAM --to lc'
		echo '-A OUTPUT -m user --user carol -j UPSTREAM --to bad'
	} >"$acl"
	chmod 600 "$acl"
}

lines()
{
	wc -l <"$WORK/rec.$1.log"
}

# npick <pool>: how many pairs picked a server of <pool>.
npick()
{
	grep -c "Upstream for idx=[0-9]*: pool $1 server " "$log"
}

# nrel: how many pairs gave their server back.
nrel()
{
	grep -c "Upstream 127\.0\.0\.1:[0-9]* released by idx=" "$log"
}

# last_pick <pool>: sets PICK_SRV, PICK_PORT and PICK_OPEN from the last
# pick of <pool>: the server's number, its port, and its count with it.
last_pick()
{
	local l

	l="$(grep "Upstream for idx=[0-9]*: pool $1 server " "$log" | tail -n 1)"
	PICK_SRV="$(sed -n 's/.* server \([0-9]*\), .*/\1/p' <<<"$l")"
	PICK_PORT="$(sed -n 's/.* server [0-9]*, 127\.0\.0\.1:\([0-9]*\) .*/\1/p' <<<"$l")"
	PICK_OPEN="$(sed -n 's/.*, \([0-9]*\) open$/\1/p' <<<"$l")"
	[ -n "$PICK_SRV" ] && [ -n "$PICK_PORT" ] && [ -n "$PICK_OPEN" ] || \
		fail "cannot read the pick '$l'"
}

# last_rel <port>: the count the last release of <port> left.
last_rel()
{
	grep "Upstream 127\.0\.0\.1:$1 released by idx=" "$log" | tail -n 1 | \
		sed -n 's/.*, \([0-9]*\) open$/\1/p'
}

# wait_rel <tag> <n>: wait (bounded) until <n> releases are logged.
wait_rel()
{
	local i

	for i in $(seq 1 600); do
		[ "$(nrel)" -ge "$2" ] && return 0
		sleep 0.1
	done
	tail -n 30 "$log" | sed 's/^/# gwp: /' >&2
	fail "$1: the pair did not give its server back"
}

# through <tag> <user:pass> <pool> <url> <ok|fail>: one connection by that
# user, which must pick <pool> and end (one release) before this returns;
# the transfer must work (ok) or not (fail). Leaves the pick in PICK_*.
through()
{
	local np nr ec=0

	np="$(npick "$3")"
	nr="$(nrel)"
	rm -f "$WORK/out.bin"
	curl -s --max-time 20 --proxy "socks5h://$2@127.0.0.1:$fp" "$4" \
		-o "$WORK/out.bin" || ec=$?
	if [ "$5" = ok ]; then
		[ "$ec" -eq 0 ] || fail "$1: the transfer failed ($ec)"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"$1: the payload was corrupted"
	else
		[ "$ec" -ne 0 ] || fail "$1: the transfer should have failed"
	fi
	[ "$(npick "$3")" -eq $((np + 1)) ] || \
		fail "$1: the connection did not pick pool $3"
	wait_rel "$1" $((nr + 1))
	last_pick "$3"
}

# held_open <tag> <name>: a tunnel by bob, through the least_conn pool,
# held open; sets HELD_<name> to its PID and PICK_* to its pick.
held_open()
{
	local np out="$WORK/held.$loop.$2.out" go="$WORK/go.$loop.$2" pid

	np="$(npick lc)"
	rm -f "$go"
	python3 "$SERVERS_DIR/socks5_held_tunnel.py" "$fp" bob pb \
		localhost "$hp" /payload.bin "$go" >"$out" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	timeout 60 bash -c "until grep -q '^FIRST' '$out' || ! kill -0 $pid 2>/dev/null; do sleep 0.1; done"
	grep -q '^FIRST 20000$' "$out" || {
		sed 's/^/# client: /' "$out" >&2
		fail "$1: the held tunnel did not get through"
	}
	[ "$(npick lc)" -eq $((np + 1)) ] || fail "$1: the tunnel did not pick lc"
	printf -v "HELD_$2" '%s' "$pid"
	last_pick lc
}

# held_close <tag> <pid> <port>: the client of a held tunnel goes; its
# server must have one pair less, and <port> then none.
held_close()
{
	local nr

	nr="$(nrel)"
	kill "$2" 2>/dev/null
	wait "$2" 2>/dev/null
	wait_rel "$1" $((nr + 1))
	[ "$(last_rel "$3")" = 0 ] || \
		fail "$1: server :$3 has $(last_rel "$3") pairs open, want 0"
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

# exit_clean <tag>: the stopped front found every reference given back.
exit_clean()
{
	if grep -q "BUG:" "$log"; then
		grep "BUG:" "$log" | sed 's/^/# gwp: /' >&2
		fail "$1: gwproxy found an accounting bug"
	fi
	grep -q "Upstream pool servers: all connection references dropped" \
		"$log" || {
		tail -n 20 "$log" | sed 's/^/# gwp: /' >&2
		fail "$1: no verdict on the pool servers' references at exit"
	}
}

url="http://localhost:$hp/payload.bin"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	write_acl "$r1" "$r2" "$r3"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	# Round-robin: in turn, across both workers, whatever the counts.
	n1="$(lines r1)"
	n2="$(lines r2)"
	n3="$(lines r3)"
	order=""
	for i in 1 2 3 4 5 6 7 8 9; do
		through "[$loop rr $i]" alice:pa rr "$url" ok
		order="$order$PICK_SRV"
	done
	[ "$order" = 123123123 ] || \
		fail "[$loop] round-robin took the servers in the order $order"
	[ "$(lines r1)" -eq $((n1 + 3)) ] && [ "$(lines r2)" -eq $((n2 + 3)) ] &&
	[ "$(lines r3)" -eq $((n3 + 3)) ] || \
		fail "[$loop] the upstreams saw $(($(lines r1) - n1)), $(($(lines r2) - n2)) and $(($(lines r3) - n3)) connections, want 3 each"

	# least_conn: two held tunnels take two servers...
	held_open "[$loop held a]" a
	pa="$PICK_PORT"
	[ "$PICK_OPEN" = 1 ] || fail "[$loop] held a: its server had $PICK_OPEN open, want 1"
	held_open "[$loop held b]" b
	pb="$PICK_PORT"
	[ "$PICK_OPEN" = 1 ] || fail "[$loop] held b: its server had $PICK_OPEN open, want 1"
	[ "$pa" != "$pb" ] || fail "[$loop] both held tunnels went to server :$pa"
	for p in "$r1" "$r2" "$r3"; do
		[ "$p" != "$pa" ] && [ "$p" != "$pb" ] && idle="$p"
	done

	# ... and new connections go to the third one.
	for i in 1 2 3 4; do
		through "[$loop lc $i]" bob:pb lc "$url" ok
		[ "$PICK_PORT" = "$idle" ] && [ "$PICK_OPEN" = 1 ] || \
			fail "[$loop] lc $i went to :$PICK_PORT ($PICK_OPEN open), want the idle :$idle"
	done

	# A reload rebuilds the pool, in another order: the counts stay.
	write_acl "$r3" "$r2" "$r1"
	gwp_hup "$front" "$log" 2
	grep -q "Failed to reload" "$log" && fail "[$loop] the reload failed"
	for i in 1 2 3 4; do
		through "[$loop reloaded lc $i]" bob:pb lc "$url" ok
		[ "$PICK_PORT" = "$idle" ] && [ "$PICK_OPEN" = 1 ] || \
			fail "[$loop] after the reload, lc $i went to :$PICK_PORT ($PICK_OPEN open), want the idle :$idle"
	done

	# A third held tunnel, through the new pool, fills the idle server.
	held_open "[$loop held c]" c
	[ "$PICK_PORT" = "$idle" ] && [ "$PICK_OPEN" = 1 ] || \
		fail "[$loop] held c went to :$PICK_PORT ($PICK_OPEN open), want :$idle"

	# The tunnels of the old pool give their slots back as they close.
	held_close "[$loop close a]" "$HELD_a" "$pa"
	through "[$loop after a]" bob:pb lc "$url" ok
	[ "$PICK_PORT" = "$pa" ] && [ "$PICK_OPEN" = 1 ] || \
		fail "[$loop] after a closed, lc went to :$PICK_PORT ($PICK_OPEN open), want :$pa"
	held_close "[$loop close b]" "$HELD_b" "$pb"
	held_close "[$loop close c]" "$HELD_c" "$idle"

	# A target the upstream cannot reach.
	through "[$loop target refused]" bob:pb lc \
		"http://127.0.0.1:$tdead/" fail
	[ "$(last_rel "$PICK_PORT")" = 0 ] || \
		fail "[$loop] target refused: :$PICK_PORT kept a pair"

	# An upstream that refuses, one that is not there, one that answers
	# garbage: round-robin over the two servers of the bad pool.
	echo refuse >"$WORK/fault"
	through "[$loop upstream refuse]" carol:pc bad "$url" fail
	[ "$PICK_PORT" = "$rf" ] && [ "$(last_rel "$rf")" = 0 ] || \
		fail "[$loop] upstream refuse: :$PICK_PORT kept a pair"
	through "[$loop upstream dead]" carol:pc bad "$url" fail
	[ "$PICK_PORT" = "$rdead" ] && [ "$(last_rel "$rdead")" = 0 ] || \
		fail "[$loop] upstream dead: :$PICK_PORT kept a pair"
	echo bad_ver >"$WORK/fault"
	through "[$loop upstream garbage]" carol:pc bad "$url" fail
	[ "$PICK_PORT" = "$rf" ] && [ "$(last_rel "$rf")" = 0 ] || \
		fail "[$loop] upstream garbage: :$PICK_PORT kept a pair"

	# Every count is 0 again: equal servers take new pairs in turn.
	seen=""
	for i in 1 2 3; do
		through "[$loop final $i]" bob:pb lc "$url" ok
		[ "$PICK_OPEN" = 1 ] || \
			fail "[$loop] final $i: :$PICK_PORT had $PICK_OPEN open, want 1"
		case " $seen " in
		*" $PICK_PORT "*) fail "[$loop] final $i: :$PICK_PORT taken twice" ;;
		esac
		seen="$seen $PICK_PORT"
	done

	stop_front "$front"
	exit_clean "[$loop]"

	# The idle timeout ends a tunnel: its slot goes back too.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --auth-file="$WORK/auth" \
		--acl-file="$acl" --idle-timeout=1
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	held_open "[$loop idle]" d
	[ "$PICK_OPEN" = 1 ] || fail "[$loop] idle: its server had $PICK_OPEN open, want 1"
	wait_rel "[$loop idle]" 1
	[ "$(last_rel "$PICK_PORT")" = 0 ] || \
		fail "[$loop] idle: :$PICK_PORT kept a pair after the idle timeout"
	kill "$HELD_d" 2>/dev/null
	wait "$HELD_d" 2>/dev/null
	stop_front "$front"
	exit_clean "[$loop idle]"
done

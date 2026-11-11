#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SIGTERM and SIGINT stop the proxy at once, also while a resolver thread is
# inside getaddrinfo() for a name the DNS server does not answer. The stop used
# to join every resolver thread, so the process, its PID file with it, lived on
# until the system resolver gave up (30 s here), and the stop signals were
# blocked meanwhile, so a second SIGTERM or a Ctrl-C did nothing.
#
#   (a) a SIGTERM with a lookup held: the process exits with status 0 well
#       within the resolver's timeout, and the PID file is gone;
#   (b) a second stop signal while the proxy waits for that lookup ends the
#       wait at once, and the exit status is still 0.
#
# Run on both loops. The answer is held back by the DNS server until the test
# is done, so the lookup stays inside getaddrinfo() for as long as needed.
# Controlling the resolver takes a resolv.conf of our own and a port 53, so the
# body runs in a private user+mount+net namespace; no name leaves it.

. "$(dirname "$0")/lib.sh"
require python3
require unshare
require ip

if [ "${1:-}" != "--inner" ]; then
	ns_drop_setup
	$NS_DROP unshare -rmn --map-root-user true 2>/dev/null \
		|| skip "no user+mount+net namespaces (unshare -rmn) available"
	out="$WORK/inner.out"
	setsid $NS_DROP unshare -rmn --map-root-user "$0" --inner "$WORK" \
		</dev/null >"$out" 2>&1 &
	for i in $(seq 1 170); do
		grep -q '^INNER-DONE' "$out" 2>/dev/null && break
		sleep 1
	done
	sed 's/^/# /' "$out" >&2
	grep -q '^INNER-DONE rc=77' "$out" && skip "see the inner run above"
	grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
	pass
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
rc=1

cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	_release_ports
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

# The resolver's own timeout, which the stop must not wait for.
RES_TIMEOUT=30
# What the stop may take instead: a 1 s grace, and the rest of the teardown,
# with room for a loaded machine and a sanitizer build.
STOP_LIMIT=10

ip link set lo up || exit 1

printf 'nameserver 127.0.0.1\noptions timeout:%d attempts:1\n' "$RES_TIMEOUT" \
	>"$WORK/resolv.conf"
mount --bind "$WORK/resolv.conf" /etc/resolv.conf || { rc=77; exit 0; }
# Keep every lookup on the server below, whatever the host's NSS would ask.
if [ -e /etc/nsswitch.conf ]; then
	printf 'hosts: files dns\n' >"$WORK/nsswitch.conf"
	mount --bind "$WORK/nsswitch.conf" /etc/nsswitch.conf || exit 1
fi

names="$WORK/names"
release="$WORK/release"
python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns.out" 2>&1 &
dns_pid=$!
for i in $(seq 1 100); do
	grep -q READY "$WORK/dns.out" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns.out" || { echo "DNS server did not start"; exit 1; }

# A SOCKS5 CONNECT to <name>, held open in the background until the proxy
# closes it; returns once the DNS server has seen the query, so a resolver
# thread is then inside getaddrinfo() for it.
hold_lookup()
{
	local port="$1" name="$2"

	python3 - "$port" "$name" "$names" <<'PY' &
import socket, struct, sys, time

port, name, names = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3]
c = socket.create_connection(("127.0.0.1", port), timeout=60)
c.sendall(b"\x05\x01\x00")
if c.recv(2) != b"\x05\x00":
    sys.exit(1)
c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", 9))
try:
    c.recv(16)
except OSError:
    pass
PY
	for i in $(seq 1 200); do
		grep -qx "$name" "$names" 2>/dev/null && return 0
		sleep 0.05
	done
	echo "the lookup of $name did not reach the DNS server"
	return 1
}

# exited <pid>: the child <pid> has exited (it is a zombie or gone).
exited()
{
	local st

	st="$(sed -n 's/^[0-9]* ([^)]*) \(.\).*/\1/p' "/proc/$1/stat" 2>/dev/null)"
	[ -z "$st" ] || [ "$st" = Z ]
}

# wait_exit <pid> <secs>: wait up to <secs> for the child <pid> to exit and
# leave its exit status in $exit_rc. Returns 1, having killed it, if it did not.
wait_exit()
{
	local pid="$1" end=$(( SECONDS + $2 ))

	until exited "$pid"; do
		if [ "$SECONDS" -ge "$end" ]; then
			kill -KILL "$pid" 2>/dev/null
			wait "$pid" 2>/dev/null
			return 1
		fi
		sleep 0.02
	done
	wait "$pid"
	exit_rc=$?
	return 0
}

# blocked <pid> <sig>: <pid>'s main thread has <sig> blocked. SIGHUP is from
# when it starts tearing down; so are SIGINT and SIGTERM, but those do not show
# while it waits for them in sigtimedwait().
blocked()
{
	local v bit=$(( 1 << ($2 - 1) ))

	v="$(sed -n 's/^SigBlk:[[:space:]]*//p' "/proc/$1/task/$1/status" 2>/dev/null)"
	[ -n "$v" ] && [ $(( 0x$v & bit )) != 0 ]
}

n=0
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# (a) One SIGTERM.
	n=$((n + 1))
	p="$(pick_port)"
	pidf="$WORK/gwp.$loop.pid"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --pid-file="$pidf"
	log="$WORK/gwp.$p.log"
	pid="$GWP_PID"
	hold_lookup "$p" "hold-stop-$n.invalid" || exit 1
	start=$(date +%s%N)
	kill -TERM "$pid"
	if ! wait_exit "$pid" "$STOP_LIMIT"; then
		echo "[$loop] still running ${STOP_LIMIT} s after SIGTERM with a lookup held"
		exit 1
	fi
	ms=$(( ($(date +%s%N) - start) / 1000000 ))
	echo "[$loop] exited ${ms} ms after SIGTERM, status $exit_rc"
	[ "$exit_rc" = 0 ] || { echo "[$loop] exit status $exit_rc"; exit 1; }
	[ ! -e "$pidf" ] || { echo "[$loop] PID file left behind"; exit 1; }
	grep -q 'Not waiting for 1 DNS lookup' "$log" || {
		sed 's/^/# /' "$log"
		echo "[$loop] no line about the lookup left behind"
		exit 1
	}

	# (b) A second stop signal during the wait, a SIGTERM (timeout(1) sends
	# two) or a Ctrl-C. The wait ends on its own after 1 s, so a run where
	# the second signal came too late to be seen says nothing; retry it then.
	for second in TERM INT; do
		ok=0
		for try in 1 2 3; do
			n=$((n + 1))
			p="$(pick_port)"
			gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
				--nr-workers=1
			log="$WORK/gwp.$p.log"
			pid="$GWP_PID"
			hold_lookup "$p" "hold-stop-$n.invalid" || exit 1
			kill -TERM "$pid"
			for i in $(seq 1 500); do
				blocked "$pid" 1 && break
				exited "$pid" && break
				sleep 0.01
			done
			kill -"$second" "$pid" 2>/dev/null
			if ! wait_exit "$pid" "$STOP_LIMIT"; then
				echo "[$loop] still running ${STOP_LIMIT} s after SIGTERM and SIG$second"
				exit 1
			fi
			[ "$exit_rc" = 0 ] || { echo "[$loop] exit status $exit_rc"; exit 1; }
			if grep -q 'Stop signal repeated: not waiting for 1 DNS lookup' "$log"; then
				echo "[$loop] SIGTERM then SIG$second: the wait was cut short"
				ok=1
				break
			fi
			sed 's/^/# /' "$log"
			echo "[$loop] try $try: SIG$second was not taken in time"
		done
		[ "$ok" = 1 ] || { echo "[$loop] SIG$second never ended the wait"; exit 1; }
	done
done

: >"$release"
kill "$dns_pid" 2>/dev/null
wait "$dns_pid" 2>/dev/null
rc=0

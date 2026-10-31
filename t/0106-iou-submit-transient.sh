#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A transient io_uring_submit_and_wait() failure must not stop the io_uring
# worker. The kernel fails io_uring_enter(2) with EAGAIN or ENOMEM when it
# cannot allocate a request right now, and older kernels with EBUSY while
# completions wait in the CQ overflow list. The worker used to log the error
# and return, and a worker that returns stops the whole proxy, so every live
# connection went with it.
#
# strace injects each of those errors into a few of the worker's
# io_uring_enter(2) calls; the proxy must stay up and keep forwarding.

. "$(dirname "$0")/lib.sh"
require python3
require strace
require_io_uring

mkdir -p "$WORK/www"
make_payload "$WORK/www/f" 4096
hp="$(pick_port)"
start_httpd "$hp" "$WORK/www" 1.0

# fetch <proxy port>: GET /f through the plain forwarding proxy, print OK.
fetch()
{
	timeout 20 python3 - "$1" "$WORK/www/f" <<-'PY'
	import socket, sys
	port, path = int(sys.argv[1]), sys.argv[2]
	want = open(path, "rb").read()
	try:
	    c = socket.create_connection(("127.0.0.1", port), timeout=10)
	    c.sendall(b"GET /f HTTP/1.0\r\nHost: x\r\n\r\n")
	    got = b""
	    while True:
	        b = c.recv(65536)
	        if not b:
	            break
	        got += b
	except OSError as e:
	    print("error: %s" % e)
	    sys.exit(0)
	body = got.partition(b"\r\n\r\n")[2]
	print("OK" if body == want else "bad reply (%d bytes)" % len(got))
	PY
}

for err in EAGAIN ENOMEM EBUSY; do
	pp="$(pick_port)"
	log="$WORK/gwp.$err.log"
	slog="$WORK/strace.$err.log"

	# Calls 2-4: the first one is the startup submit, after which the
	# worker sleeps until a client comes.
	strace -f -qq -o "$slog" -e trace=io_uring_enter \
		-e inject=io_uring_enter:error="$err":when=2..4 \
		"$GWPROXY" --event-loop=io_uring --nr-workers=1 \
		--bind="127.0.0.1:$pp" --target="127.0.0.1:$hp" \
		--acl-allow-all --log-level=3 >"$log" 2>&1 &
	st_pid=$!
	_PIDS+=("$st_pid")
	wait_listen "$pp" "$st_pid" || fail "[$err] proxy did not listen"

	# Stop the proxy itself, by its pid, before strace: strace stays
	# behind for as long as its tracee lives.
	gwp_pid=""
	for _ in $(seq 1 50); do
		gwp_pid="$(cat "/proc/$st_pid/task/$st_pid/children" 2>/dev/null)"
		gwp_pid="${gwp_pid%% *}"
		[ -n "$gwp_pid" ] && break
		sleep 0.1
	done
	[ -n "$gwp_pid" ] || fail "[$err] cannot find the traced proxy"
	_PIDS=("$gwp_pid" "${_PIDS[@]}")

	for i in 1 2 3 4 5; do
		got="$(fetch "$pp")"
		if [ "$got" != OK ]; then
			sed 's/^/# gwp: /' "$log" >&2
			fail "[$err] fetch $i: $got"
		fi
	done

	grep -q "INJECTED" "$slog" || skip "strace did not inject $err"
	kill -0 "$gwp_pid" 2>/dev/null || fail "[$err] proxy died"
	grep -q "io_uring_submit_and_wait" "$log" ||
		fail "[$err] the failed submit was not logged"
	kill "$gwp_pid" 2>/dev/null
	wait "$st_pid" 2>/dev/null
done

pass

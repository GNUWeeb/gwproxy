#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# In plain and transparent forwarding, a client accepted while the descriptor
# table is full has no target socket yet: the proxy keeps it and retries the
# target connect every 100 ms. The epoll loop did not watch the client
# meanwhile, so one that reset was noticed only at the connect timeout, or
# never at --connect-timeout=0, and once a descriptor was free again its
# target was dialled for nobody. io_uring watches it.
#
# A client waits for its target socket and resets: within 3 s the proxy is
# back at its idle descriptor count, also with a 10 s connect timeout, and the
# target is not dialled once descriptors are free. A client that sends while
# it waits has its bytes delivered once they are. Both loops.

. "$(dirname "$0")/lib.sh"
require python3

tp="$(pick_port)"
python3 - "$tp" >"$WORK/target.log" 2>&1 <<-'PY' &
	import socket, sys, threading
	ls = socket.socket()
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ls.bind(("127.0.0.1", int(sys.argv[1])))
	ls.listen(64)

	def echo(c):
	    while True:
	        try:
	            b = c.recv(4096)
	        except OSError:
	            break
	        if not b:
	            break
	        c.sendall(b)
	    c.close()

	while True:
	    c, _ = ls.accept()
	    print("accept", flush=True)
	    threading.Thread(target=echo, args=(c,), daemon=True).start()
PY
tpid=$!
_PIDS+=("$tpid")
wait_listen "$tp" "$tpid" || fail "the target did not listen"

loops=(epoll)
have_io_uring && loops+=(io_uring)

run_case()
{
	local loop="$1" ct="$2" action="$3" p out rc

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$tp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout="$ct" \
		--protocol-timeout=600
	out="$(python3 "$SERVERS_DIR/fdwait_client.py" "$p" "$GWP_PID" \
		"$WORK/gwp.$p.log" "$WORK/target.log" "$action")"
	rc=$?
	[ $rc -eq 77 ] && skip "$out"
	diag "$loop --connect-timeout=$ct $action: $out"
	kill -0 "$GWP_PID" 2>/dev/null || fail "$loop: proxy died"
	if [ $rc -ne 0 ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$p.log" | tail -n 30 >&2
		fail "$loop --connect-timeout=$ct $action: $out"
	fi
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

for loop in "${loops[@]}"; do
	run_case "$loop" 0 rst
	run_case "$loop" 10 rst
	run_case "$loop" 0 data
done

pass

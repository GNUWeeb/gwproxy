#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A plain forwarding client that waits for its target socket (the descriptor
# table was full when it was accepted) and half-closes. At --connect-timeout=0
# nothing else bounds the wait, so the manual has --protocol-timeout bound a
# FIN during the connect. The epoll loop did not watch a waiting client and
# never saw the FIN: the pair stayed for as long as the table was full, and
# its target was dialled once it was not. io_uring bounds it.
#
# At --connect-timeout=0 --protocol-timeout=2 the half-closed client is closed
# after about 2 s, its descriptor is returned and the target is not dialled.
# A client that sends and half-closes while it waits gets its bytes back and
# then the end of stream, once descriptors are free. Both loops.

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
	local loop="$1" action="$2" p out rc

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --target="127.0.0.1:$tp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=0 \
		--protocol-timeout=2
	out="$(python3 "$SERVERS_DIR/fdwait_client.py" "$p" "$GWP_PID" \
		"$WORK/gwp.$p.log" "$WORK/target.log" "$action" 2)"
	rc=$?
	[ $rc -eq 77 ] && skip "$out"
	diag "$loop $action: $out"
	kill -0 "$GWP_PID" 2>/dev/null || fail "$loop: proxy died"
	if [ $rc -ne 0 ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$p.log" | tail -n 30 >&2
		fail "$loop $action: $out"
	fi
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

for loop in "${loops[@]}"; do
	run_case "$loop" fin
	run_case "$loop" datafin
done

pass

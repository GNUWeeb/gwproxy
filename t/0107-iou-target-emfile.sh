#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# In plain and transparent forwarding, the io_uring loop creates the target
# socket right after accepting the client. With the descriptor table nearly
# full, the client can take the last free slot and leave none for its target
# socket. The client was then closed at once, which it saw as a reset or an
# empty reply. Running out of descriptors is transient: the client must be
# kept and its connect retried until a descriptor is returned.
#
# Idle clients, each holding a client and a target socket in the proxy, fill
# its descriptor table until one more client gets no echo. That client must
# not have been dropped, and once an idle client leaves it must be served.
# Whether the table runs out at the accept or at the target socket depends on
# the parity of the free descriptors, so this runs with two limits.

. "$(dirname "$0")/lib.sh"
require python3
require_io_uring

soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt 256 ]; then
	skip "harness fd limit ($soft) too low"
fi

# An echo target that takes any number of connections.
python3 -c '
import socket, threading
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(256)
print(s.getsockname()[1], flush=True)
def echo(c):
    while True:
        b = c.recv(4096)
        if not b:
            break
        c.sendall(b)
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
' >"$WORK/echo.port" &
_PIDS+=("$!")
tp=""
for _ in $(seq 1 50); do
	tp="$(head -n 1 "$WORK/echo.port" 2>/dev/null)"
	[ -n "$tp" ] && break
	sleep 0.1
done
[ -n "$tp" ] || fail "echo target did not start"

run_with_limit()
{
	local FDLIMIT="$1" pp gwp_pid out rc

	pp="$(pick_port)"
	( ulimit -n "$FDLIMIT"; exec "$GWPROXY" --event-loop=io_uring \
		--bind="127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--acl-allow-all --nr-workers=1 --connect-timeout=10 \
		--log-level=3 ) >"$WORK/gwp.$FDLIMIT.log" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

	out="$(python3 - "$pp" <<-'PY'
	import socket, sys
	port = int(sys.argv[1])

	def echo(c, timeout):
	    c.settimeout(timeout)
	    try:
	        c.sendall(b"ping")
	        got = b""
	        while len(got) < 4:
	            b = c.recv(4 - len(got))
	            if not b:
	                return b""
	            got += b
	        return got
	    except socket.timeout:
	        return None
	    except ConnectionResetError:
	        return b""

	idle, waiting = [], None
	for _ in range(64):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    rep = echo(c, 0.5)
	    if rep == b"":
	        print("client %d was accepted and dropped" % (len(idle) + 1))
	        sys.exit(3)
	    if rep == b"ping":
	        idle.append(c)
	        continue
	    waiting = c
	    break
	if waiting is None:
	    print("never ran out of descriptors (%d idle clients)" % len(idle))
	    sys.exit(1)

	idle.pop().close()
	waiting.settimeout(5)
	try:
	    got = waiting.recv(4)
	except (socket.timeout, ConnectionResetError) as e:
	    got = repr(e)
	if got != b"ping":
	    print("the waiting client was not served: %r" % got)
	    sys.exit(1)
	print("ok with %d idle clients" % len(idle))
	PY
	)"
	rc=$?
	diag "fd limit $FDLIMIT: $out"
	kill -0 "$gwp_pid" 2>/dev/null || fail "proxy died"
	if [ $rc -ne 0 ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$FDLIMIT.log" | tail -n 20 >&2
		fail "fd limit $FDLIMIT: $out"
	fi
	kill "$gwp_pid" 2>/dev/null
}

for lim in 32 33; do
	run_with_limit "$lim"
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The accept throttle after EMFILE must not be pre-paid. Once accept() runs
# out of descriptors, the epoll worker stops accepting until enough of them
# have been returned (a few pairs' worth), so that it does not bounce
# between EMFILE and rearming on every close. Descriptors closed while
# accept is running must not count towards that: before the fix, every
# failed connect attempt was credited, the credit piled up during normal
# operation, and the first close after the next EMFILE rearmed at once.
#
# Here many SOCKS5 CONNECTs to a closed port first fail in normal operation.
# Then idle clients fill the proxy's descriptor table until one is left
# waiting in the listen backlog. Closing one idle client must not let that
# one in; closing all of them must.
#
# No client may be accepted and then dropped for want of a descriptor: the
# proxy must stop accepting first and leave it in the backlog. Each client
# takes one descriptor, its socket; its protocol timer takes none on either
# event loop. This runs with two limits, so that the table runs out at an
# odd and at an even number of free descriptors.

. "$(dirname "$0")/lib.sh"
require python3

soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt 256 ]; then
	skip "harness fd limit ($soft) too low"
fi

# A port nothing listens on, kept bound for the duration of the test.
python3 -c '
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1], flush=True)
time.sleep(600)' >"$WORK/closed.port" &
_PIDS+=("$!")
cport=""
for _ in $(seq 1 50); do
	cport="$(cat "$WORK/closed.port" 2>/dev/null)"
	[ -n "$cport" ] && break
	sleep 0.1
done
[ -n "$cport" ] || fail "could not reserve a closed port"

run_with_limit()
{
	local FDLIMIT="$1" pp gwp_pid out rc

	pp="$(pick_port)"
	( ulimit -n "$FDLIMIT"; exec "$GWPROXY" --event-loop=epoll --as-socks5=1 \
		--bind="127.0.0.1:$pp" --acl-allow-all --nr-workers=1 \
		--log-level=3 ) >"$WORK/gwp.$FDLIMIT.log" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

	out="$(python3 - "$pp" "$cport" <<-'PY'
	import socket, sys, time
	port, cport = int(sys.argv[1]), int(sys.argv[2])

	def greet(c, timeout):
	    c.settimeout(timeout)
	    try:
	        return c.recv(2) == b"\x05\x00"
	    except socket.timeout:
	        return False

	# Failed connect attempts while accept is running.
	for _ in range(60):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    if not greet(c, 5):
	        print("no greeting reply in normal operation")
	        sys.exit(1)
	    c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + cport.to_bytes(2, "big"))
	    c.settimeout(5)
	    rep = c.recv(16)
	    c.close()
	    if rep[:2] != b"\x05\x05":
	        print("expected REP 0x05 for a refused target, got %s" % rep.hex())
	        sys.exit(1)

	# Fill the descriptor table with idle clients until one is left waiting.
	# A client accepted and then closed reads as a reset when its greeting
	# had arrived and as an end of stream when the proxy got there first.
	idle, waiting = [], None
	for _ in range(64):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    c.settimeout(0.5)
	    try:
	        rep = c.recv(2)
	    except socket.timeout:
	        rep = None
	    except ConnectionResetError:
	        rep = b""
	    if rep == b"":
	        print("client %d was accepted and dropped" % (len(idle) + 1))
	        sys.exit(3)
	    ok = rep == b"\x05\x00"
	    if ok:
	        idle.append(c)
	        continue
	    waiting = c
	    break
	if waiting is None:
	    print("never ran out of descriptors (%d idle clients)" % len(idle))
	    sys.exit(1)

	idle.pop().close()
	if greet(waiting, 1.0):
	    print("accept resumed after a single close (%d idle clients)" % len(idle))
	    sys.exit(2)

	for c in idle:
	    c.close()
	if not greet(waiting, 5.0):
	    print("accept did not resume after every idle client closed")
	    sys.exit(1)
	print("ok with %d idle clients" % (len(idle) + 1))
	PY
	)"
	rc=$?
	diag "fd limit $FDLIMIT: $out"
	kill -0 "$gwp_pid" 2>/dev/null || fail "proxy died"
	case $rc in
	0) ;;
	2) fail "the accept throttle was pre-paid by attempts closed in normal operation" ;;
	3) fail "fd limit $FDLIMIT: $out" ;;
	*) fail "$out" ;;
	esac
	kill "$gwp_pid" 2>/dev/null
}

for lim in 64 65; do
	run_with_limit "$lim"
done

# Plain forwarding creates the target socket at accept time. When the
# table ran out at the target socket, the client was accepted and closed
# at once; it must be kept instead, and connected once descriptors are
# returned. The origin closes a connection once the client has, so that
# the pair goes away.
#
# A client takes two descriptors, its socket and the target socket; its
# connect timer takes none on either event loop. The parity of the free
# descriptors decides whether the table runs out at accept() or at the
# target socket, hence two limits; one of them has to end at the target
# socket. This holds with and without a connect timer: when the epoll loop
# still gave each client a timerfd, the timer always ran out first and the
# target socket was never reached with one.
origin_port=""
python3 -c '
import socket, threading
def serve(c):
    c.sendall(b"R\n")
    while c.recv(4096):
        pass
    c.close()
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(256)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()' >"$WORK/origin.port" &
_PIDS+=("$!")
for _ in $(seq 1 50); do
	origin_port="$(cat "$WORK/origin.port" 2>/dev/null)"
	[ -n "$origin_port" ] && break
	sleep 0.1
done
[ -n "$origin_port" ] || fail "origin did not start"

run_plain()
{
	local ev="$1" ct="$2" lim pp log gwp_pid out hit_target=0

	for lim in 64 65; do
		pp="$(pick_port)"
		log="$WORK/gwp.plain.$ev.$ct.$lim.log"
		( ulimit -n "$lim"; exec "$GWPROXY" --event-loop="$ev" \
			--target="127.0.0.1:$origin_port" --bind="127.0.0.1:$pp" \
			--connect-timeout="$ct" \
			--acl-allow-all --nr-workers=1 --log-level=3 ) >"$log" 2>&1 &
		gwp_pid=$!
		_PIDS+=("$gwp_pid")
		wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

		out="$(python3 - "$pp" <<-'PY'
		import socket, sys
		port = int(sys.argv[1])

		def banner(c, timeout):
		    c.settimeout(timeout)
		    try:
		        return c.recv(2)
		    except socket.timeout:
		        return None
		    except ConnectionResetError:
		        return b""

		# Fill the table with forwarded clients until one is left waiting.
		idle, waiting = [], None
		for _ in range(64):
		    c = socket.create_connection(("127.0.0.1", port), timeout=5)
		    rep = banner(c, 0.5)
		    if rep == b"":
		        print("client %d was accepted and dropped" % (len(idle) + 1))
		        sys.exit(1)
		    if rep == b"R\n":
		        idle.append(c)
		        continue
		    waiting = c
		    break
		if waiting is None:
		    print("never ran out of descriptors (%d clients)" % len(idle))
		    sys.exit(1)

		for c in idle:
		    c.close()
		rep = banner(waiting, 4.0)
		if rep != b"R\n":
		    print("the waiting client was not connected once descriptors were "
		          "returned (%r)" % rep)
		    sys.exit(1)
		print("ok with %d clients" % (len(idle) + 1))
		PY
		)" || fail "[$ev] plain forwarding, connect timeout $ct, fd limit $lim: $out"
		diag "[$ev] plain forwarding, connect timeout $ct, fd limit $lim: $out"
		kill -0 "$gwp_pid" 2>/dev/null || fail "[$ev] proxy died"
		kill "$gwp_pid" 2>/dev/null
		wait "$gwp_pid" 2>/dev/null
		grep -q "retrying the target connect" "$log" && hit_target=1
	done
	[ "$hit_target" = 1 ] || \
		fail "[$ev] connect timeout $ct: no limit ran out at the target socket"
}

run_plain epoll 0
run_plain epoll 10

if grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null; then
	run_plain io_uring 0
	run_plain io_uring 10
else
	diag "gwproxy built without io_uring; skipping that leg"
fi

pass

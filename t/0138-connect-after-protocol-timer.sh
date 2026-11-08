#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The protocol timer bounds the handshake and nothing after it: once the
# client has asked for a target, only the connect timeout applies, whatever
# is left of the protocol timeout. On both event loops:
#
#   longer	  --connect-timeout above --protocol-timeout: a target that
#		  never answers gets REP 0x06 at the connect timeout, not when
#		  the protocol timeout runs out.
#   unlimited	  --connect-timeout=0: the same target is still being waited
#		  for after the protocol timeout has run out.
#   idle	  --idle-timeout below --connect-timeout: a tunnel with a
#		  little traffic early on is closed about one idle timeout
#		  after the traffic stops, not when a leftover timer lets the
#		  idle check run again.
#
# With nothing bounding the connect or the upstream handshake, a client that resets
# must still not leave its pair behind, whether the wait is for a target that never
# answers or an upstream that accepts and says nothing, and whether or not a FIN
# came first. A FIN alone may come from a client that only finished sending, so
# that one is held, but no longer than --protocol-timeout from the FIN on, also
# when it is queued behind more than the proxy can take in; only with
# --protocol-timeout=0 as well is it held without a limit. See gone_cases below.

. "$(dirname "$0")/lib.sh"
require python3

python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh.port" 2>"$WORK/bh.log" &
_PIDS+=("$!")
for _ in $(seq 1 50); do
	bport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$bport" ] && break
	sleep 0.1
done
[ -n "${bport:-}" ] || fail "blackhole listener did not report its port"

PROT=4		# --protocol-timeout where it matters
CONN=8		# --connect-timeout above it
EARLY=1		# seconds into the protocol timeout the client asks

# client <case> <proxy port>: print "ok" or what went wrong.
client()
{
	timeout 60 python3 - "$1" "$2" "$bport" "$PROT" "$CONN" "$EARLY" <<-'PY'
	import socket, struct, sys, threading, time
	case, port, bport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
	PROT, CONN, EARLY = (float(x) for x in sys.argv[4:7])

	def request(dport):
	    c = socket.create_connection(("127.0.0.1", port), timeout=10)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        sys.exit("no greeting reply")
	    time.sleep(EARLY)
	    c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
	              struct.pack(">H", dport))
	    return c, time.monotonic()

	if case == "longer":
	    c, t = request(bport)
	    c.settimeout(CONN + 20)
	    rep = c.recv(10)
	    d = time.monotonic() - t
	    if rep[1:2] != b"\x06":
	        sys.exit("got %r, want REP 0x06" % rep)
	    # The protocol timer would answer PROT - EARLY after the request.
	    if d < CONN - 1:
	        sys.exit("REP 0x06 after %.1f s, want about %.0f" % (d, CONN))
	elif case == "unlimited":
	    c, t = request(bport)
	    c.settimeout(PROT - EARLY + 3)
	    try:
	        sys.exit("got %r after %.1f s, want no reply" %
	                 (c.recv(10), time.monotonic() - t))
	    except socket.timeout:
	        pass
	elif case == "idle":
	    ls = socket.socket()
	    ls.bind(("127.0.0.1", 0))
	    ls.listen(1)
	    def echo():
	        o, _ = ls.accept()
	        while True:
	            d = o.recv(64)
	            if not d:
	                break
	            o.sendall(d)
	    threading.Thread(target=echo, daemon=True).start()
	    c, t = request(ls.getsockname()[1])
	    c.settimeout(10)
	    rep = c.recv(10)
	    if rep[1:2] != b"\x00":
	        sys.exit("CONNECT got %r" % rep)
	    time.sleep(0.5)
	    c.sendall(b"x")
	    if c.recv(1) != b"x":
	        sys.exit("no echo")
	    t = time.monotonic()
	    # A timer left over would hold the check back until --connect-timeout,
	    # 40 s here. The idle timeout is 2 s, checked at a one second grain.
	    c.settimeout(40)
	    try:
	        d = c.recv(1)
	    except ConnectionResetError:
	        d = b""
	    t = time.monotonic() - t
	    if d:
	        sys.exit("unexpected data %r" % d)
	    if t > 15:
	        sys.exit("closed %.1f s after the last byte, idle timeout 2 s" % t)
	print("ok")
	PY
}

# An upstream proxy that accepts, reads and never says anything.
python3 -c '
import socket, threading
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(128)
print(ls.getsockname()[1], flush=True)
def drain(c):
    while c.recv(4096):
        pass
while True:
    threading.Thread(target=drain, args=(ls.accept()[0],), daemon=True).start()
' >"$WORK/up.port" 2>"$WORK/up.log" &
_PIDS+=("$!")
for _ in $(seq 1 50); do
	uport="$(cat "$WORK/up.port" 2>/dev/null)"
	[ -n "$uport" ] && break
	sleep 0.1
done
[ -n "${uport:-}" ] || fail "silent upstream did not report its port"

# gone <how> <front> <proxy port> <proxy pid>: a client asks for a target that
# will not answer, then does <how>. Print "ok" or what went wrong.
gone()
{
	timeout 60 python3 - "$@" "$bport" "$PROT" <<-'PY'
	import os, socket, struct, sys, time
	how, front, port, pid, bport, PROT = sys.argv[1], sys.argv[2], *map(int, sys.argv[3:7])
	# Well below the two minutes the kernel retries a SYN for, which would
	# end the wait for a black hole by itself.
	LIMIT = 40

	def fds():
	    return len(os.listdir("/proc/%d/fd" % pid))

	base = fds()
	c = socket.create_connection(("127.0.0.1", port), timeout=10)
	if front == "socks5":
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        sys.exit("no greeting reply")
	    c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
	              struct.pack(">H", bport))
	if how.startswith("full"):
	    # More than --client-buf-size, so that the proxy cannot read up to the FIN.
	    c.sendall(b"x" * 16384)
	    how = how[4:]
	end = time.monotonic() + 20
	while fds() <= base and time.monotonic() < end:
	    time.sleep(0.05)
	if fds() <= base:
	    sys.exit("the proxy has not taken up the connection")
	time.sleep(0.5)

	if how.startswith("fin"):
	    c.shutdown(socket.SHUT_WR)
	    time.sleep(0.5)
	if how == "finbound":
	    # --protocol-timeout from the FIN on: REP 0x06, if the client can
	    # still read it, and the pair goes.
	    t = time.monotonic()
	    c.settimeout(PROT + 20)
	    try:
	        got = c.recv(10)
	    except ConnectionResetError:
	        got = b""
	    except socket.timeout:
	        sys.exit("no reply nor end %d s after the FIN" % (PROT + 20))
	    if time.monotonic() - t < PROT - 1:
	        sys.exit("ended %.1f s after the FIN, before the protocol "
	                 "timeout" % (time.monotonic() - t))
	    if got and got[:2] != b"\x05\x06":
	        sys.exit("got %r, want REP 0x06" % got)
	    while fds() > base and time.monotonic() - t < LIMIT:
	        time.sleep(0.1)
	    if fds() > base:
	        sys.exit("%d descriptors above idle %d s after the FIN" %
	                 (fds() - base, LIMIT))
	    print("ok")
	    sys.exit(0)
	if how in ("stay", "fin"):
	    # Past what the protocol timer would have allowed.
	    c.settimeout(PROT + 3)
	    try:
	        sys.exit("got %r, want no reply" % c.recv(10))
	    except socket.timeout:
	        pass
	    if fds() <= base:
	        sys.exit("the pair went away while the client waited")
	    print("ok")
	    sys.exit(0)
	c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
	c.close()
	t = time.monotonic()
	while fds() > base and time.monotonic() - t < LIMIT:
	    time.sleep(0.1)
	if fds() > base:
	    sys.exit("%d descriptors above idle %d s after the client left" %
	             (fds() - base, LIMIT))
	print("ok")
	PY
}

# name, how the client behaves, its front-end, and the proxy's other options.
# Without --as-socks5 the target is what --target names, through the upstream
# if any. The port named there is never reached.
up="--upstream-proxy=socks5://127.0.0.1:$uport"
hup="--upstream-proxy=http://127.0.0.1:$uport"
none="--connect-timeout=0 --protocol-timeout=$PROT"
gone_cases()
{
	cat <<-EOF
	up-stay		stay	socks5	$none $up
	up-rst		rst	socks5	$none $up
	up-fin		finbound	socks5	$none $up
	up-fullfin	fullfinbound	socks5	$none $up --client-buf-size=4096
	up-finrst	finrst	socks5	$none $up
	up-fullrst	fullrst	socks5	$none $up --client-buf-size=4096
	up-nolimit	fin	socks5	--connect-timeout=0 --protocol-timeout=0 $up
	hup-rst		rst	socks5	$none $hup
	hole-rst	rst	socks5	$none
	hole-fin	finbound	socks5	$none
	hole-fullfin	fullfinbound	socks5	$none --client-buf-size=4096
	plain-rst	rst	plain	$none $up --target=127.0.0.1:9
	timed-rst	rst	socks5	--connect-timeout=300 --protocol-timeout=$PROT $up
	EOF
}

# All of it at once: most of it is waiting for something to time out.
pids=""
clients=""
names=""
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for case in longer unlimited idle; do
		case "$case" in
		longer)    args="--protocol-timeout=$PROT --connect-timeout=$CONN" ;;
		unlimited) args="--protocol-timeout=$PROT --connect-timeout=0" ;;
		idle)      args="--protocol-timeout=60 --connect-timeout=40 --idle-timeout=2" ;;
		esac
		pp="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 $args
		pids="$pids $GWP_PID"
		client "$case" "$pp" >"$WORK/$loop.$case.out" 2>&1 &
		clients="$clients $!"
		names="$names $loop.$case"
	done

	while read -r name how front args; do
		fe=""
		[ "$front" = socks5 ] && fe="--as-socks5=1"
		pp="$(pick_port)"
		# shellcheck disable=SC2086
		gwp_start "127.0.0.1:$pp" $fe --event-loop="$loop" --nr-workers=1 $args
		pids="$pids $GWP_PID"
		gone "$how" "$front" "$pp" "$GWP_PID" >"$WORK/$loop.$name.out" 2>&1 &
		clients="$clients $!"
		names="$names $loop.$name"
	done <<-EOF
	$(gone_cases)
	EOF
done

for pid in $clients; do
	wait "$pid"
done
for name in $names; do
	got="$(cat "$WORK/$name.out")"
	[ "$got" = ok ] || fail "[$name] $got"
done
for pid in $pids; do
	kill -0 "$pid" 2>/dev/null || fail "proxy $pid died"
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
done

pass

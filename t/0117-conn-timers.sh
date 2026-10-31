#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Many connections in different phases at once, each under its own timeout,
# on one worker: the protocol, connect and idle timeouts must each fire when
# they should, for the connection they belong to, and no sooner. Re-arming a
# timer for the next phase, to a later or to an earlier time, must replace
# its deadline, not add a second one.
#
#   silent	  never sends a greeting: closed at the protocol timeout,
#		  without a reply.
#   idle	  CONNECTs to an echo origin, then sends nothing: closed at
#		  the idle timeout, counted from the CONNECT.
#   busy	  CONNECTs, echoes a byte every half second for longer than the
#		  idle timeout, then stops: open while busy, closed at the idle
#		  timeout after the last byte.
#   blackhole	  CONNECTs to a target that never answers: REP 0x06 at the
#		  connect timeout, which is shorter than the protocol timeout
#		  still running when the request arrives.
#   late	  sends its request just before the protocol timeout: the
#		  connect timer replaces that timer, so the tunnel is up and
#		  stays up until the idle timeout.
#
# Timers take no descriptor of their own on either event loop: no timerfd
# may be open while all of these are.

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

PROT=4		# --protocol-timeout
CONN=1		# --connect-timeout
IDLE=3		# --idle-timeout

run_clients()	# $1=proxy port $2=proxy pid
{
	python3 - "$1" "$2" "$bport" "$PROT" "$CONN" "$IDLE" <<-'PY'
	import os, socket, struct, sys, threading, time
	port, pid, bport = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
	PROT, CONN, IDLE = (float(x) for x in sys.argv[4:7])
	T0 = time.monotonic()
	errors, lock = [], threading.Lock()

	def err(msg):
	    with lock:
	        errors.append(msg)

	def now():
	    return time.monotonic() - T0

	# An echo origin of our own.
	ls = socket.socket()
	ls.bind(("127.0.0.1", 0))
	ls.listen(128)
	eport = ls.getsockname()[1]
	def echo(o):
	    try:
	        while True:
	            d = o.recv(4096)
	            if not d:
	                break
	            o.sendall(d)
	    except OSError:
	        pass
	    o.close()
	def origin():
	    while True:
	        o, _ = ls.accept()
	        threading.Thread(target=echo, args=(o,), daemon=True).start()
	threading.Thread(target=origin, daemon=True).start()

	def request(dport):
	    return b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + \
	        struct.pack(">H", dport)

	def wait_close(c, name, lo, hi):
	    # The proxy must close c between lo and hi seconds from T0.
	    c.settimeout(max(hi - now(), 0.1))
	    try:
	        d = c.recv(64)
	    except socket.timeout:
	        return err("%s: still open at %.1f s (want closed by %.1f)" %
	                   (name, now(), hi))
	    except ConnectionResetError:
	        d = b""
	    t = now()
	    if d:
	        return err("%s: unexpected data %r at %.1f s" % (name, d, t))
	    if t < lo:
	        err("%s: closed at %.1f s, before %.1f" % (name, t, lo))

	def connect(name, dport):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        raise Exception("%s: no greeting reply" % name)
	    c.sendall(request(dport))
	    return c

	def silent(i):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    wait_close(c, "silent%d" % i, PROT - 0.5, PROT + 2)

	def idle(i):
	    c = connect("idle%d" % i, eport)
	    rep = c.recv(10)
	    if rep[1:2] != b"\x00":
	        return err("idle%d: CONNECT got %r" % (i, rep))
	    t = now()
	    wait_close(c, "idle%d" % i, t + IDLE - 1.5, t + IDLE + 2)

	def busy(i):
	    c = connect("busy%d" % i, eport)
	    rep = c.recv(10)
	    if rep[1:2] != b"\x00":
	        return err("busy%d: CONNECT got %r" % (i, rep))
	    c.settimeout(2)
	    end = now() + IDLE + 2.5
	    while now() < end:
	        time.sleep(0.5)
	        try:
	            c.sendall(b"x")
	            if c.recv(1) != b"x":
	                return err("busy%d: closed while busy at %.1f s" % (i, now()))
	        except OSError as e:
	            return err("busy%d: %s while busy at %.1f s" % (i, e, now()))
	    t = now()
	    wait_close(c, "busy%d" % i, t + IDLE - 1.5, t + IDLE + 2)

	def blackhole(i):
	    c = connect("blackhole%d" % i, bport)
	    t = now()
	    c.settimeout(PROT + 3)
	    try:
	        rep = c.recv(10)
	    except socket.timeout:
	        return err("blackhole%d: no reply" % i)
	    if rep[1:2] != b"\x06":
	        return err("blackhole%d: got %r, want REP 0x06" % (i, rep))
	    d = now() - t
	    if d < CONN - 0.5 or d > CONN + 1.5:
	        err("blackhole%d: REP 0x06 after %.1f s, want about %.0f" %
	            (i, d, CONN))

	def late(i):
	    c = socket.create_connection(("127.0.0.1", port), timeout=5)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        return err("late%d: no greeting reply" % i)
	    time.sleep(PROT - 0.7)
	    c.sendall(request(eport))
	    rep = c.recv(10)
	    if rep[1:2] != b"\x00":
	        return err("late%d: CONNECT got %r" % (i, rep))
	    t = now()
	    # Past the protocol timeout, the tunnel must still carry data.
	    time.sleep(1.5)
	    try:
	        c.sendall(b"y")
	        if c.recv(1) != b"y":
	            return err("late%d: tunnel closed after the CONNECT" % i)
	    except OSError as e:
	        return err("late%d: %s after the CONNECT" % (i, e))
	    t = now()
	    wait_close(c, "late%d" % i, t + IDLE - 1.5, t + IDLE + 2)

	threads = []
	for f, n in ((silent, 8), (idle, 8), (busy, 8), (blackhole, 4),
	             (late, 4)):
	    for i in range(n):
	        th = threading.Thread(target=f, args=(i,), daemon=True)
	        threads.append(th)
	        th.start()

	# Everything is open now: no timer may hold a descriptor.
	time.sleep(1)
	fds = os.listdir("/proc/%d/fd" % pid)
	tfd = 0
	for fd in fds:
	    try:
	        if "timerfd" in os.readlink("/proc/%d/fd/%s" % (pid, fd)):
	            tfd += 1
	    except OSError:
	        pass
	if tfd:
	    err("%d timerfds open with %d descriptors in all" % (tfd, len(fds)))

	for th in threads:
	    th.join(30)
	print("; ".join(errors) if errors else "ok")
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout="$PROT" \
		--connect-timeout="$CONN" --idle-timeout="$IDLE"
	got="$(run_clients "$pp" "$GWP_PID")"
	[ "$got" = ok ] || fail "[$loop] $got"
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$loop] proxy died"
	kill "$GWP_PID" 2>/dev/null
done

pass

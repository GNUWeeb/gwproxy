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
#
# How the times are taken, so that a loaded host cannot fail the test:
#
#   - Each timeout is measured from a time taken just BEFORE the client's
#     action that starts it (the connect, the request, the last byte sent).
#     The proxy starts its timer no sooner, so however late the client or the
#     proxy runs, a close can only look later than it was, never earlier:
#     the lower bounds hold as they are.
#   - The upper bounds allow for stalls, and only for those measured: one
#     thread watches every socket for its reply or close, and meanwhile sends
#     a pulse byte through the proxy every 0.1 s. A pulse that takes longer
#     than STALL to come back means the proxy did not run (or the kernel or
#     this process did not); a pass of the watch loop that takes longer means
#     this process did not run. A close may be late by the time either was
#     stalled between its start and the moment it was seen, plus SLACK.
#     On an idle host the window is the one the timers promise.
#   - "late" and "busy" depend on the client keeping its own schedule (a
#     request just before the deadline, a byte every half second). An attempt
#     that missed it, or that ran while the proxy stalled, is inconclusive
#     and run again, up to five times.

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
	import os, selectors, socket, struct, sys, threading, time
	port, pid, bport = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
	PROT, CONN, IDLE = (float(x) for x in sys.argv[4:7])
	# A pulse round trip or a pass of the watch loop longer than STALL is a
	# stall; SLACK is what a busy host adds to a deadline short of one.
	STALL, SLACK, TICK, PULSE = 0.2, 0.5, 0.05, 0.1
	# How long past its window a close is waited for before it counts as
	# never coming.
	GIVE_UP = 20
	# How many times "late" and "busy" are tried before a stall in every
	# attempt counts as a failure.
	ATTEMPTS = 5
	now = time.monotonic
	errors, obs, lock = [], [], threading.Lock()
	retries = 0

	def err(msg):
	    with lock:
	        errors.append(msg)

	class Retry(Exception):
	    pass

	class Watcher:
	    """Waits for a reply or a close on any number of sockets, and
	    measures the stalls of the proxy and of this process meanwhile."""

	    def __init__(self, pulse):
	        self.sel = selectors.DefaultSelector()
	        self.lock = threading.Lock()
	        self.queue = []
	        self.stalls = []	# (start, end, "proxy" or "client")
	        self.pulse = pulse
	        self.sent = None	# when the pulse in flight was sent
	        self.last = 0.0
	        self.stop = False
	        pulse.setblocking(False)
	        self.sel.register(pulse, selectors.EVENT_READ, None)

	    def stall(self, a, b, who):
	        with self.lock:
	            self.stalls.append((a, b, who))

	    def lost(self, a, b, who=None):
	        """How long, in all, the proxy or this process was stalled
	        between a and b, counting a pulse still in flight."""
	        with self.lock:
	            iv = [(s, e) for s, e, w in self.stalls
	                  if who is None or w == who]
	            if self.sent is not None and now() - self.sent > STALL:
	                iv.append((self.sent + STALL, now()))
	        iv = sorted((max(s, a), min(e, b)) for s, e in iv
	                    if e > a and s < b)
	        total, end = 0.0, a
	        for s, e in iv:
	            if e > end:
	                total += e - max(s, end)
	                end = e
	        return total

	    def wait(self, c, limit):
	        """The first bytes c receives ("" for a close) and when they
	        were seen; None for the bytes if nothing came within limit."""
	        w = [threading.Event(), None, None]
	        c.setblocking(False)
	        with self.lock:
	            self.queue.append((c, w))
	        if not w[0].wait(max(limit, 0.1)):
	            return None, now()
	        return w[1], w[2]

	    def run(self):
	        prev = now()
	        while not self.stop:
	            ready = self.sel.select(TICK)
	            t = now()
	            if t - prev > TICK + STALL:
	                self.stall(prev + TICK + STALL, t, "client")
	            prev = t
	            for key, _ in ready:
	                c, w = key.fileobj, key.data
	                try:
	                    d = c.recv(64)
	                except BlockingIOError:
	                    continue
	                except OSError:
	                    d = b""
	                if w is None:
	                    if not d:
	                        # Idle for the whole idle timeout: this
	                        # process stalled that long. Start another.
	                        self.sel.unregister(c)
	                        self.stall(self.sent or self.last, now(), "client")
	                        self.pulse = pulse_conn()
	                        self.pulse.setblocking(False)
	                        self.sel.register(self.pulse,
	                                          selectors.EVENT_READ, None)
	                        self.sent = None
	                    elif self.sent is not None:
	                        if t - self.sent > STALL:
	                            self.stall(self.sent + STALL, t, "proxy")
	                        self.sent = None
	                    continue
	                self.sel.unregister(c)
	                w[1], w[2] = d, t
	                w[0].set()
	            with self.lock:
	                q, self.queue = self.queue, []
	            for c, w in q:
	                self.sel.register(c, selectors.EVENT_READ, w)
	            if self.sent is None and t - self.last >= PULSE:
	                try:
	                    self.pulse.send(b"p")
	                    self.sent = self.last = t
	                except OSError:
	                    pass

	T0 = now()

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

	def connect(name, dport):
	    """Greet, ask for dport, and return the socket and when the
	    request was about to be sent."""
	    c = socket.create_connection(("127.0.0.1", port), timeout=10)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        raise Exception("%s: no greeting reply" % name)
	    t = now()
	    c.sendall(request(dport))
	    return c, t

	def reply(c, name):
	    rep = c.recv(10)
	    if rep[1:2] != b"\x00":
	        raise Exception("%s: CONNECT got %r" % (name, rep))

	def wait_close(c, name, ref, lo, hi):
	    # The proxy must close c between lo and hi seconds after ref, which
	    # was taken before whatever started the timer.
	    d, t = W.wait(c, hi + GIVE_UP - (now() - ref))
	    if d is None:
	        return err("%s: still open %.1f s after its start (want closed by %.1f)" %
	                   (name, t - ref, hi))
	    if d:
	        return err("%s: unexpected data %r at %.1f s" % (name, d, t - ref))
	    with lock:
	        obs.append((name, ref, t, lo, hi))

	def pulse_conn():
	    c, _ = connect("pulse", eport)
	    reply(c, "pulse")
	    return c

	def silent(i):
	    t = now()
	    c = socket.create_connection(("127.0.0.1", port), timeout=10)
	    wait_close(c, "silent%d" % i, t, PROT - 0.5, PROT + 2)

	def idle(i):
	    c, t = connect("idle%d" % i, eport)
	    reply(c, "idle%d" % i)
	    wait_close(c, "idle%d" % i, t, IDLE - 1.5, IDLE + 2)

	def busy_once(i):
	    name = "busy%d" % i
	    c, t = connect(name, eport)
	    reply(c, name)
	    end = now() + IDLE + 2.5
	    while now() < end:
	        time.sleep(0.5)
	        t1 = now()
	        try:
	            c.sendall(b"x")
	            if c.recv(1) != b"x":
	                raise OSError("closed")
	        except OSError as e:
	            # Legitimate if this client let the connection go idle, or
	            # if the proxy stalled past its deadline.
	            if t1 - t > IDLE - 0.5 or W.lost(t, now()) > STALL:
	                raise Retry()
	            return err("%s: %s while busy at %.1f s" % (name, e, now() - T0))
	        t = t1
	    wait_close(c, name, t, IDLE - 1.5, IDLE + 2)

	def blackhole(i):
	    name = "blackhole%d" % i
	    c, t = connect(name, bport)
	    d, t1 = W.wait(c, PROT + 3 + GIVE_UP)
	    if d is None:
	        return err("%s: no reply" % name)
	    if d[1:2] != b"\x06":
	        return err("%s: got %r, want REP 0x06" % (name, d))
	    with lock:
	        obs.append((name, t, t1, CONN - 0.5, CONN + 1.5))

	def late_once(i):
	    name = "late%d" % i
	    t0 = now()
	    c = socket.create_connection(("127.0.0.1", port), timeout=10)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        return err("%s: no greeting reply" % name)
	    time.sleep(PROT - 0.7)
	    t = now()
	    c.sendall(request(eport))
	    t1 = now()
	    try:
	        rep = c.recv(10)
	    except OSError:
	        rep = b""
	    if rep[1:2] != b"\x00":
	        # The request had to beat the protocol timeout to test anything.
	        if t1 - t0 > PROT - 0.3 or W.lost(t0, now()) > STALL:
	            raise Retry()
	        return err("%s: CONNECT got %r" % (name, rep))
	    # Past the protocol timeout, the tunnel must still carry data.
	    time.sleep(1.5)
	    t2 = now()
	    try:
	        c.sendall(b"y")
	        if c.recv(1) != b"y":
	            raise OSError("closed")
	    except OSError as e:
	        if now() - t > IDLE - 0.5 or W.lost(t, now()) > STALL:
	            raise Retry()
	        return err("%s: %s after the CONNECT" % (name, e))
	    wait_close(c, name, t2, IDLE - 1.5, IDLE + 2)

	def again(f):
	    def run(i):
	        global retries
	        for _ in range(ATTEMPTS):
	            try:
	                return f(i)
	            except Retry:
	                with lock:
	                    retries += 1
	        err("%s%d: %d attempts in a row missed their schedule" %
	            (run.__name__, i, ATTEMPTS))
	    run.__name__ = f.__name__.replace("_once", "")
	    return run

	def guard(f, i):
	    try:
	        f(i)
	    except Exception as e:
	        err("%s%d: %s" % (f.__name__, i, e))

	W = Watcher(pulse_conn())
	threading.Thread(target=W.run, daemon=True).start()

	threads = []
	for f, n in ((silent, 8), (idle, 8), (again(busy_once), 8),
	             (blackhole, 4), (again(late_once), 4)):
	    for i in range(n):
	        th = threading.Thread(target=guard, args=(f, i), daemon=True)
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
	    th.join(300)
	    if th.is_alive():
	        err("a client thread did not finish")
	time.sleep(0.5)		# for the last pulse to land
	W.stop = True

	worst = -GIVE_UP
	for name, ref, t, lo, hi in obs:
	    d = t - ref
	    if d < lo:
	        err("%s: closed %.2f s after its start, before %.1f" % (name, d, lo))
	        continue
	    lost = W.lost(ref, t)
	    if d > hi + SLACK + lost:
	        err("%s: closed %.2f s after its start, want by %.1f (+%.1f slack, +%.2f stalled)" %
	            (name, d, hi, SLACK, lost))
	    worst = max(worst, d - hi)
	end = now()
	sys.stderr.write("# %.1f s; latest close %+.2f s from its window's end; %d attempts again; stalled %.2f s (proxy or kernel) and %.2f s (client)\n" %
	                 (end - T0, worst, retries, W.lost(T0, end, "proxy"),
	                  W.lost(T0, end, "client")))
	print("; ".join(errors) if errors else "ok")
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout="$PROT" \
		--connect-timeout="$CONN" --idle-timeout="$IDLE"
	got="$(run_clients "$pp" "$GWP_PID" 2>"$WORK/clients.$loop.err")"
	sed "s/^/# [$loop] /" "$WORK/clients.$loop.err" >&2
	[ "$got" = ok ] || fail "[$loop] $got"
	kill -0 "$GWP_PID" 2>/dev/null || fail "[$loop] proxy died"
	kill "$GWP_PID" 2>/dev/null
done

pass

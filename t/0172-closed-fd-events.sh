#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A descriptor closed without EPOLL_CTL_DEL stays in the epoll set for as
# long as anything else holds a reference to its file: epoll drops an item
# when the file goes, not at close(). Another process reading
# /proc/<pid>/fd (ls -l, ss -p, lsof) holds one for a moment, and any
# event that comes in meanwhile reaches the pair that the closed socket
# belonged to, which may already have been freed.
#
# fd_holder.py makes that moment last: it runs the proxy as its child and
# keeps a duplicate of every socket the proxy opens. Then, on every
# available event loop:
#
#  - Clients connect and hang up, the proxy closes their pairs, and the
#    clients' FINs make the closed sockets readable for good.
#  - A pool server answers 407 a moment after the CONNECT and then hangs
#    up; the proxy closes that socket and retries the pair on the other
#    server, whose tunnel then sits idle before it is used and closed.
#  - On epoll, with --raw-dns: the DNS server answers twice, so the second
#    answer reaches the query's socket after the lookup closed it.
#
# No event may come back for any closed socket: with a sanitizer the stale
# event is a use-after-free, without one the worker spins on it, or
# crashes. Last, the race as it happens: many pairs opened and closed
# while a loop lists /proc/<pid>/fd.
#
# The io_uring loop has no epoll set: each request holds its own reference
# to the file and to the pair, so it should pass either way.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
make_payload "$WORK/p.bin" 4096
start_httpd "$hp" "$WORK" "1.0"

has_opt() { "$GWPROXY" --help 2>&1 | grep -q -- "$1"; }

sanitizer_check()	# <log> <what>
{
	if grep -qE 'Sanitizer|runtime error' "$1"; then
		grep -E -A12 'Sanitizer|runtime error' "$1" | head -40 >&2
		fail "$2: sanitizer report"
	fi
}

# hold_start <name> <gwproxy args...>: run the proxy under fd_holder.py;
# sets HPID (the helper), GPID (the proxy), PP (its port), HLOG (its log)
# and HELD=1, or HELD=0 when pidfd_getfd() is not available.
hold_start()
{
	local name="$1" st
	shift
	PP="$(pick_port)"
	st="$WORK/hold.${name//\//.}.st"
	HLOG="$WORK/gwp.hold.${name//\//.}.log"
	python3 "$SERVERS_DIR/fd_holder.py" "$st" "$HLOG" "$GWPROXY" \
		--bind="127.0.0.1:$PP" --nr-workers=1 "$@" &
	HPID=$!
	_PIDS+=("$HPID")
	if ! wait_listen "$PP" "$HPID"; then
		sed 's/^/# gwp: /' "$HLOG" >&2
		fail "[$name] the proxy did not listen on $PP"
	fi
	# Not just the first state: the helper writes one before the proxy
	# has opened any socket ("HELD 0"), and only learns at the first one
	# whether pidfd_getfd() is allowed. Wait for its verdict on the
	# listener, which is open by now.
	timeout 20 bash -c "until grep -qE 'NOGETFD|HELD [1-9]' '$st' 2>/dev/null; do sleep 0.05; done" ||
		fail "[$name] fd_holder.py did not take the listener ($(cat "$st" 2>/dev/null))"
	GPID="$(awk '{print $2}' "$st")"
	HST="$st"
	HELD=1
	if grep -q NOGETFD "$st"; then
		diag "[$name] pidfd_getfd() unavailable ($(cat "$st")), part skipped"
		HELD=0
	fi
}

# hold_check <name> <rc> <out>: judge a part's client, then stop the proxy.
hold_check()
{
	local name="$1" rc="$2" out="$3" ec

	diag "[$name] $out"
	sanitizer_check "$HLOG" "[$name]"
	if ! kill -0 "$GPID" 2>/dev/null; then
		wait "$HPID"
		fail "[$name] the proxy died (status $?): $out"
	fi
	case $rc in
	0) ;;
	2) fail "[$name] the worker spun on events of closed sockets: $out" ;;
	*) fail "[$name] $out" ;;
	esac
	r="$(python3 "$SERVERS_DIR/socks5_probe.py" "$PP" "$hp")"
	[ "$r" = "REP=0x00" ] || fail "[$name] SOCKS5 CONNECT afterwards: $r"
	kill -TERM "$GPID"
	timeout 30 bash -c "while kill -0 $GPID 2>/dev/null; do sleep 0.05; done" ||
		fail "[$name] the proxy did not exit on SIGTERM"
	wait "$HPID"
	ec=$?
	sanitizer_check "$HLOG" "[$name]"
	[ "$ec" = 0 ] || { tail -20 "$HLOG" >&2; fail "[$name] exit status $ec"; }
}

# The client of the pool and DNS parts: a SOCKS5 tunnel to <dst>:<hp>, idle
# for a second, then used and closed; the proxy must stay idle meanwhile
# and after. Exit 2 when it spun.
cat >"$WORK/tunnel.py" <<'PY'
import os, socket, struct, sys, time

port, pid, log, dst, dport = (int(sys.argv[1]), sys.argv[2], sys.argv[3],
                              sys.argv[4], int(sys.argv[5]))
hz = os.sysconf("SC_CLK_TCK")
idle = 1.0

def ticks():
    try:
        with open("/proc/%s/stat" % pid) as f:
            s = f.read().rsplit(")", 1)[1].split()
    except OSError:
        print("the proxy is gone")
        sys.exit(1)
    return int(s[11]) + int(s[12])     # utime + stime

def closed():
    with open(log, errors="replace") as f:
        return f.read().count("Closing connection pair")

def spun(what):
    a = ticks()
    time.sleep(idle)
    used = ticks() - a
    limit = int(idle * hz / 4)
    if used > limit:
        print("%d ticks while idle %s (limit %d, %d Hz)" % (used, what, limit, hz))
        sys.exit(2)
    return used

before = closed()
c = socket.create_connection(("127.0.0.1", port), timeout=20)
c.sendall(b"\x05\x01\x00")
if c.recv(2) != b"\x05\x00":
    print("greeting refused")
    sys.exit(1)
try:
    req = b"\x01" + socket.inet_aton(dst)
except OSError:
    req = b"\x03" + bytes([len(dst)]) + dst.encode()
c.sendall(b"\x05\x01\x00" + req + struct.pack("!H", dport))
rep = c.recv(10)
if len(rep) < 2 or rep[1] != 0:
    print("CONNECT failed: %r" % rep)
    sys.exit(1)
time.sleep(0.8)         # whatever comes late has come by now
u1 = spun("with the tunnel open")
c.sendall(b"GET /p.bin HTTP/1.0\r\nHost: x\r\n\r\n")
got = b""
while True:
    d = c.recv(65536)
    if not d:
        break
    got += d
c.close()
if not got.startswith(b"HTTP/1.0 200") or len(got) <= 4096:
    print("bad reply through the tunnel: %r" % got[:40])
    sys.exit(1)
end = time.monotonic() + 20
while closed() <= before and time.monotonic() < end:
    time.sleep(0.02)
if closed() <= before:
    print("the pair was not closed")
    sys.exit(1)
time.sleep(0.2)
u2 = spun("after the pair closed")
print("%d and %d ticks while idle" % (u1, u2))
PY

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# Clients that hang up.
	hold_start "$loop/hangup" --log-level=3 --acl-allow-all --as-socks5=1 \
		--event-loop="$loop"
	if [ "$HELD" = 1 ]; then
		out="$(python3 - "$PP" "$GPID" "$HST" "$HLOG" <<-'PY'
		import os, socket, sys, time

		port, pid, st, log = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
		hz = os.sysconf("SC_CLK_TCK")
		n, idle = 16, 1.0

		def held():
		    with open(st) as f:
		        w = f.read().split()
		    return int(w[3]) if len(w) > 3 and w[2] == "HELD" else -1

		def closed():
		    with open(log, errors="replace") as f:
		        return f.read().count("Closing connection pair")

		def ticks():
		    try:
		        with open("/proc/%s/stat" % pid) as f:
		            s = f.read().rsplit(")", 1)[1].split()
		    except OSError:
		        print("the proxy is gone")
		        sys.exit(1)
		    return int(s[11]) + int(s[12])     # utime + stime

		def wait(cond, secs):
		    end = time.monotonic() + secs
		    while time.monotonic() < end:
		        if cond():
		            return True
		        time.sleep(0.02)
		    return False

		base = held()		# the listener, held since hold_start
		conns = []
		for _ in range(n):
		    c = socket.create_connection(("127.0.0.1", port), timeout=10)
		    conns.append(c)
		if not wait(lambda: held() >= base + n, 20):
		    print("only %d of %d sockets held" % (held() - base, n))
		    sys.exit(1)
		for c in conns:
		    c.close()
		if not wait(lambda: closed() >= n, 20):
		    print("only %d of %d pairs closed" % (closed(), n))
		    sys.exit(1)
		time.sleep(0.2)
		a = ticks()
		time.sleep(idle)
		used = ticks() - a
		limit = int(idle * hz / 4)
		print("%d ticks while idle (limit %d, %d Hz)" % (used, limit, hz))
		sys.exit(2 if used > limit else 0)
		PY
		)"
		hold_check "$loop/hangup" $? "$out"
	else
		hold_check "$loop/hangup" 0 "skipped"
	fi

	# A pool server that answers 407 late and then hangs up.
	if has_opt --upstream-proxy; then
		up407="$(pick_port)"
		python3 - "$up407" >"$WORK/up407.$loop.log" 2>&1 <<-'PY' &
		import socket, sys, threading, time

		ls = socket.socket()
		ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		ls.bind(("127.0.0.1", int(sys.argv[1])))
		ls.listen(16)

		def serve(c):
		    buf = b""
		    while b"\r\n\r\n" not in buf:
		        d = c.recv(4096)
		        if not d:
		            break
		        buf += d
		    time.sleep(0.3)
		    c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
		              b"Proxy-Authenticate: Basic realm=\"x\"\r\n"
		              b"Content-Length: 0\r\n\r\n")
		    time.sleep(0.3)
		    c.close()

		while True:
		    c, _ = ls.accept()
		    threading.Thread(target=serve, args=(c,), daemon=True).start()
		PY
		_PIDS+=("$!")
		wait_listen "$up407" "$!" || fail "the 407 upstream did not listen"
		rec="$(pick_port)"
		python3 "$SERVERS_DIR/recording_proxy.py" http 127.0.0.1 "$rec" \
			"$WORK/rec.$loop.log" >"$WORK/rec.$loop.err" 2>&1 &
		_PIDS+=("$!")
		wait_listen "$rec" "$!" || fail "the recording upstream did not listen"
		{
			echo 'upstream p {'
			echo "	server http://127.0.0.1:$up407;"
			echo "	server http://127.0.0.1:$rec;"
			echo '}'
			echo '-A OUTPUT -j UPSTREAM --to p --accept'
		} >"$WORK/pool.$loop.acl"
		hold_start "$loop/redial" --log-level=4 --as-socks5=1 \
			--event-loop="$loop" --acl-file="$WORK/pool.$loop.acl"
		if [ "$HELD" = 1 ]; then
			rc=0
			for _ in 1 2; do
				out="$(python3 "$WORK/tunnel.py" "$PP" "$GPID" "$HLOG" 127.0.0.1 "$hp")"
				rc=$?
				[ "$rc" = 0 ] || break
				grep -q "Upstream retry for idx=" "$HLOG" && break
			done
			[ "$rc" != 0 ] || grep -q "Upstream retry for idx=" "$HLOG" ||
				fail "[$loop/redial] no pair was retried on the other server"
			hold_check "$loop/redial" "$rc" "$out"
		else
			hold_check "$loop/redial" 0 "skipped"
		fi
	fi

	# A DNS server that answers twice (raw DNS is epoll only).
	if [ "$loop" = epoll ] && has_opt --raw-dns; then
		dp="$(pick_port)"
		python3 - "$dp" >"$WORK/dns.log" 2>&1 <<-'PY' &
		import socket, struct, sys, time

		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(("127.0.0.1", int(sys.argv[1])))
		print("ready", flush=True)
		while True:
		    q, peer = s.recvfrom(2048)
		    if len(q) < 12:
		        continue
		    off = 12
		    while off < len(q) and q[off]:
		        off += q[off] + 1
		    question = q[12:off + 5]
		    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
		    resp = q[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr
		    time.sleep(0.3)
		    s.sendto(resp, peer)
		    time.sleep(0.3)
		    s.sendto(resp, peer)
		PY
		_PIDS+=("$!")
		timeout 10 bash -c "until grep -q ready '$WORK/dns.log'; do sleep 0.05; done" ||
			fail "the DNS server did not start"
		hold_start "$loop/dns" --log-level=3 --acl-allow-all --as-socks5=1 \
			--event-loop="$loop" --raw-dns=1 --dns-server="127.0.0.1:$dp"
		if [ "$HELD" = 1 ]; then
			out="$(python3 "$WORK/tunnel.py" "$PP" "$GPID" "$HLOG" q.example "$hp")"
			hold_check "$loop/dns" $? "$out"
		else
			hold_check "$loop/dns" 0 "skipped"
		fi
	fi

	# Pairs coming and going while /proc/<pid>/fd is read.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$hp" \
		--event-loop="$loop" --nr-workers=2 --log-level=1
	log="$WORK/gwp.$pp.log"
	gp=$GWP_PID
	(
		while kill -0 "$gp" 2>/dev/null && [ ! -e "$WORK/stop" ]; do
			ls -l "/proc/$gp/fd/" >/dev/null 2>&1
		done
	) &
	scan=$!
	_PIDS+=("$scan")
	out="$(python3 - "$pp" <<-'PY'
	import socket, sys, threading, time

	port = int(sys.argv[1])
	end = time.monotonic() + 4
	ok, bad = [0], [0]
	req = b"GET /p.bin HTTP/1.0\r\nHost: x\r\n\r\n"

	def run():
	    while time.monotonic() < end:
	        try:
	            c = socket.create_connection(("127.0.0.1", port), timeout=10)
	            c.sendall(req)
	            got = b""
	            while True:
	                d = c.recv(65536)
	                if not d:
	                    break
	                got += d
	            c.close()
	            if got.startswith(b"HTTP/1.0 200") and len(got) > 4096:
	                ok[0] += 1
	            else:
	                bad[0] += 1
	        except OSError:
	            bad[0] += 1

	ts = [threading.Thread(target=run) for _ in range(8)]
	for t in ts:
	    t.start()
	for t in ts:
	    t.join()
	print("%d pairs, %d failed" % (ok[0] + bad[0], bad[0]))
	sys.exit(1 if bad[0] or not ok[0] else 0)
	PY
	)"
	rc=$?
	touch "$WORK/stop"
	wait "$scan"
	rm -f "$WORK/stop"
	diag "[$loop] /proc scan: $out"
	sanitizer_check "$log" "[$loop] /proc scan"
	kill -0 "$gp" 2>/dev/null || fail "[$loop] the proxy died under the /proc scan"
	[ "$rc" = 0 ] || fail "[$loop] /proc scan: $out"
	kill -TERM "$gp"
	wait "$gp"
	ec=$?
	sanitizer_check "$log" "[$loop] /proc scan"
	[ "$ec" = 0 ] || { tail -20 "$log" >&2; fail "[$loop] exit status $ec after the /proc scan"; }
done

pass

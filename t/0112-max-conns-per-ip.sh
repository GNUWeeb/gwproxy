#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --max-conns-per-ip: a client holding the maximum number of connections has
# the next one closed right after accept, with a log line; closing one of its
# connections, by the client or by a timeout, makes room for exactly one
# more, and once all are closed the count is back to zero. Spread over
# several workers, so the count must be shared between them. Checked for an
# IPv4 client and for an IPv6 one (counted by its /64), for SOCKS5 and plain
# forwarding, on every event loop; without the option nothing is refused.

. "$(dirname "$0")/lib.sh"
require python3

CAP=3

# client <host> <port> <mode> <scenario> <cap>: prints "ok" or what went
# wrong. <mode> is socks5, or fwd for plain forwarding to fwd_echo().
client() {
	python3 - "$@" <<'PY'
import socket, sys, time
host, port, mode, scen, cap = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])

def conn():
    return socket.create_connection((host, port), timeout=3)

def served(c):
    # The proxy talks to it: a SOCKS5 greeting is answered, a forwarded
    # byte comes back from the echo server.
    try:
        if mode == "socks5":
            c.sendall(b"\x05\x01\x00")
            return c.recv(2) == b"\x05\x00"
        c.sendall(b"x")
        return c.recv(1) == b"x"
    except (socket.timeout, OSError):
        return False

def refused(c):
    # Closed by the proxy before it read anything: EOF, no reply.
    c.settimeout(2)
    try:
        return c.recv(16) == b""
    except socket.timeout:
        return False
    except ConnectionResetError:
        return True

def open_served(n):
    out = []
    for i in range(n):
        c = conn()
        if not served(c):
            print("connection %d of %d was not served" % (i + 1, n)); sys.exit(0)
        out.append(c)
    return out

def eventually_served():
    # The proxy frees a closed client's slot when it sees the close, which
    # races with the next connect; give it a moment.
    for _ in range(30):
        c = conn()
        if served(c):
            return c
        c.close()
        time.sleep(0.1)
    print("no connection was served after one was closed"); sys.exit(0)

def eventually_full_set():
    # Likewise for a whole set once all were closed.
    for _ in range(30):
        out = []
        for i in range(cap):
            c = conn()
            if not served(c):
                c.close()
                break
            out.append(c)
        if len(out) == cap:
            return out
        for c in out:
            c.close()
        time.sleep(0.1)
    print("no full set was served after all were closed"); sys.exit(0)

if scen == "cap":
    held = open_served(cap)
    c = conn()
    if not refused(c):
        print("connection %d was not closed at once" % (cap + 1)); sys.exit(0)
    c.close()
    # A burst over the cap: each is refused, but the log stays short.
    for _ in range(20):
        c = conn()
        if not refused(c):
            print("a connection of the burst was not closed"); sys.exit(0)
        c.close()
    # One closed, one more fits, and then no more.
    held.pop().close()
    held.append(eventually_served())
    c = conn()
    if not refused(c):
        print("over the cap again, but not closed"); sys.exit(0)
    c.close()
    # All closed: a full set fits again.
    for c in held:
        c.close()
    held = eventually_full_set()
    c = conn()
    if not refused(c):
        print("over the cap after the reset, but not closed"); sys.exit(0)
    print("ok")
elif scen == "timeout":
    # cap is 1 and --protocol-timeout drops a client that stops halfway
    # through its handshake. Served first, so it surely was counted first.
    c = open_served(1)[0]
    c2 = conn()
    if not refused(c2):
        print("a second connection was not closed at once"); sys.exit(0)
    c.settimeout(4)
    try:
        d = c.recv(16)
    except (socket.timeout, OSError):
        d = None
    if d != b"":
        print("the silent client was not timed out"); sys.exit(0)
    c.close()
    eventually_served()
    print("ok")
elif scen == "off":
    open_served(cap * 3)
    print("ok")
PY
}

# A plain-forwarding target: echoes whatever it gets, for any number of
# connections.
fwd_echo() {
	python3 - "$WORK/fwdport" <<'PY' &
import os, socket, sys, threading
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(64)
open(sys.argv[1] + ".tmp", "w").write(str(s.getsockname()[1]))
os.rename(sys.argv[1] + ".tmp", sys.argv[1])
def echo(c):
    while True:
        d = c.recv(4096)
        if not d:
            break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
PY
	_PIDS+=("$!")
	for _ in $(seq 1 50); do
		[ -s "$WORK/fwdport" ] && return 0
		sleep 0.1
	done
	fail "the forwarding echo server did not start"
}

have_ipv6=0
python3 -c 'import socket; s = socket.socket(socket.AF_INET6); s.bind(("::1", 0))' \
	2>/dev/null && have_ipv6=1

fwd_echo
fport="$(cat "$WORK/fwdport")"

# run <loop> <host> <bind> <mode> <scenario> <cap> [gwproxy args...]
run() {
	local loop="$1" host="$2" bind="$3" mode="$4" scen="$5" cap="$6"
	local p got n t0 t1 span
	shift 6

	p="$(pick_port)"
	if [ "$mode" = socks5 ]; then
		set -- --as-socks5=1 "$@"
	else
		set -- --target="127.0.0.1:$fport" "$@"
	fi
	gwp_start "$bind:$p" --event-loop="$loop" --nr-workers=4 "$@"
	got="$(client "$host" "$p" "$mode" "$scen" "$cap")"
	[ "$got" = ok ] || fail "[$loop $host $mode $scen] $got"

	n="$(grep -c 'Refused client' "$WORK/gwp.$p.log")"
	if [ "$scen" = off ]; then
		[ "$n" = 0 ] || fail "[$loop $host $mode off] refused a client without a cap"
	else
		[ "$n" -ge 1 ] || fail "[$loop $host $mode $scen] the refusal was not logged"
		grep -q "Refused client $host" "$WORK/gwp.$p.log" || \
		grep -q "Refused client \[$host\]" "$WORK/gwp.$p.log" || \
			fail "[$loop $host $mode $scen] the log line does not name $host"
		# At most once a second: n lines take n - 1 seconds, give or
		# take one for the log's clock against the limiter's. Once all
		# of the client's connections close, its count and its log
		# limit start over, so the refusal after that reset is logged
		# at once: leave its line out.
		grep 'Refused client' "$WORK/gwp.$p.log" >"$WORK/refused.$p"
		if [ "$scen" = cap ]; then
			head -n -1 "$WORK/refused.$p" >"$WORK/refused.$p.rate"
			mv "$WORK/refused.$p.rate" "$WORK/refused.$p"
			n=$((n - 1))
		fi
		t0="$(head -n1 "$WORK/refused.$p" | cut -c2-20)"
		t1="$(tail -n1 "$WORK/refused.$p" | cut -c2-20)"
		span=$(( $(date -d "$t1" +%s) - $(date -d "$t0" +%s) ))
		[ "$n" -le $((span + 2)) ] || \
			fail "[$loop $host $mode $scen] $n refusals logged in $span s"
	fi
	kill "$GWP_PID" 2>/dev/null
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	run "$loop" 127.0.0.1 127.0.0.1 socks5 cap "$CAP" --max-conns-per-ip="$CAP"
	run "$loop" 127.0.0.1 127.0.0.1 fwd cap "$CAP" --max-conns-per-ip="$CAP"
	run "$loop" 127.0.0.1 127.0.0.1 socks5 timeout 1 --max-conns-per-ip=1 \
		--protocol-timeout=1
	run "$loop" 127.0.0.1 127.0.0.1 socks5 off "$CAP"
	[ "$have_ipv6" = 1 ] && \
		run "$loop" ::1 '[::1]' socks5 cap "$CAP" --max-conns-per-ip="$CAP"
done

pass

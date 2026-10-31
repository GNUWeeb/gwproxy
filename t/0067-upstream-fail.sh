#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An upstream proxy (-x) that fails must end the client connection cleanly,
# and nothing of the upstream handshake may reach the client:
#
#   (1) plain forwarding through an upstream that refuses the connection:
#       the client is closed at once, gets no bytes, and the worker does not
#       spin in the meantime (a failed connect leaves EPOLLERR raised on the
#       socket until it is closed); both upstream protocols;
#   (2) an upstream that answers nothing, or part of its reply, and then
#       stalls: when the connect timeout fires, a plain-forwarding client is
#       closed without seeing those bytes, and a SOCKS5 client gets REP 0x06
#       alone, and is then closed;
#   (3) an upstream that refuses the CONNECT: a SOCKS5 client gets REP
#       0x05 alone, not the upstream's reply in front of it, and an HTTP
#       client a 502.
#
# All of it runs on every available event loop, (2) with a SOCKS5 and an
# http:// upstream.

. "$(dirname "$0")/lib.sh"
require python3

# A port nothing listens on: bind it, never listen, and keep it bound so no
# one else can take it while the test runs.
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

# An upstream that misbehaves: "silent" reads the greeting and never answers,
# "stall" (SOCKS5) answers one byte of the method selection and then goes
# quiet, "hstall" (HTTP) the first lines of a CONNECT reply, and "refuse"
# (SOCKS5) accepts the method and answers the CONNECT with REP 0x05.
# Run it in the background: the exec makes the pid that lib.sh kills the
# server itself.
upstream()
{
	exec python3 - "$@" <<-'PY'
	import socket, sys, threading, time
	port, mode = int(sys.argv[1]), sys.argv[2]
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("127.0.0.1", port))
	s.listen(16)
	def h(c):
	    try:
	        c.recv(512)
	        if mode == "silent":
	            pass
	        elif mode == "stall":
	            c.sendall(b"\x05")
	        elif mode == "hstall":
	            c.sendall(b"HTTP/1.1 200 OK\r\nX-Partial: ")
	        else:
	            c.sendall(b"\x05\x00")
	            c.recv(512)
	            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
	        time.sleep(30)
	    except OSError:
	        pass
	while True:
	    c, _ = s.accept()
	    threading.Thread(target=h, args=(c,), daemon=True).start()
	PY
}

stp="$(pick_port)"
upstream "$stp" stall >"$WORK/stall.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$stp" "$!" || fail "stalling upstream did not start on $stp"
slp="$(pick_port)"
upstream "$slp" silent >"$WORK/silent.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$slp" "$!" || fail "silent upstream did not start on $slp"
hsp="$(pick_port)"
upstream "$hsp" hstall >"$WORK/hstall.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$hsp" "$!" || fail "stalling HTTP upstream did not start on $hsp"
rfp="$(pick_port)"
upstream "$rfp" refuse >"$WORK/refuse.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$rfp" "$!" || fail "refusing upstream did not start on $rfp"

# probe <port> <pid> [socks5]: connect, with "socks5" also make a SOCKS5
# CONNECT request, and wait for the proxy to close us. Prints
# "<secs> <ticks> <hex bytes>": the wait, the proxy's CPU ticks over it, and
# everything received after the request ("-" for nothing), or "OPEN" on a
# timeout.
probe()
{
	python3 - "$@" <<-'PY'
	import socket, sys, time
	port, pid = int(sys.argv[1]), sys.argv[2]
	s5 = len(sys.argv) > 3 and sys.argv[3] == "socks5"
	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])
	c = socket.create_connection(("127.0.0.1", port))
	c.settimeout(8)
	t0, k0 = time.monotonic(), ticks()
	got = b""
	if s5:
	    c.sendall(b"\x05\x01\x00")
	    m = c.recv(2)
	    if m != b"\x05\x00":
	        print("0 0 greeting:" + (m.hex() or "-"))
	        sys.exit(0)
	    c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
	try:
	    while True:
	        d = c.recv(4096)
	        if not d:
	            break
	        got += d
	except socket.timeout:
	    print("OPEN")
	    sys.exit(0)
	print("%.2f %d %s" % (time.monotonic() - t0, ticks() - k0, got.hex() or "-"))
	PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scheme in socks5 http; do
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="127.0.0.1:9" \
			--upstream-proxy="$scheme://127.0.0.1:$cport" \
			--event-loop="$loop" --nr-workers=1 --connect-timeout=3
		read -r secs ticks bytes < <(probe "$pp" "$GWP_PID")
		diag "[$loop] refused $scheme upstream: closed after ${secs}s, $ticks ticks, bytes $bytes"
		[ "$secs" != OPEN ] || fail "[$loop] refused $scheme upstream: client left open"
		[ "$bytes" = - ] || \
			fail "[$loop] refused $scheme upstream: client got upstream bytes $bytes"
		awk -v s="$secs" 'BEGIN { exit !(s < 1.5) }' || \
			fail "[$loop] refused $scheme upstream: client closed only after ${secs}s"
		[ "$ticks" -le 20 ] || \
			fail "[$loop] refused $scheme upstream: proxy used $ticks ticks of CPU"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done

	# (2) An upstream that never answers, SOCKS5 client: REP 0x06 at the
	#     connect timeout, and then the connection closes.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 \
		--upstream-proxy="socks5://127.0.0.1:$slp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=1
	read -r secs ticks bytes < <(probe "$pp" "$GWP_PID" socks5)
	diag "[$loop] silent upstream, SOCKS5: closed after ${secs}s, bytes $bytes"
	[ "$secs" != OPEN ] || fail "[$loop] silent upstream (SOCKS5): client left open"
	case "$bytes" in
	0506????????????????) ;;
	*) fail "[$loop] silent upstream (SOCKS5): expected REP 0x06 alone, got $bytes" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	# (2) A stalled upstream, plain forwarding and SOCKS5.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:9" \
		--upstream-proxy="socks5://127.0.0.1:$stp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=1
	read -r secs ticks bytes < <(probe "$pp" "$GWP_PID")
	diag "[$loop] stalled upstream, plain: closed after ${secs}s, bytes $bytes"
	[ "$secs" != OPEN ] || fail "[$loop] stalled upstream: client left open"
	[ "$bytes" = - ] || \
		fail "[$loop] stalled upstream: client got upstream bytes $bytes"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	for up in "socks5://127.0.0.1:$stp" "http://127.0.0.1:$hsp"; do
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --upstream-proxy="$up" \
			--event-loop="$loop" --nr-workers=1 --connect-timeout=1
		read -r secs ticks bytes < <(probe "$pp" "$GWP_PID" socks5)
		diag "[$loop] stalled ${up%%:*} upstream, SOCKS5: closed after ${secs}s, bytes $bytes"
		[ "$secs" != OPEN ] || \
			fail "[$loop] stalled ${up%%:*} upstream (SOCKS5): client left open"
		case "$bytes" in
		0506????????????????) ;;
		*) fail "[$loop] stalled ${up%%:*} upstream (SOCKS5): expected REP 0x06 alone, got $bytes" ;;
		esac
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done

	# (3) An upstream that refuses the CONNECT, SOCKS5 and HTTP clients.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 \
		--upstream-proxy="socks5://127.0.0.1:$rfp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=3
	read -r secs ticks bytes < <(probe "$pp" "$GWP_PID" socks5)
	diag "[$loop] refusing upstream, SOCKS5: closed after ${secs}s, bytes $bytes"
	[ "$secs" != OPEN ] || fail "[$loop] refusing upstream (SOCKS5): client left open"
	case "$bytes" in
	0505????????????????) ;;
	*) fail "[$loop] refusing upstream (SOCKS5): expected REP 0x05 alone, got $bytes" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 \
		--upstream-proxy="socks5://127.0.0.1:$rfp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=3
	st="$(python3 - "$pp" <<-'PY'
	import socket, sys
	c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
	c.sendall(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: x\r\n\r\n")
	r = c.recv(200)
	print(r.split(b"\r\n")[0].decode(errors="replace") if r else "CLOSED")
	PY
	)"
	diag "[$loop] refusing upstream, HTTP: $st"
	case "$st" in
	"HTTP/1."?" 502 "*) ;;
	*) fail "[$loop] refusing upstream (HTTP): expected a 502, got '$st'" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An http:// upstream (-x) whose CONNECT reply header never ends: more than
# the target buffer holds, with no blank line. The rest can never fit, so
# the handshake must fail at once, with no upstream byte reaching the
# client. The epoll loop used to wait for the connect timeout instead,
# with the full buffer's level-triggered EPOLLIN spinning the worker all
# that time. A SOCKS5 client gets REP 0x01 and an HTTP client a 502, right
# away. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

# The upstream: read the CONNECT, answer 200 KiB of a header that never
# ends, then hold the connection open.
up="$(pick_port)"
python3 - "$up" >"$WORK/up.log" 2>&1 <<'PY' &
import socket, sys, threading, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
def h(c):
    try:
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nX: " + b"A" * 200000)
        time.sleep(30)
    except OSError:
        pass
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
_PIDS+=("$!")
wait_listen "$up" "$!" || fail "upstream did not listen"

# ask <port> <socks5|http>: the first reply the client gets, and how long
# it took; "TIMEOUT" when nothing came within 4 s.
ask() {
	python3 - "$1" "$2" <<'PY'
import socket, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
c.settimeout(4)
try:
    if sys.argv[2] == "socks5":
        c.sendall(b"\x05\x01\x00")
        c.recv(2)
        c.sendall(b"\x05\x01\x00\x03\x0bexample.com\x00\x50")
    else:
        c.sendall(b"CONNECT example.com:80 HTTP/1.1\r\nHost: x\r\n\r\n")
    r = c.recv(64)
except socket.timeout:
    print("TIMEOUT")
    sys.exit(0)
except ConnectionResetError:
    r = b""
if not r:
    print("CLOSED")
elif sys.argv[2] == "socks5":
    print("REP=0x%02x" % r[1] if len(r) > 1 else "SHORT")
else:
    print(r.split(b"\r\n")[0].decode(errors="replace"))
PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --connect-timeout=10 \
		--upstream-proxy="http://127.0.0.1:$up"

	for proto in socks5 http; do
		got="$(ask "$p" "$proto")"
		case "$loop:$proto:$got" in
		*:socks5:REP=0x01) ;;
		*:http:"HTTP/1."?" 502 "*) ;;
		*) fail "[$loop] $proto client got '$got' for an endless upstream reply" ;;
		esac
	done
	kill "$GWP_PID" 2>/dev/null
done

pass

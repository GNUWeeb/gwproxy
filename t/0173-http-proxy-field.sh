#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A "Proxy" request field never reaches the origin of a forwarding request: a
# CGI-style origin would make it HTTP_PROXY, which many HTTP libraries take for
# the proxy of their own outgoing requests ("httpoxy"), so the client could
# send the origin's requests through a proxy of its choosing. Check byte for
# byte what the origin gets, with the field in several spellings and repeated,
# in one read and dribbled a byte at a time: every "Proxy" line is gone, the
# fields around it and names that only start like it are passed on, and the
# body behind the header is intact.

. "$(dirname "$0")/lib.sh"
require python3

printf 'user:pass\n' >"$WORK/auth"

op="$(pick_port)"
mkdir -p "$WORK/reqs"
python3 "$SERVERS_DIR/raw_origin.py" "$op" "$WORK/reqs" \
	>"$WORK/raw_origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "raw origin did not listen on $op"

# send <port> <delay> <request-file>: send the request (a byte at a time if
# <delay> is not 0, sleeping <delay> seconds in between), print the status line
# of the reply.
send()
{
	timeout 30 python3 -c '
import socket, sys, time
port, delay, data = int(sys.argv[1]), float(sys.argv[2]), open(sys.argv[3], "rb").read()
s = socket.create_connection(("127.0.0.1", port))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
if delay:
    for i in range(len(data)):
        s.sendall(data[i:i + 1])
        time.sleep(delay)
else:
    s.sendall(data)
s.settimeout(10)
r = b""
try:
    while b"\r\n" not in r:
        c = s.recv(4096)
        if not c:
            break
        r += c
except OSError:
    pass
print(r.split(b"\r\n", 1)[0].decode("latin-1") or "CLOSED")
' "$1" "$2" "$3"
}

printf '%s' \
	"POST http://127.0.0.1:$op/cgi-bin/x?q=1 HTTP/1.1"$'\r\n' \
	$'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n' \
	$'X-Before: 1\r\n' \
	$'Proxy: http://127.0.0.1:1/\r\n' \
	$'Content-Length: 4\r\n' \
	$'PROXY: http://127.0.0.1:2/\r\n' \
	$'Proxy-Foo: f\r\n' \
	$'proxy:\r\n' \
	$'Proxys: s\r\n' \
	$'pRoXy:   http://127.0.0.1:3/  \r\n' \
	$'X-After: 2\r\n' \
	$'\r\n' \
	'body' >"$WORK/fwd.req"
printf '%s' \
	$'POST /cgi-bin/x?q=1 HTTP/1.1\r\n' \
	"Host: 127.0.0.1:$op"$'\r\n' \
	$'X-Before: 1\r\n' \
	$'Content-Length: 4\r\n' \
	$'Proxy-Foo: f\r\n' \
	$'Proxys: s\r\n' \
	$'X-After: 2\r\n' \
	$'Connection: close\r\n' \
	$'\r\n' \
	'body' >"$WORK/fwd.want"

n=0
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --auth-file="$WORK/auth"
	for delay in 0 0.002; do
		got="$(send "$pp" "$delay" "$WORK/fwd.req")"
		[ "$got" = "HTTP/1.1 200 OK" ] ||
			fail "[$loop delay=$delay] forward: got '$got'"
		n=$((n + 1))
		cmp -s "$WORK/reqs/req.$n" "$WORK/fwd.want" || {
			diag "origin got:"; cat -A "$WORK/reqs/req.$n" >&2
			fail "[$loop delay=$delay] forwarded request differs"
		}
	done
	kill "$GWP_PID" 2>/dev/null
done

pass

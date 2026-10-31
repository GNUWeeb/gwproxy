#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The request header is parsed where it arrives, in the client buffer, and the
# forwarded request is rewritten from there. Check byte for byte what reaches
# the origin when the header comes in one read and when it is dribbled a byte
# at a time: merged list fields, dropped hop-by-hop and Connection-listed
# fields, the Host taken from the URI, trimmed values, and the body behind the
# header. A header that cannot fit in the client buffer is answered with 431,
# a CONNECT as much as a forwarding request.

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
	"GET http://127.0.0.1:$op/p?q=1 HTTP/1.1"$'\r\n' \
	$'Host: evil.example.com\r\n' \
	$'Accept: a\r\n' \
	$'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n' \
	$'Connection: keep-alive, X-Drop\r\n' \
	$'X-Drop: 1\r\n' \
	$'Vary: x\r\n' \
	$'accept: b\r\n' \
	$'Content-Length: 4\r\n' \
	$'X-Keep:   spaced value  \t\r\n' \
	$'Vary:\r\n' \
	$'Keep-Alive: 5\n' \
	$'\r\n' \
	'body' >"$WORK/fwd.req"
printf '%s' \
	$'GET /p?q=1 HTTP/1.1\r\n' \
	"Host: 127.0.0.1:$op"$'\r\n' \
	$'Accept: a, b\r\n' \
	$'Vary: x\r\n' \
	$'Content-Length: 4\r\n' \
	$'X-Keep: spaced value\r\n' \
	$'Connection: close\r\n' \
	$'\r\n' \
	'body' >"$WORK/fwd.want"

# A CONNECT of about 600 bytes, too big for a 512-byte client buffer.
pad="$(printf 'a%.0s' $(seq 1 500))"
printf 'CONNECT 127.0.0.1:%s HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nX-Pad: %s\r\n\r\n' \
	"$op" "$pad" >"$WORK/connect-big.req"
printf 'CONNECT 127.0.0.1:%s HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n' \
	"$op" >"$WORK/connect.req"
# Credentials longer than any valid ones, refused like any wrong ones.
printf 'CONNECT 127.0.0.1:%s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n' \
	"$op" "$(printf 'QUFB%.0s' $(seq 1 400))" >"$WORK/connect-longcred.req"

n=0
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

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

		got="$(send "$pp" "$delay" "$WORK/connect.req")"
		[ "$got" = "HTTP/1.1 200 OK" ] ||
			fail "[$loop delay=$delay] CONNECT: got '$got'"
	done
	got="$(send "$pp" 0 "$WORK/connect-longcred.req")"
	case "$got" in
	"HTTP/1.1 407 "*) ;;
	*) fail "[$loop] long credentials: got '$got'" ;;
	esac
	kill "$GWP_PID" 2>/dev/null

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --auth-file="$WORK/auth" --client-buf-size=512
	got="$(send "$pp" 0 "$WORK/connect.req")"
	[ "$got" = "HTTP/1.1 200 OK" ] ||
		fail "[$loop] CONNECT at 512: got '$got'"
	got="$(send "$pp" 0 "$WORK/connect-big.req")"
	case "$got" in
	"HTTP/1.1 431 "*) ;;
	*) fail "[$loop] CONNECT header over the client buffer: got '$got'" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
done

pass

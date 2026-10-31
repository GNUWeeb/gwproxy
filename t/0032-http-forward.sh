#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Forwarding HTTP proxy (absolute-form requests, not CONNECT): curl in plain
# proxy mode sends "GET http://host/path HTTP/1.1" to gwproxy, which rewrites
# it to origin-form, fetches it from the origin and relays the response. Verify
# the payload arrives intact for an IPv4-literal target and a hostname target
# (which makes gwproxy resolve the name), on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# An origin that records the Host header it was sent, for the rewrite check.
op="$(pick_port)"
hlog="$WORK/host.log"
python3 "$SERVERS_DIR/header_origin.py" "$op" "$hlog" Host \
	>"$WORK/header_origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "header origin did not listen on $op"

# About the size of an ordinary browser's cookie jar: too big for a 2 KiB
# client buffer, comfortably inside the 64 KiB default.
bigval="$(printf 'a%.0s' $(seq 1 3000))"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-http=1 --event-loop="$loop" --nr-workers=2
	pp_pid="$GWP_PID"

	# IPv4-literal target. No --proxytunnel: curl issues a plain forward-proxy
	# GET with an absolute-form request-target.
	curl -s --max-time 20 -x "http://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
		|| fail "[$loop] curl via HTTP forward proxy to IPv4 target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$loop] HTTP forward proxy corrupted the payload (ipv4)"

	# Hostname target -> gwproxy resolves "localhost" before connecting.
	curl -s --max-time 20 -x "http://[::1]:$pp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out2.bin" \
		|| fail "[$loop] curl via HTTP forward proxy to hostname target failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out2.bin" \
		"[$loop] HTTP forward proxy corrupted the payload (hostname)"

	# RFC 9112 s3.2.2: the Host forwarded to the origin comes from the URI
	# authority, not from whatever the client sent. Forwarding the client's
	# copy would let it aim us at one host while telling the origin another.
	: >"$hlog"
	printf 'GET http://127.0.0.1:%s/x HTTP/1.1\r\nHost: evil.example.com\r\n\r\n' \
		"$op" | timeout 10 python3 -c '
import socket, sys
s = socket.create_connection(("::1", int(sys.argv[1])))
s.sendall(sys.stdin.buffer.read())
s.settimeout(5)
try:
    while s.recv(4096):
        pass
except OSError:
    pass' "$pp" >/dev/null 2>&1
	got="$(head -1 "$hlog")"
	[ "$got" = "127.0.0.1:$op" ] \
		|| fail "[$loop] origin saw Host '$got', want 127.0.0.1:$op"

	# A request header too large for the client buffer must be answered
	# with 431, not dropped with a bare reset. The forward path needs the
	# whole rewritten request to fit. The size is pinned explicitly rather
	# than leaning on the default, so this keeps discriminating whatever the
	# default becomes.
	sp="$(pick_port)"
	gwp_start "[::1]:$sp" --as-http=1 --event-loop="$loop" \
		--client-buf-size=2048
	code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
		-x "http://[::1]:$sp" -H "Cookie: c=$bigval" \
		"http://127.0.0.1:$hp/payload.bin")"
	kill "$GWP_PID" 2>/dev/null
	[ "$code" = 431 ] \
		|| fail "[$loop] oversized header at 2048 got $code (want 431)"

	# ... and the same request goes straight through on the default buffer,
	# which is the point of the large default: an ordinary browser request
	# should not need tuning.
	code="$(curl -s -o "$WORK/big.bin" -w '%{http_code}' --max-time 20 \
		-x "http://[::1]:$pp" -H "Cookie: c=$bigval" \
		"http://127.0.0.1:$hp/payload.bin")"
	[ "$code" = 200 ] \
		|| fail "[$loop] 3KiB header at the default buffer got $code (want 200)"
	assert_files_equal "$WORK/payload.bin" "$WORK/big.bin" \
		"[$loop] big-header forward corrupted the payload"
	kill "$pp_pid" 2>/dev/null
done

pass

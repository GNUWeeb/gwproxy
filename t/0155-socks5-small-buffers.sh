#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The smallest buffers the proxy accepts must carry the longest valid messages:
# a 257-byte SOCKS5 greeting, a 513-byte RFC 1929 request and a CONNECT request
# for a 253-byte name in the 513-byte client buffer, in writes of their own or
# all in one, and the longest HTTP CONNECT request to an upstream proxy in the
# 1280-byte target buffer. Each loop, with HTTP detection on and off.
#
# The upstream is a stub, so the long name never goes to a resolver.

. "$(dirname "$0")/lib.sh"
require python3

user="$(printf 'u%.0s' $(seq 255))"
pass="$(printf 'p%.0s' $(seq 255))"
printf '%s:%s\n' "$user" "$pass" >"$WORK/auth"

# start_stub <socks5|http>: sets STUB_PORT, and STUB_LOG to the requests seen.
start_stub()
{
	STUB_PORT="$(pick_port)"
	STUB_LOG="$WORK/stub.$STUB_PORT"
	python3 "$SERVERS_DIR/stub_upstream.py" "$1" "$STUB_PORT" "$STUB_LOG" \
		>/dev/null 2>&1 &
	local pid=$!
	_PIDS+=("$pid")
	wait_listen "$STUB_PORT" "$pid" || fail "stub upstream did not listen"
}

# socks5_long <port> <split|whole>: the longest handshake, expecting the banner
# of the stub through the tunnel.
socks5_long()
{
	python3 - "$1" "$2" "$user" "$pass" <<'PY'
import socket, sys

port, how, user, pw = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
name = b".".join([b"a" * 63] * 3 + [b"a" * 61])
greet = bytes([5, 255]) + bytes([2] * 255)
auth = bytes([1, len(user)]) + user.encode() + bytes([len(pw)]) + pw.encode()
conn = bytes([5, 1, 0, 3, len(name)]) + name + (443).to_bytes(2, "big")
assert (len(greet), len(auth), len(conn)) == (257, 513, 260)

s = socket.create_connection(("127.0.0.1", port), timeout=60)


def want(n, expect, what):
    got = b""
    while len(got) < n:
        c = s.recv(n - len(got))
        if not c:
            sys.exit("%s: EOF after %r" % (what, got))
        got += c
    if not got.startswith(expect):
        sys.exit("%s: got %r" % (what, got))


if how == "whole":
    s.sendall(greet + auth + conn)
    want(2, b"\x05\x02", "method")
    want(2, b"\x01\x00", "auth")
else:
    s.sendall(greet)
    want(2, b"\x05\x02", "method")
    s.sendall(auth)
    want(2, b"\x01\x00", "auth")
    s.sendall(conn)
want(10, b"\x05\x00", "connect")
want(16, b"UPSTREAM-TUNNEL\n", "tunnel")
PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for up in socks5 http; do
		start_stub "$up"
		[ "$up" = socks5 ] && url="socks5h://127.0.0.1:$STUB_PORT" ||
			url="http://127.0.0.1:$STUB_PORT"

		for http in 0 1; do
			pp="$(pick_port)"
			gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http="$http" \
				--auth-file="$WORK/auth" --event-loop="$loop" \
				--nr-workers=1 --client-buf-size=513 \
				--target-buf-size=1280 --protocol-timeout=60 \
				--upstream-proxy="$url" \
				--upstream-proxy-auth-file="$WORK/auth"

			for how in split whole; do
				out="$(socks5_long "$pp" "$how" 2>&1)" ||
					fail "[$loop $up http=$http $how] $out"
			done
			kill "$GWP_PID" 2>/dev/null
			wait "$GWP_PID" 2>/dev/null
		done
		grep -q "aaaa" "$STUB_LOG" || fail "[$loop $up] the stub saw no request"
	done
done

pass

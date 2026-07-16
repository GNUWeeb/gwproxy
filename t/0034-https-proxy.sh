#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# HTTPS proxy: gwproxy terminates the client's TLS on its own listener (server
# role, from --tls-cert/--tls-key) and runs the existing SOCKS5/HTTP logic on
# the decrypted stream. Because TLS is auto-detected from the first byte, a
# single port serves both TLS ("curl -x https://proxy") and plaintext
# ("curl -x http://proxy" / "socks5h://proxy") clients. Verify: forward-proxy
# over TLS, CONNECT tunnelling over TLS, plaintext coexistence on the same
# port, and Basic auth over TLS. TLS is epoll-only in this cut, so the io_uring
# loop must refuse a TLS listener.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require openssl
require cmp

# Compiled without OpenSSL -> no --tls-cert option -> nothing to test.
require_opt --tls-cert

# curl needs to talk TLS to a proxy and skip its certificate check.
curl --help all 2>/dev/null | grep -q -- --proxy-insecure \
	|| skip "curl lacks --proxy-insecure (HTTPS-proxy support)"

# A throwaway self-signed cert for the listener (curl skips verification).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

printf 'testuser:s3cr3t\n' >"$WORK/auth"

pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --as-http=1 --as-socks5=1 \
	--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" --nr-workers=2

# (1) HTTP forward proxy over TLS: curl speaks TLS to the proxy, which
#     terminates it and relays the absolute-form GET to the origin.
curl -s --max-time 20 --proxy-insecure -x "https://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/fwd.bin" \
	|| fail "curl HTTP-forward over TLS proxy failed"
assert_files_equal "$WORK/payload.bin" "$WORK/fwd.bin" \
	"HTTP forward over TLS corrupted the payload"

# (2) CONNECT tunnel over TLS: --proxytunnel forces a CONNECT, which the
#     TLS-terminated proxy blind-tunnels to the origin.
curl -s --max-time 20 --proxytunnel --proxy-insecure -x "https://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/connect.bin" \
	|| fail "curl CONNECT over TLS proxy failed"
assert_files_equal "$WORK/payload.bin" "$WORK/connect.bin" \
	"CONNECT over TLS corrupted the payload"

# (3) Coexistence: a plaintext HTTP-forward client on the very same port.
curl -s --max-time 20 -x "http://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/plain_http.bin" \
	|| fail "plaintext HTTP client on the TLS port failed"
assert_files_equal "$WORK/payload.bin" "$WORK/plain_http.bin" \
	"plaintext HTTP coexistence corrupted the payload"

# (4) Coexistence: a plaintext SOCKS5 client on the very same port.
curl -s --max-time 20 -x "socks5h://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/plain_socks5.bin" \
	|| fail "plaintext SOCKS5 client on the TLS port failed"
assert_files_equal "$WORK/payload.bin" "$WORK/plain_socks5.bin" \
	"plaintext SOCKS5 coexistence corrupted the payload"

kill "$GWP_PID" 2>/dev/null

# (5) Basic auth over TLS: reject without credentials, accept with them.
pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --as-http=1 --auth-file="$WORK/auth" \
	--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" --nr-workers=2

rm -f "$WORK/noauth.bin"
# --fail turns the 407 challenge (a "successful" HTTP transaction for a plain
# forward GET) into a non-zero exit so we can assert the request was refused.
if curl -s --fail --max-time 20 --proxy-insecure -x "https://127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/noauth.bin"; then
	fail "unauthenticated client over TLS unexpectedly succeeded"
fi
if cmp -s "$WORK/payload.bin" "$WORK/noauth.bin"; then
	fail "unauthenticated client over TLS received the payload"
fi

curl -s --max-time 20 --proxy-insecure -x "https://testuser:s3cr3t@127.0.0.1:$pp" \
	"http://127.0.0.1:$hp/payload.bin" -o "$WORK/auth.bin" \
	|| fail "authenticated client over TLS failed"
assert_files_equal "$WORK/payload.bin" "$WORK/auth.bin" \
	"authenticated HTTP-forward over TLS corrupted the payload"

kill "$GWP_PID" 2>/dev/null

# (6) TLS is epoll-only here: the io_uring loop must refuse a TLS listener.
if grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null; then
	pp="$(pick_port)"
	if "$GWPROXY" --bind="127.0.0.1:$pp" --as-http=1 --event-loop=io_uring \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		>"$WORK/iou.log" 2>&1; then
		fail "io_uring loop accepted a TLS listener (should be rejected)"
	fi
	grep -qi 'epoll' "$WORK/iou.log" \
		|| fail "io_uring+TLS rejection lacked a clear diagnostic"
fi

pass

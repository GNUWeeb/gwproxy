#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS handshake that fails has the engine queue an alert saying why. It must
# reach the client ahead of the close, or all the client gets to report is an
# unexpected EOF. Checked with a client that shares no cipher with the proxy, and
# with a malformed ClientHello. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 120 python3 - "$pp" 2>&1 <<'PY'
import socket
import ssl
import sys

port = int(sys.argv[1])


def fatal_alert(raw):
    # A record of type alert, with a level of fatal.
    return len(raw) >= 7 and raw[0] == 21 and raw[5] == 2


def read_all(s):
    raw = b""
    try:
        while True:
            d = s.recv(4096)
            if not d:
                return raw
            raw += d
    except ConnectionError:
        return raw


def malformed_hello():
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    s.sendall(bytes.fromhex("1603010004") + b"\x01\xff\xff\xff")
    raw = read_all(s)
    s.close()
    return raw


def no_shared_cipher():
    # The certificate has an EC key, and this asks for RSA key exchange.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("kRSA")
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    o = ctx.wrap_bio(inb, outb)
    try:
        o.do_handshake()
    except ssl.SSLWantReadError:
        pass
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    s.sendall(outb.read())
    raw = read_all(s)
    s.close()
    return raw


for f in (malformed_hello, no_shared_cipher):
    raw = f()
    if not fatal_alert(raw):
        print("%s: got %r, not a fatal alert" % (f.__name__, raw[:32]))
        sys.exit(1)
print("ok")
PY
)"
	[ "$out" = ok ] || fail "[$loop] $out"
	kill "$GWP_PID" 2>/dev/null
done

pass

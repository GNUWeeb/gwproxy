#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A name that does not resolve gets the same answer whichever resolver looked
# it up. The system resolver's failures all come back as host unreachable,
# SOCKS5 REP 0x04 (t/0022 checks that); --raw-dns used to pass on whatever
# errno the failure had, so NXDOMAIN, SERVFAIL, an answer with no address and
# a malformed reply each read as a general failure, REP 0x01. HTTP clients get
# 502 either way.
#
# A name too long for DNS (over 255 octets as sent, so 254 or more characters)
# is malformed, and is answered at once as one: REP 0x01, HTTP 400, with no
# query sent. It used to be sent, and the reply was then refused as not about
# the question asked, so the client waited for the protocol timeout. A name of
# 253 characters is still looked up and connected to.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

# A name of <n> characters in labels of 63, never ending in a dot.
long_name()
{
	python3 -c 'import sys; n = int(sys.argv[1])
print("".join("." if k % 64 == 63 else "a" for k in range(n)))' "$1"
}

# ask <socks5|http> <proxy port> <name>: the SOCKS5 reply code, or the HTTP
# status of a CONNECT, or NONE when nothing came back within the timeout. The
# proxy's protocol timeout is far longer, so a lookup left waiting shows here.
ask()
{
	python3 -c '
import socket, sys
kind, port, name, dport = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + dport.to_bytes(2, "big"))
        r = s.recv(16)
        print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
    else:
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                   % (name, dport, name, dport)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        print(r[1].decode() if len(r) > 1 else "NONE")
    s.close()
except Exception:
    print("NONE")' "$@" "$hp" 2>/dev/null
}

# Each case has a responder and a proxy of its own, so they run at once.
dns_case()
{
	local mode="$1" W="$WORK/$1" p name rep code nq want_rep want_code

	mkdir -p "$W"
	case "$mode" in
	long-*)
		start_dns_responder good "$W/nr_queries" ;;
	*)
		start_dns_responder "$mode" ;;
	esac
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$DNS_PORT" --nr-workers=1 \
		--protocol-timeout=120

	name=probe.example
	want_rep=REP=0x04
	want_code=502
	case "$mode" in
	long-253)
		name="$(long_name 253)"
		want_rep=REP=0x00
		want_code=200
		;;
	long-254)
		name="$(long_name 254)"
		want_rep=REP=0x01
		want_code=400
		;;
	esac

	rep="$(ask socks5 "$p" "$name")"
	[ "$rep" = "$want_rep" ] || \
		fail "SOCKS5 got '$rep' for $mode (want $want_rep)"
	code="$(ask http "$p" "$name")"
	[ "$code" = "$want_code" ] || \
		fail "HTTP CONNECT got '$code' for $mode (want $want_code)"

	if [ "$mode" = long-254 ]; then
		nq="$(cat "$W/nr_queries" 2>/dev/null || echo 0)"
		[ "$nq" = 0 ] || fail "$nq queries sent for a name too long for DNS"
	fi
	kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died on $mode"
	return 0
}

gwp_parallel dns_case nxdomain servfail txt-only rdata-truncated \
	long-253 long-254

pass

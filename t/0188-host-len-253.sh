#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A DNS name is at most 253 characters, 254 with the root's trailing dot: 255
# octets on the wire, with a length byte per label and the root's zero. The
# proxy took target names of up to 255 characters, so a name of 254 or 255
# characters passed its checks and could never resolve: the raw resolver
# refused it as malformed (SOCKS5 REP 0x01, HTTP 400), the system resolver
# failed the lookup (REP 0x04, HTTP 502). Both now refuse it as malformed
# before any lookup, for SOCKS5, HTTP CONNECT and a forwarded GET alike.
#
# A name of 253 characters, with or without a trailing dot, is still looked
# up: the raw resolver's test server resolves it and the tunnel comes up,
# while the system resolver fails it as host unreachable, as it fails any
# name under ".invalid" (RFC 2606), which nothing resolves. A trailing dot
# on a 254 character name does not make it short enough.
#
# epoll for --raw-dns, which gwproxy refuses with io_uring; both loops for the
# system resolver.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

# name <n> [dot]: a name of <n> characters ending in ".invalid", in labels of
# at most 63, then a trailing dot (not counted) with "dot".
name()
{
	python3 -c 'import sys
n, dot = int(sys.argv[1]), sys.argv[2:] == ["dot"]
s = "invalid"
while len(s) < n:
    room = n - len(s) - 1
    lab = min(63, room)
    if room - lab == 1:
        lab -= 1	# no empty label in front
    s = "a" * lab + "." + s
assert len(s) == n, s
print(s + ("." if dot else ""))' "$@"
}

# ask <socks5|http|get> <proxy port> <name>: the SOCKS5 reply code, or the
# HTTP status of a CONNECT or of a forwarded GET, or NONE when nothing came
# back.
ask()
{
	python3 -c '
import socket, sys
kind, port, name, dport = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + dport.to_bytes(2, "big"))
        r = s.recv(16)
        print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
    else:
        if kind == "http":
            req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
        else:
            req = "GET http://%s:%d/payload.bin HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
        s.sendall((req % (name, dport, name, dport)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        print(r[1].decode() if len(r) > 1 else "NONE")
    s.close()
except Exception:
    print("NONE")' "$@" "$hp" 2>/dev/null
}

# expect <case> <proxy port> <name> <SOCKS5 reply> <CONNECT status>
# <GET status>
expect()
{
	local c="$1" p="$2" n="$3" got

	got="$(ask socks5 "$p" "$n")"
	[ "$got" = "$4" ] || fail "$c: SOCKS5 got '$got' (want $4)"
	got="$(ask http "$p" "$n")"
	[ "$got" = "$5" ] || fail "$c: HTTP CONNECT got '$got' (want $5)"
	got="$(ask get "$p" "$n")"
	[ "$got" = "$6" ] || fail "$c: HTTP GET got '$got' (want $6)"
}

# The answers for a name that is looked up, then those for every name too
# long for DNS, which must not be.
check()
{
	local c="$1" p="$2" ok_rep="$3" ok_connect="$4" ok_get="$5" n

	expect "$c 253" "$p" "$(name 253)" "$ok_rep" "$ok_connect" "$ok_get"
	expect "$c 253." "$p" "$(name 253 dot)" "$ok_rep" "$ok_connect" "$ok_get"
	for n in "254" "254 dot" "255"; do
		# shellcheck disable=SC2086
		expect "$c $n" "$p" "$(name $n)" REP=0x01 400 400
	done
	kill -0 "$GWP_PID" 2>/dev/null || fail "$c: proxy died"
}

run_case()
{
	local p

	p="$(pick_port)"
	case "$1" in
	raw)
		grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null \
			|| skip "gwproxy built without the raw DNS resolver"
		start_dns_responder good
		gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 \
			--raw-dns=1 --dns-server="127.0.0.1:$DNS_PORT" \
			--nr-workers=1
		check raw "$p" REP=0x00 200 200
		;;
	system-*)
		gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 \
			--event-loop="${1#system-}" --nr-workers=1
		check "$1" "$p" REP=0x04 502 502
		;;
	esac
}

cases=(raw system-epoll)
if have_io_uring; then
	cases+=(system-io_uring)
else
	diag "no usable io_uring here; skipping that loop"
fi
gwp_parallel run_case "${cases[@]}"

pass

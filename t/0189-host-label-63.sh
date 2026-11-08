#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A DNS label is at most 63 characters: on the wire its length byte keeps the
# top two bits for compression pointers. The proxy took target names with
# longer labels, which could never resolve, and the answer depended on the
# resolver: the raw resolver's query builder refused such a name as malformed
# (SOCKS5 REP 0x01, HTTP 400), the system resolver failed the lookup (REP
# 0x04, HTTP 502). Both now refuse it as malformed before any lookup, for
# SOCKS5, HTTP CONNECT and a forwarded GET alike, wherever the long label is
# and with or without a trailing dot.
#
# Names with labels of 63 characters are still looked up: the raw resolver's
# test server resolves them and the tunnel comes up, while the system resolver
# fails them as host unreachable, as it fails any name under ".invalid" (RFC
# 2606), which nothing resolves.
#
# A --target with a 64 character label is refused at startup when a remote-DNS
# upstream is to resolve it; one with 63 is taken.
#
# epoll for --raw-dns, which gwproxy refuses with io_uring; both loops for the
# system resolver.

. "$(dirname "$0")/lib.sh"
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

l63="$(printf 'a%.0s' $(seq 1 63))"
l64="${l63}b"

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

# The answers for names whose labels are short enough, which are looked up,
# then those for every name with a label too long, which must not be.
check()
{
	local c="$1" p="$2" ok_rep="$3" ok_connect="$4" ok_get="$5" n

	for n in "$l63.invalid" "$l63.invalid." "x.$l63.$l63.invalid"; do
		expect "$c ${#n}:$n" "$p" "$n" "$ok_rep" "$ok_connect" "$ok_get"
	done
	for n in "$l64.invalid" "$l64.invalid." "x.$l64.invalid" \
		 "invalid.$l64" "invalid.$l64."; do
		expect "$c ${#n}:$n" "$p" "$n" REP=0x01 400 400
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

# --target for a remote-DNS upstream goes by the same rule. Nothing listens
# on the upstream's port: the proxy needs it only once a client comes.
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --target="$l63.invalid:80" \
	--upstream-proxy=socks5h://127.0.0.1:1 --nr-workers=1
kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null

bad="$l64.invalid:80"
"$GWPROXY" --bind=127.0.0.1:0 --target="$bad" --acl-allow-all \
	--upstream-proxy=socks5h://127.0.0.1:1 --nr-workers=1 \
	>"$WORK/bad.log" 2>&1 &
bad_pid=$!
_PIDS+=("$bad_pid")
for _ in $(seq 1 100); do
	kill -0 "$bad_pid" 2>/dev/null || break
	sleep 0.1
done
kill -0 "$bad_pid" 2>/dev/null \
	&& fail "--target='$bad' with a remote-DNS upstream was not refused at startup"
wait "$bad_pid" 2>/dev/null
[ "$?" != 0 ] || fail "--target='$bad': exit status 0"
grep -q 'Invalid target address' "$WORK/bad.log" \
	|| fail "--target='$bad': no error logged: $(cat "$WORK/bad.log")"

pass

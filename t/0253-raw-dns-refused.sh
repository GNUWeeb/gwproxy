#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A --dns-server with nothing listening answers the raw resolver's query with
# an ICMP port unreachable, which the query's connected socket reports as
# ECONNREFUSED. The lookup must fail at once, as the system resolver fails
# then, with the reply for a name that does not resolve: SOCKS5 REP 0x04,
# HTTP 502. The error used to be ignored, so every hostname request waited
# for the protocol timeout and got a timeout reply.
#
# The port is one the kernel handed out to a UDP socket that is then closed.
# Another test may bind that number meanwhile, and its socket swallows the
# query instead: a slow answer is then tried again on a fresh port, once.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

# ask <socks5|http> <proxy port> <name>: print the SOCKS5 reply code
# (REP=0x..) or the HTTP status of a CONNECT, or NONE, then the seconds it
# took.
ask()
{
	python3 -c '
import socket, sys, time
kind, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
t0 = time.monotonic()
res = "NONE"
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x00\x50")
        r = s.recv(16)
        if len(r) > 1:
            res = "REP=0x%02x" % r[1]
    else:
        s.sendall(("CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n"
                   % (name, name)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        if len(r) > 1:
            res = r[1].decode()
    s.close()
except Exception:
    pass
print(res, "%.2f" % (time.monotonic() - t0))' "$@" 2>/dev/null
}

# try_once: 0 when both requests are refused within 2 s, 2 when an answer
# was slow but right (the port may have been taken), 1 on a wrong answer.
try_once()
{
	local dp p out res t slow=0 kind want

	dp="$(python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])')"
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$dp" --nr-workers=1 \
		--protocol-timeout=30

	for kind in socks5 http; do
		want=REP=0x04
		[ "$kind" = http ] && want=502
		out="$(ask "$kind" "$p" "refused.example")"
		res="${out% *}"
		t="${out#* }"
		diag "$kind via DNS port $dp: $res after $t s"
		if [ "$res" != "$want" ]; then
			diag "$kind: got '$res' (want $want)"
			return 1
		fi
		python3 -c 'import sys; sys.exit(float(sys.argv[1]) > 2)' "$t" || \
			slow=1
	done
	kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
	gwp_stop_pids "$GWP_PID"
	[ "$slow" = 0 ] || return 2
	return 0
}

st=0
try_once || st=$?
if [ "$st" = 2 ]; then
	diag "slow answer, trying once more on another port"
	st=0
	try_once || st=$?
fi
case "$st" in
0)	pass ;;
2)	fail "a refused DNS query was not answered within 2 s, twice" ;;
*)	fail "a refused DNS query got the wrong answer" ;;
esac

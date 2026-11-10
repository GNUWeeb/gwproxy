#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --raw-dns sends a query again when no reply came: after 1 s, then after 2 s
# more, and fails the lookup 4 s after that third send, as for a name that
# does not resolve (SOCKS5 REP 0x04, HTTP 502). It used to send each query
# once, so one lost datagram cost the whole protocol timeout and then a
# timeout reply (0x06, 504) for a name that resolves.
#
# A DNS server drops the first query, or the first two, of names named so;
# the lookup must succeed after the resend, at about 1 s and 3 s, with the
# resend under the same transaction ID. A name never answered gets REP 0x04
# after the three sends, long before the protocol timeout of 30 s.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

# start_dns_drop: start t/servers/dns_drop_first.py, logging its queries to
# $WORK/queries, and set DNS_PORT. The kernel picks the port.
start_dns_drop()
{
	local log="$WORK/dns.log" pid port i

	python3 "$SERVERS_DIR/dns_drop_first.py" "$WORK/queries" >"$log" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	for i in $(seq 1 200); do
		port="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$log")"
		if [ -n "$port" ]; then
			DNS_PORT="$port"
			return 0
		fi
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	sed 's/^/# dns: /' "$log" >&2
	fail "the DNS responder did not start"
}

hp="$(pick_port)"
start_httpd "$hp" "$WORK" "1.1"
start_dns_drop
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$DNS_PORT" --nr-workers=1 \
	--protocol-timeout=30

# ask <socks5|http> <name>: print the SOCKS5 reply code (REP=0x..) or the
# HTTP status of a CONNECT, or NONE, then the seconds it took.
ask()
{
	python3 -c '
import socket, sys, time
kind, port, name, dport = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
t0 = time.monotonic()
res = "NONE"
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
                  + dport.to_bytes(2, "big"))
        r = s.recv(16)
        if len(r) > 1:
            res = "REP=0x%02x" % r[1]
    else:
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                   % (name, dport, name, dport)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        if len(r) > 1:
            res = r[1].decode()
    s.close()
except Exception:
    pass
print(res, "%.2f" % (time.monotonic() - t0))' "$1" "$p" "$2" "$hp" 2>/dev/null
}

# check <kind> <name> <want> <min s> <max s>
check()
{
	local out res t

	out="$(ask "$1" "$2")"
	res="${out% *}"
	t="${out#* }"
	diag "$1 $2: $res after $t s"
	[ "$res" = "$3" ] || fail "$1 $2: got '$res' (want $3) after $t s"
	python3 -c 'import sys; t, lo, hi = map(float, sys.argv[1:])
sys.exit(0 if lo <= t <= hi else 1)' "$t" "$4" "$5" || \
		fail "$1 $2: answered after $t s (want $4 to $5 s)"
	return 0
}

case_one()
{
	case "$1" in
	s5-drop1)	check socks5 drop1-a.example REP=0x00 0.8 4 ;;
	http-drop1)	check http drop1-b.example 200 0.8 4 ;;
	s5-drop2)	check socks5 drop2-c.example REP=0x00 2.8 6 ;;
	s5-silent)	check socks5 silent-d.example REP=0x04 6.8 12 ;;
	http-silent)	check http silent-e.example 502 6.8 12 ;;
	esac
}

gwp_parallel case_one s5-drop1 http-drop1 s5-drop2 s5-silent http-silent

# The sends of each name: drop1 two, drop2 three, silent three and no more;
# each name's under one transaction ID.
for n in drop1-a:2 drop1-b:2 drop2-c:3 silent-d:3 silent-e:3; do
	name="${n%:*}.example"
	want="${n#*:}"
	got="$(awk -v n="$name" '$1 == n && $2 == 1' "$WORK/queries" | wc -l)"
	[ "$got" = "$want" ] || \
		fail "$name: $got A queries sent (want $want)"
	ids="$(awk -v n="$name" '$1 == n && $2 == 1 { print $3 }' \
		"$WORK/queries" | sort -u | wc -l)"
	[ "$ids" = 1 ] || fail "$name: the resends used $ids transaction IDs"
done

kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
pass

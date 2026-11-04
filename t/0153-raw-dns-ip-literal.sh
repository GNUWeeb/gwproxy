#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# With --raw-dns an IP literal is the target: it is not a name to ask the DNS
# server about. The literal used to go out as a query, so it failed on any
# ordinary server, told the server where the client was going, and let the
# server's answer choose where the tunnel went, past a -d rule on the literal.
#
# Asserted for an HTTP CONNECT and a SOCKS5 domain-typed request, with every
# spelling the system resolver takes as a number. A real name still goes to the
# server, so a query count of zero means what it says.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

start_dns()				# $1=mode $2=count_file, sets $dns_port
{
	local ready="$WORK/ready.$1"

	dns_port="$(pick_port)"
	python3 "$SERVERS_DIR/dns_malformed.py" "$1" "$dns_port" "$2" 2>"$ready" &
	_PIDS+=("$!")
	for _ in $(seq 300); do
		[ -s "$ready" ] && return 0
		sleep 0.1
	done
	fail "the DNS responder did not start ($1)"
}

queries() { cat "$1" 2>/dev/null || echo 0; }

socks()					# $1=proxy_port $2=host $3=port
{
	timeout 60 python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--atyp domain --dst "$2" "$1" "$3"
}

# The status code of an HTTP CONNECT to the authority $2.
http()					# $1=proxy_port $2=authority
{
	timeout 60 python3 -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=50)
a = sys.argv[2].encode()
s.sendall(b"CONNECT " + a + b" HTTP/1.1\r\nHost: " + a + b"\r\n\r\n")
d = b""
while b"\r\n" not in d:
    c = s.recv(4096)
    if not c:
        break
    d += c
print(d.split(b" ")[1].decode() if b" " in d else "NONE")' "$1" "$2"
}

# 1) A server that fails every name: the literals must reach the target anyway,
#    without a single query.
count="$WORK/queries.fail"
start_dns rdata-truncated "$count"
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dns_port" --nr-workers=1 --protocol-timeout=30

for host in 127.0.0.1 2130706433 127.1; do
	r="$(socks "$p" "$host" "$hp")"
	[ "$r" = "REP=0x00" ] || fail "SOCKS5 to the literal $host: '$r'"
	r="$(http "$p" "$host:$hp")"
	[ "$r" = 200 ] || fail "HTTP CONNECT to the literal $host: '$r'"
done
[ "$(queries "$count")" = 0 ] \
	|| fail "$(queries "$count") DNS queries for IPv4 literals"

# Nothing need be listening on ::1, or IPv6 even be up: the reply does not
# matter here, the query does.
socks "$p" ::1 "$hp" >/dev/null
http "$p" "[::1]:$hp" >/dev/null
[ "$(queries "$count")" = 0 ] \
	|| fail "$(queries "$count") DNS queries for an IPv6 literal"

r="$(socks "$p" probe.example "$hp")"
[ "$r" != "REP=0x00" ] || fail "a name the server fails was connected: '$r'"
[ "$(queries "$count")" != 0 ] || fail "a real name did not reach the DNS server"
kill "$GWP_PID" 2>/dev/null

# 2) A server that answers 127.0.0.1 for everything must not steer a literal:
#    nothing listens on 127.0.0.2:$lp, and a rule against it must apply.
count="$WORK/queries.good"
start_dns good "$count"
lp="$(pick_port)"
python3 -c '
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
time.sleep(600)' "$lp" &
lp_pid=$!
_PIDS+=("$lp_pid")
wait_listen "$lp" "$lp_pid" || fail "the loopback listener did not start"
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dns_port" --nr-workers=1 --protocol-timeout=30
r="$(socks "$p" 127.0.0.2 "$lp")"
[ "$r" != "REP=0x00" ] || fail "the DNS server steered a SOCKS5 literal elsewhere"
r="$(http "$p" "127.0.0.2:$lp")"
[ "$r" != 200 ] || fail "the DNS server steered an HTTP literal elsewhere"
kill "$GWP_PID" 2>/dev/null

acl="$WORK/acl"
printf -- '-A OUTPUT -d 127.0.0.2/32 -j REJECT\n-P OUTPUT ACCEPT\n' >"$acl"
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dns_port" --nr-workers=1 --protocol-timeout=30 \
	--acl-file="$acl"
r="$(socks "$p" 127.0.0.2 "$hp")"
[ "$r" = "REP=0x02" ] || fail "SOCKS5: a -d rule on the literal gave '$r'"
r="$(http "$p" "127.0.0.2:$hp")"
[ "$r" = 403 ] || fail "HTTP: a -d rule on the literal gave '$r'"
[ "$(queries "$count")" = 0 ] \
	|| fail "$(queries "$count") DNS queries for a literal"
r="$(socks "$p" probe.example "$hp")"
[ "$r" = "REP=0x00" ] || fail "a name the server answers failed: '$r'"
[ "$(queries "$count")" != 0 ] || fail "a real name did not reach the DNS server"

pass

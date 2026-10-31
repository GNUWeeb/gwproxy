#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Built-in default ACL (no --acl-file, no --acl-allow-all): a loopback-only
# service must stay out of reach whatever the client calls it. 127.0.0.1 is
# the obvious spelling, but on Linux a connect() to the unspecified address
# (0.0.0.0, ::) lands on the local host as well, ::1 is loopback, and
# "localhost" and "0" are names for those, so each of them is tried over
# SOCKS5 (every ATYP), HTTP CONNECT, HTTP forwarding and the UDP ASSOCIATE
# relay. The metadata address 169.254.169.254 must be refused by the ACL
# outright (REP 0x02), not attempted.
#
# The same requests with --acl-allow-all must reach the service, which proves
# the refusals above come from the default ACL and not from a broken path.

. "$(dirname "$0")/lib.sh"
require curl
require python3

python3 -c 'import socket; socket.socket(socket.AF_INET6).bind(("::1", 0))' \
	2>/dev/null || skip "no IPv6 loopback"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 4096
start_httpd "$hp" "$WORK" "1.1"		# dual-stack [::], like most services

# A dual-stack UDP echo server, reachable via ::1 and 0.0.0.0 alike.
start_udp_echo ::
ep="$UDP_ECHO_PORT"

# Start gwproxy with no ACL argument at all. gwp_start would inject
# --acl-allow-all into such a command line, so launch it directly.
gwp_start_default()			# $1=port, rest: gwproxy args
{
	local port="$1"; shift

	"$GWPROXY" --bind="127.0.0.1:$port" --log-level=3 "$@" \
		>"$WORK/gwp.$port.log" 2>&1 &
	GWP_PID=$!
	_PIDS+=("$GWP_PID")
	if ! wait_listen "$port" "$GWP_PID"; then
		sed 's/^/# gwp: /' "$WORK/gwp.$port.log" >&2
		fail "default-ACL gwproxy did not listen on $port"
	fi
}

socks5_rep()				# $1=proxy_port $2=atyp $3=dst $4=dst_port
{
	python3 "$SERVERS_DIR/socks5_probe.py" --atyp "$2" --dst "$3" \
		"$1" "$4" 2>/dev/null
}

# Print the status code of an HTTP CONNECT reply (or nothing).
http_connect_code()			# $1=proxy_port $2=authority
{
	python3 - "$@" 2>/dev/null <<-'PY'
	import socket, sys
	s = socket.create_connection(('127.0.0.1', int(sys.argv[1])))
	s.settimeout(10)
	a = sys.argv[2]
	s.sendall(('CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (a, a)).encode())
	print(s.recv(64).split(b' ')[1].decode())
	PY
}

# Every spelling of "this host" a client could use, per request type.
S5_TARGETS="ipv4/127.0.0.1 ipv4/0.0.0.0 ipv6/::1 ipv6/:: ipv6/::ffff:0.0.0.0
	domain/localhost domain/0 domain/0.0.0.0"
HTTP_HOSTS="127.0.0.1 0.0.0.0 [::1] [::] localhost 0"
UDP_HOSTS="::1 0.0.0.0"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start_default "$pp" --as-socks5=1 --as-http=1 --nr-workers=1 \
		--event-loop="$loop"

	# ::127.0.0.1 (IPv4-compatible) does not route to this host, so it
	# has no place in the control run below; it must still be refused.
	for t in $S5_TARGETS ipv6/::127.0.0.1; do
		rep="$(socks5_rep "$pp" "${t%%/*}" "${t#*/}" "$hp")"
		[ "$rep" = REP=0x02 ] || \
			fail "$loop default ACL: SOCKS5 $t got '${rep:-<none>}' (want REP=0x02)"
	done

	# The metadata endpoint: refused by the ruleset, so the reply is
	# immediate and says "not allowed" rather than timing out a connect.
	rep="$(timeout 5 python3 "$SERVERS_DIR/socks5_probe.py" --atyp ipv4 \
		--dst 169.254.169.254 "$pp" 80 2>/dev/null)"
	[ "$rep" = REP=0x02 ] || \
		fail "$loop default ACL: SOCKS5 169.254.169.254 got '${rep:-<none>}' (want REP=0x02)"

	for h in $HTTP_HOSTS; do
		code="$(http_connect_code "$pp" "$h:$hp")"
		[ "$code" = 403 ] || \
			fail "$loop default ACL: HTTP CONNECT $h got '${code:-<none>}' (want 403)"
		code="$(curl -s --max-time 10 -x "http://127.0.0.1:$pp" \
			"http://$h:$hp/payload.bin" -o /dev/null -w '%{http_code}')"
		[ "$code" = 403 ] || \
			fail "$loop default ACL: HTTP forward to $h got $code (want 403)"
	done

	for h in $UDP_HOSTS; do
		python3 "$SERVERS_DIR/socks5_udp_client.py" --target-host "$h" \
			--expect-drop "$pp" "$ep" 64 >/dev/null || \
			fail "$loop default ACL: UDP datagram to $h was relayed"
	done
	kill "$GWP_PID" 2>/dev/null

	# Control: with the default ACL disabled the very same requests reach
	# the service (127.0.0.1 included, so this is not a list of names that
	# merely fail to resolve or connect on this host).
	ap="$(pick_port)"
	gwp_start "127.0.0.1:$ap" --as-socks5=1 --as-http=1 --nr-workers=1 \
		--event-loop="$loop" --acl-allow-all

	for t in $S5_TARGETS; do
		rep="$(socks5_rep "$ap" "${t%%/*}" "${t#*/}" "$hp")"
		[ "$rep" = REP=0x00 ] || \
			fail "$loop --acl-allow-all: SOCKS5 $t got '${rep:-<none>}' (want REP=0x00)"
	done

	for h in $HTTP_HOSTS; do
		code="$(http_connect_code "$ap" "$h:$hp")"
		[ "$code" = 200 ] || \
			fail "$loop --acl-allow-all: HTTP CONNECT $h got '${code:-<none>}' (want 200)"
		curl -s --max-time 20 -x "http://127.0.0.1:$ap" \
			"http://$h:$hp/payload.bin" -o "$WORK/out.bin" || \
			fail "$loop --acl-allow-all: HTTP forward to $h failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"$loop --acl-allow-all: HTTP forward to $h corrupted the payload"
	done

	for h in $UDP_HOSTS; do
		python3 "$SERVERS_DIR/socks5_udp_client.py" --target-host "$h" \
			"$ap" "$ep" 64 >/dev/null || \
			fail "$loop --acl-allow-all: UDP datagram to $h was not relayed"
	done
	kill "$GWP_PID" 2>/dev/null
done

pass

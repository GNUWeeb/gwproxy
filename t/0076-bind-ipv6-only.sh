#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --bind-ipv6-only: IPV6_V6ONLY on the listener, so a wildcard [::] bind stops
# accepting IPv4 clients as ::ffff:a.b.c.d.
#
# Both settings are asserted against the same bind address, because "an IPv4
# client could not connect" proves nothing unless the identical proxy with the
# option off accepts one. The option is also set explicitly in both directions,
# so this holds regardless of the host's net.ipv6.bindv6only sysctl.
#
# The UDP relay case matters most: that socket deliberately clears
# IPV6_V6ONLY so it can egress both families, and it must keep working with
# --bind-ipv6-only=1 on the listener.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --bind-ipv6-only

python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::1", 0)); s.close()' 2>/dev/null || skip "no usable IPv6 loopback"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 4096
start_httpd "$hp" "$WORK" "1.1"

# Can an IPv4 client reach a proxy bound to the IPv6 wildcard?
v4_reaches() {			# $1=port -> prints yes|no
	python3 -c 'import socket, sys
try:
    s = socket.socket(); s.settimeout(5)
    s.connect(("127.0.0.1", int(sys.argv[1]))); s.close(); print("yes")
except OSError:
    print("no")' "$1"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# Off: the dual-stack default, IPv4 clients are accepted.
	p="$(pick_port)"
	gwp_start "[::]:$p" --as-socks5=1 --event-loop="$loop" \
		--bind-ipv6-only=0
	got="$(v4_reaches "$p")"
	kill "$GWP_PID" 2>/dev/null
	[ "$got" = yes ] \
		|| fail "[$loop] --bind-ipv6-only=0 refused an IPv4 client on [::]"

	# On: same bind, IPv4 clients can no longer reach it...
	p="$(pick_port)"
	gwp_start "[::]:$p" --as-socks5=1 --event-loop="$loop" \
		--bind-ipv6-only=1
	got="$(v4_reaches "$p")"
	[ "$got" = no ] \
		|| fail "[$loop] --bind-ipv6-only=1 still accepted an IPv4 client on [::]"

	# ...while IPv6 clients still work end to end on that same proxy, so
	# the option narrowed the listener rather than breaking it.
	curl -s --max-time 20 -x "socks5://[::1]:$p" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/v6.bin" \
		|| fail "[$loop] --bind-ipv6-only=1 broke IPv6 clients"
	assert_files_equal "$WORK/payload.bin" "$WORK/v6.bin" \
		"[$loop] --bind-ipv6-only=1 corrupted an IPv6-client transfer"
	kill "$GWP_PID" 2>/dev/null

	# The UDP relay socket must stay dual-stack: it is bound separately and
	# is what lets a v6 client reach a v4 target. A regression here would
	# silently break UDP ASSOCIATE while the TCP cases above stayed green.
	start_udp_echo 127.0.0.1
	up="$UDP_ECHO_PORT"

	p="$(pick_port)"
	gwp_start "[::]:$p" --as-socks5=1 --event-loop="$loop" \
		--bind-ipv6-only=1
	python3 "$SERVERS_DIR/socks5_udp_client.py" --proxy-host ::1 \
		--target-host 127.0.0.1 "$p" "$up" 64 1400 \
		>"$WORK/udp.out" 2>&1 \
		|| fail "[$loop] UDP relay to an IPv4 target broke under --bind-ipv6-only=1"
	kill "$GWP_PID" 2>/dev/null
done

pass

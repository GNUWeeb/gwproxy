#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# On a kernel without IPv6 the SOCKS5 UDP relay cannot be dual-stack, but it must
# still relay between IPv4 addresses. A seccomp filter stands in for that kernel:
# socket(AF_INET6, ...) fails as it does there. Exercised on every available
# event loop.

. "$(dirname "$0")/lib.sh"
require python3

noipv6="$SERVERS_DIR/no_ipv6_exec.py"
pin() { python3 "$SERVERS_DIR/socks5_udp_pin.py" "$@"; }
probe() { python3 "$SERVERS_DIR/socks5_udp_probe.py" "$@"; }
udp_client() { python3 "$SERVERS_DIR/socks5_udp_client.py" "$@"; }

# The filter must really work here, or this test proves nothing. The helper exits
# 77 where it cannot be installed; the nested python exits 3 if IPv6 still works.
r=0
python3 "$noipv6" "$(command -v python3)" -c '
import errno, socket, sys
try:
    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
except OSError as e:
    sys.exit(0 if e.errno == errno.EAFNOSUPPORT else 3)
sys.exit(3)' || r=$?
[ "$r" != 77 ] || skip "cannot install a seccomp filter here"
[ "$r" = 0 ] || fail "the filter did not refuse AF_INET6 sockets ($r)"

# Run the proxy itself, not python, under the filter: gwp_start() takes the PID
# of a script that execs its way to gwproxy.
real="$GWPROXY"
GWPROXY="$WORK/gwproxy-noipv6"
printf '#!/bin/sh\nexec python3 "%s" "%s" "$@"\n' "$noipv6" "$real" >"$GWPROXY"
chmod +x "$GWPROXY"

start_udp_echo 127.0.0.1
ep="$UDP_ECHO_PORT"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop"

	udp_client "$pp" "$ep" 1 1400 60000 \
		|| fail "[$loop] the relay did not work without IPv6"

	# A v4-mapped target is still an IPv4 one, and a datagram to the
	# unspecified address is answered from loopback.
	[ "$(probe --atyp ipv6 --dst ::ffff:127.0.0.1 "$pp" "$ep")" = RELAYED ] \
		|| fail "[$loop] a v4-mapped target was dropped"
	[ "$(probe --dst 0.0.0.0 "$pp" "$ep")" = RELAYED ] \
		|| fail "[$loop] a datagram to 0.0.0.0 got no reply"

	# An IPv6 target cannot be reached: drop it, keep the association.
	[ "$(probe --atyp ipv6 --dst ::1 "$pp" "$ep")" = DROPPED ] \
		|| fail "[$loop] an IPv6 target was not dropped"

	# Pinning works on IPv4 addresses too.
	for c in first-wins declared; do
		pin "$pp" "$ep" "$c" || fail "[$loop] $c"
	done

	kill -0 "$GWP_PID" 2>/dev/null || fail "[$loop] the proxy died"
	kill "$GWP_PID" 2>/dev/null
done

pass

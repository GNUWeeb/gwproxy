#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A target that turns out to be the proxy's own listener is refused. Otherwise
# one client connection and a few KB of pipelined requests nest the proxy in
# itself, each request opening another pair of descriptors. Plain forwarding
# needs no client bytes for that: each hop dials the next by itself, even after
# the client has gone. Whichever way the address comes about, -j DNAT and an
# upstream included, and whichever local address it is under a wildcard bind.
# Another service on the same port number of an address the listener does not
# cover must still work.
#
# The wildcard and non-loopback cases run in a private network namespace, and
# are skipped where user namespaces are unavailable. Runs on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

N=300		# nested requests behind the first
MAX_FDS=60	# plenty for a handful of pairs, far below 2 * N

# refused <what> <dst> <dport>: the chain stops at the first hop, on proxy GWP_PID
# listening on port $pp.
refused()
{
	local out

	out="$(python3 "$SERVERS_DIR/socks5_self_chain.py" "$GWP_PID" "$pp" \
		"$2" "$3" "$N" "${host:-127.0.0.1}")" || fail "$tag $1: client failed"
	case "$out" in
	"REP=0x00 "*) fail "$tag $1: connected to itself ($out)" ;;
	"REP=0x"*) ;;
	*) fail "$tag $1: no reply ($out)" ;;
	esac
	[ "${out##*PEAK=}" -lt "$MAX_FDS" ] || fail "$tag $1: nested ($out)"
}

# reached <what> <dst> <dport>: the proxy connects there.
reached()
{
	local got

	got="$(python3 "$SERVERS_DIR/socks5_probe.py" --atyp "$(case "$2" in *:*) echo ipv6 ;; *) echo ipv4 ;; esac)" \
		--host "${host:-127.0.0.1}" --dst "$2" "$pp" "$3")"
	[ "$got" = "REP=0x00" ] || fail "$tag $1: got '$got', want REP=0x00"
}

# listener <addr> <port>: a service on <addr> <port>, until the test ends.
listener()
{
	local log="$WORK/lst.$1.$2" pid i

	python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
print("READY", flush=True)
while True:
    s.accept()[0].close()
' "$1" "$2" >"$log" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	for i in $(seq 1 400); do
		grep -q READY "$log" && return 0
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	fail "no listener on $1 $2: $(cat "$log")"
}

# nr_refused: refusals in the log of the proxy listening on port $pp.
nr_refused()
{
	grep -c 'Refused a target' "$WORK/gwp.$pp.log" || true
}

# not_self <what> <dst>: an address with no route, on the listener's port. The
# proxy tries it and fails, rather than taking it for itself.
not_self()
{
	local before got

	before="$(nr_refused)"
	got="$(python3 "$SERVERS_DIR/socks5_probe.py" --atyp ipv4 --dst "$2" "$pp" "$pp")"
	case "$got" in
	"REP=0x00") fail "$tag $1: reported connected" ;;
	"REP=0x"*) ;;
	*) fail "$tag $1: no reply ($got)" ;;
	esac
	[ "$(nr_refused)" = "$before" ] || fail "$tag $1: taken for the proxy itself"
}

# plain_client <what>: one client of the plain forwarder on port $pp is
# disconnected.
plain_client()
{
	local got

	got="$(python3 - "$pp" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
s.settimeout(30)
try:
    print("DATA" if s.recv(100) else "EOF")
except ConnectionError:
    print("EOF")
except OSError as e:
    print(type(e).__name__)
PY
)"
	[ "$got" = EOF ] || fail "$tag $1: client got $got, want a disconnect"
}

# plain_refused <what>: as plain_client, having caused one refusal and no further
# hop.
plain_refused()
{
	local n

	plain_client "$1"
	# A chain would keep adding refusals after the client has gone.
	sleep 1
	n="$(nr_refused)"
	[ "$n" = 1 ] || fail "$tag $1: $n refusals for one client, want 1"
}

stop_proxy()
{
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

if [ "${1:-}" != --inner ]; then
	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue
		tag="[$loop]"

		pp="$(pick_port)"
		ACL="$WORK/acl.$loop"
		printf -- '-A OUTPUT --dports 9 -j DNAT --to 127.0.0.1:%s\n-P OUTPUT ACCEPT\n' \
			"$pp" >"$ACL"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
			--nr-workers=2 --acl-file="$ACL"

		refused "own address" 127.0.0.1 "$pp"
		refused "-j DNAT onto itself" 127.0.0.1 9

		# HTTP gets the same answer, in its own terms.
		st="$(python3 - "$pp" <<'PY'
import socket, sys
p = sys.argv[1]
s = socket.create_connection(("127.0.0.1", int(p)), timeout=30)
s.settimeout(30)
s.sendall(b"CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: x\r\n\r\n" % p.encode())
print(s.recv(200).split(b"\r\n")[0].decode(errors="replace"))
PY
)"
		case "$st" in
		"HTTP/1."?" 502 "*) ;;
		*) fail "$tag HTTP CONNECT to itself got '$st' (want 502)" ;;
		esac

		# Another address, the same port number: not this listener.
		listener 127.0.0.2 "$pp"
		reached "same port, other address" 127.0.0.2 "$pp"
		stop_proxy

		# The unspecified address is 127.0.0.1 to connect(), so it is this
		# listener only if that is where it listens.
		host=127.0.0.2
		pp="$(pick_port)"
		listener 127.0.0.1 "$pp"
		gwp_start "127.0.0.2:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1
		reached "unspecified, reaches another address" 0.0.0.0 "$pp"
		stop_proxy
		host=

		# An upstream that is the proxy itself.
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --upstream-proxy="socks5://127.0.0.1:$pp"
		refused "upstream is itself" 192.0.2.1 80
		stop_proxy

		# Plain forwarding, with nothing from the client to wait for.
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$pp" \
			--event-loop="$loop" --nr-workers=1
		plain_refused "plain, target is itself"
		stop_proxy

		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target="0.0.0.0:$pp" \
			--event-loop="$loop" --nr-workers=1
		plain_refused "plain, unspecified target"
		stop_proxy

		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --target=192.0.2.1:80 \
			--upstream-proxy="socks5://127.0.0.1:$pp" \
			--event-loop="$loop" --nr-workers=1
		plain_refused "plain, upstream is itself"
		stop_proxy
	done

	require unshare
	require ip
	ns_drop_setup
	$NS_DROP unshare -rn true 2>/dev/null || \
		skip "no user+net namespaces (unshare -rn) available"
	out="$($NS_DROP unshare -rn "$0" --inner "$WORK" 2>&1)"
	printf '%s\n' "$out" | sed 's/^/# /' >&2
	case "$out" in
	*PASS-INNER*) pass ;;
	esac
	fail "inner run failed (see above)"
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
trap '[ -z "${GWP_PID:-}" ] || kill "$GWP_PID" 2>/dev/null; for p in "${_PIDS[@]}"; do kill "$p" 2>/dev/null; done' EXIT

ip link set lo up || fail "cannot bring up lo in the namespace"
ip addr add 192.0.2.1/32 dev lo || fail "cannot add an address"
ip addr add 198.51.100.1/32 dev lo || fail "cannot add an address"
# The second of a subnet is a secondary address: its local route has the first
# as its source, so a connection to it does not leave from it.
ip addr add 10.9.0.1/24 dev lo || fail "cannot add an address"
ip addr add 10.9.0.2/24 dev lo || fail "cannot add an address"
have_v6=1
ip -6 addr add fd01::77/128 dev lo 2>/dev/null || have_v6=
# Local routes: no address on the host, yet connections arrive. IPv6 bind() says
# no to these without freebind.
ip route add local 10.77.0.0/16 dev lo || fail "cannot add a local route"
[ -z "$have_v6" ] || ip -6 route add local fd02::/64 dev lo || have_v6=

# The namespace is private, so fixed numbers cannot clash.
pp=20000
other=20001

# The address logic is shared, so the second loop only checks the way there; a
# test of every case on both would run past the watchdog on a loaded machine.
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue
	tag="[$loop ns]"

	# Dual-stack wildcard: every local address, of either family.
	gwp_start "[::]:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
		--acl-allow-all
	refused "wildcard, local IPv4" 192.0.2.1 "$pp"
	refused "wildcard, secondary IPv4" 10.9.0.2 "$pp"
	if [ "$loop" = epoll ]; then
		refused "wildcard, second local IPv4" 198.51.100.1 "$pp"
		refused "wildcard, other loopback address" 127.0.0.2 "$pp"
		refused "wildcard, unspecified" 0.0.0.0 "$pp"
		if [ -n "$have_v6" ]; then
			refused "wildcard, local IPv6" fd01::77 "$pp"
			refused "wildcard, IPv6 loopback" ::1 "$pp"
		fi
		refused "wildcard, IPv4 local route" 10.77.1.1 "$pp"
	fi
	if [ -n "$have_v6" ]; then
		refused "wildcard, IPv6 local route" fd02::9 "$pp"
	fi
	stop_proxy

	if [ "$loop" = epoll ]; then
		# A local service on another port is none of this.
		gwp_start "0.0.0.0:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
			--acl-allow-all
		listener 192.0.2.1 "$other"
		reached "wildcard, other port" 192.0.2.1 "$other"
		refused "IPv4 wildcard, local IPv4" 198.51.100.1 "$pp"
		not_self "IPv4 wildcard, not a local address" 203.0.113.9
		# An IPv4 wildcard does not cover IPv6.
		if [ -n "$have_v6" ]; then
			listener ::1 "$pp"
			reached "IPv4 wildcard, same port on IPv6" ::1 "$pp"
		fi
		stop_proxy

		# A forced source does not hide it.
		gwp_start "0.0.0.0:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
			--acl-allow-all --bind-source=198.51.100.1
		refused "wildcard, forced source" 192.0.2.1 "$pp"
		stop_proxy

		# ip_nonlocal_bind has bind() say yes to anything, which must not
		# make every target on this port number the proxy.
		if echo 1 2>/dev/null >/proc/sys/net/ipv4/ip_nonlocal_bind; then
			gwp_start "0.0.0.0:$pp" --as-socks5=1 --event-loop="$loop" \
				--nr-workers=1 --acl-allow-all
			refused "ip_nonlocal_bind, local IPv4" 10.9.0.2 "$pp"
			stop_proxy
			# Plain forwarding is asked before the connect, so the answer
			# shows even though nothing is there to connect to.
			gwp_start "0.0.0.0:$pp" --target="203.0.113.9:$pp" \
				--event-loop="$loop" --nr-workers=1 --acl-allow-all
			plain_client "ip_nonlocal_bind, not a local address"
			[ "$(nr_refused)" = 0 ] || \
				fail "$tag ip_nonlocal_bind: a remote target taken for the proxy"
			stop_proxy
			echo 0 >/proc/sys/net/ipv4/ip_nonlocal_bind
		fi
	fi

	# A forced source is where connect() takes the unspecified address, here
	# the address of the listener. -j BIND forces one too.
	host=198.51.100.1
	gwp_start "198.51.100.1:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
		--acl-allow-all --bind-source=198.51.100.1
	refused "specific address, forced source, unspecified" 0.0.0.0 "$pp"
	stop_proxy
	if [ "$loop" = epoll ]; then
		printf -- '-A OUTPUT -j BIND --to-source 198.51.100.1 --accept\n-P OUTPUT ACCEPT\n' \
			>"$WORK/acl.ns"
		gwp_start "198.51.100.1:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
			--acl-file="$WORK/acl.ns"
		refused "specific address, -j BIND, unspecified" 0.0.0.0 "$pp"
		stop_proxy
	fi
	host=

	# A full table leaves no descriptor to ask the routing table with. A
	# connected target on the listener's port cannot be let through, or the
	# chain goes on with every two descriptors freed. Plain forwarding has not
	# connected yet: it waits, and asks once it has a descriptor.
	gwp_start "0.0.0.0:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
		--acl-allow-all --protocol-timeout=120
	got="$(python3 "$SERVERS_DIR/self_full_table.py" socks5 "$GWP_PID" "$pp" 192.0.2.1)" || \
		fail "$tag full table: $got"
	[ "$got" = "REP=0x01" ] || fail "$tag full table: got '$got', want REP=0x01"
	stop_proxy

	gwp_start "0.0.0.0:$pp" --target="203.0.113.9:$pp" --event-loop="$loop" \
		--nr-workers=1 --acl-allow-all
	got="$(python3 "$SERVERS_DIR/self_full_table.py" plain "$GWP_PID" "$pp")" || \
		fail "$tag full table, plain: $got"
	[ "$got" = "WAITED EOF" ] || fail "$tag full table, plain: got '$got', want WAITED EOF"
	[ "$(nr_refused)" = 0 ] || fail "$tag full table, plain: a remote target refused"
	stop_proxy

	# Plain forwarding to a secondary address, under a wildcard.
	gwp_start "0.0.0.0:$pp" --target="10.9.0.2:$pp" --event-loop="$loop" \
		--nr-workers=1 --acl-allow-all
	plain_refused "plain, wildcard, secondary IPv4"
	stop_proxy

	if [ "$loop" = epoll ]; then
		# A forced source that is some other address: not this listener. Last,
		# as the service holds the port against a wildcard bind.
		host=198.51.100.1
		listener 192.0.2.1 "$pp"
		gwp_start "198.51.100.1:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1 \
			--acl-allow-all --bind-source=192.0.2.1
		reached "specific address, other forced source" 0.0.0.0 "$pp"
		stop_proxy
		host=
	fi

	for p in "${_PIDS[@]}"; do
		kill "$p" 2>/dev/null
		wait "$p" 2>/dev/null
	done
	_PIDS=()
	# Closed connections of the listeners still hold these numbers.
	pp=$((pp + 2))
	other=$((other + 2))
done

echo PASS-INNER
exit 0

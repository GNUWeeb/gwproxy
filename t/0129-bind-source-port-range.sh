#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pinned source address with no pinned port must not cap egress at one local
# port range. bind() with port 0 makes the kernel choose a port with no idea of
# the destination, and that port is then taken for every destination, TIME_WAIT
# included; connect() only needs a unique 4-tuple. So the source port has to be
# left to connect(), which is what IP_BIND_ADDRESS_NO_PORT asks for.
#
# Shrinking the local port range makes the limit reachable with a handful of
# tunnels, and the range is a per-network-namespace setting, so the body runs in
# a private one. t/servers/socks5_port_range.py has the details.
#
# Covered, on every event loop, each through --bind-source and -j BIND without a
# port, IPv4 and IPv6: closed tunnels do not eat into the range for other
# destinations, more tunnels than ports can be open at once, each of them still
# leaves from the pinned address, and using up the range for one destination
# refuses only the tunnels over the limit.

. "$(dirname "$0")/lib.sh"
require python3
require unshare
require ip
require_opt --bind-source

RANGE_LOW=50000
RANGE_SIZE=8

if [ "${1:-}" != --inner ]; then
	ns_drop_setup
	$NS_DROP unshare -rn true 2>/dev/null || \
		skip "no user+net namespaces (unshare -rn) available"
	out="$($NS_DROP unshare -rn "$0" --inner "$WORK" 2>&1)"
	printf '%s\n' "$out" | sed 's/^/# /' >&2
	case "$out" in
	*SKIP-INNER*) skip "the local port range cannot be set in a namespace" ;;
	*PASS-INNER*) pass ;;
	esac
	fail "inner run failed (see above)"
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
# The work directory is the outer half's: leave its removal to it. Nothing but
# the proxy runs in the background here, and it must go with the namespace.
trap '[ -z "${GWP_PID:-}" ] || kill "$GWP_PID" 2>/dev/null' EXIT

ip link set lo up || fail "cannot bring up lo in the namespace"
echo "$RANGE_LOW $((RANGE_LOW + RANGE_SIZE - 1))" \
	>/proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || {
	echo SKIP-INNER
	exit 0
}

have_v6=1
ip -6 addr add fd01::77/128 dev lo 2>/dev/null || have_v6=
ip -6 addr add fd01::78/128 dev lo 2>/dev/null || have_v6=

# The namespace is private, so fixed numbers cannot clash. All of them lie below
# the narrow range. Every case gets origin and client ports of its own, because
# the previous case leaves TIME_WAIT sockets behind.
proxy_port=30000
first_port=31000

# run_case <what> <origin-ip> <source-ip> <gwproxy args...>
run_case()
{
	local what="$1" origin="$2" src="$3" out
	shift 3

	proxy_port=$((proxy_port + 1))
	first_port=$((first_port + 1000))
	gwp_start "127.0.0.1:$proxy_port" --as-socks5=1 --nr-workers=1 "$@"
	if ! out="$(python3 "$SERVERS_DIR/socks5_port_range.py" "$proxy_port" \
		"$origin" "$src" "$first_port" "$RANGE_SIZE" 2>&1)"; then
		sed 's/^/# gwp: /' "$WORK/gwp.$proxy_port.log" >&2
		fail "$what: $out"
	fi
	diag "$what: $out"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	GWP_PID=
}

printf -- '%s\n' '-A OUTPUT -j BIND --to-source 127.0.0.78' \
	'-P OUTPUT ACCEPT' >"$WORK/bind4.acl"
printf -- '%s\n' '-A OUTPUT -j BIND --to-source fd01::78' \
	'-P OUTPUT ACCEPT' >"$WORK/bind6.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	run_case "[$loop] --bind-source" 127.0.0.1 127.0.0.77 \
		--event-loop="$loop" --bind-source=127.0.0.77
	run_case "[$loop] -j BIND" 127.0.0.1 127.0.0.78 \
		--event-loop="$loop" --acl-file="$WORK/bind4.acl"
	[ -n "$have_v6" ] || continue
	run_case "[$loop] IPv6 --bind-source" ::1 fd01::77 \
		--event-loop="$loop" --bind-source=fd01::77
	run_case "[$loop] IPv6 -j BIND" ::1 fd01::78 \
		--event-loop="$loop" --acl-file="$WORK/bind6.acl"
done
[ -n "$have_v6" ] || diag "no IPv6 in the namespace: IPv6 cases not run"

echo PASS-INNER

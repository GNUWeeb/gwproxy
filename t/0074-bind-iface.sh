#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --bind-iface: the global default egress interface for outgoing (target)
# connections, and how an ACL "-j BIND" rule overrides it.
#
# SO_BINDTODEVICE itself has been unprivileged since Linux 5.7, but to be worth
# asserting on it needs a second path to the origin: a veth pair with one end in
# a separate network namespace, the origin server inside that namespace, and two
# addresses on our end. That makes the assertions sharp. Binding the wrong
# device leaves the origin unreachable, so "the connection was dropped" really
# does mean the device was honoured, and our end's second address is one the
# kernel would never pick by itself.
#
# There are two ways to build that network, and this test takes whichever the
# host allows:
#
#   * unprivileged, inside a private user+network namespace, where we hold
#     CAP_NET_ADMIN over our own netns. The peer namespace is a parked
#     "unshare -n" helper addressed by pid rather than an "ip netns" entry,
#     because that would want CAP_SYS_ADMIN to mount under /run/netns. Nothing
#     outside the namespace is touched, so the test network cannot collide with
#     the host's addresses or be rewritten by its NAT rules;
#
#   * privileged, on the host with "ip netns", when user namespaces are not
#     available. Ubuntu 24.04 restricts unprivileged ones by default
#     (kernel.apparmor_restrict_unprivileged_userns), and the GitHub runners
#     have them off -- 0063 skips there for exactly this reason. Without this
#     fallback the whole test would skip on the one machine that runs it most.
#
# Only when neither works does it skip.
#
# Covered, on every event loop:
#   * --bind-iface alone: the right device carries traffic, the wrong one (lo)
#     is fatal rather than silently egressing via the default route;
#   * --bind-iface together with --bind-source;
#   * an ACL "-j BIND --to-iface" rule overriding a global default that would
#     otherwise drop the connection, and REPLACING it wholesale -- a rule that
#     names only an interface must not inherit the global --bind-source;
#   * a nonexistent global device: gwproxy still starts (the device may come up
#     later, e.g. a WireGuard link) but every connection is dropped.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --bind-iface

IP="$(command -v ip 2>/dev/null || echo /usr/sbin/ip)"
[ -x "$IP" ] || skip "iproute2 (ip) not available"

# RFC 5737 TEST-NET-1: a range no host has a reason to route, let alone NAT.
NET=192.0.2

if [ "${1:-}" != "--inner" ]; then
	#
	# Outer half. Prefer the namespace; fall back to the host.
	#
	# ns_drop_setup has to run here rather than inside: in there "id -u" is
	# the MAPPED root, and its chown to the outer uid would fail with
	# EINVAL, that uid having no mapping. See lib.sh for why it exists.
	#
	ns_drop_setup
	if $NS_DROP unshare -rn true 2>/dev/null; then
		require unshare
		require nsenter
		out="$WORK/inner.out"
		# Detached: a backgrounded proxy holding the pipe would wedge
		# the read.
		setsid $NS_DROP unshare -rn "$0" --inner "$WORK" \
			</dev/null >"$out" 2>&1 &
		for i in $(seq 1 120); do
			grep -q '^INNER-DONE' "$out" 2>/dev/null && break
			sleep 1
		done
		sed 's/^/# /' "$out" >&2
		# A skip decided inside the namespace has to come back out as a
		# skip: the inner exit status is lost, only INNER-DONE crosses.
		grep -q '^INNER-DONE rc=77' "$out" && \
			skip "$(sed -n 's/^SKIP: //p' "$out" | head -1)"
		grep -q '^INNER-DONE rc=0' "$out" || \
			fail "inner run failed (see above)"
		pass
	fi

	# ------------------------------------------------------- privileged --
	if [ "$(id -u)" = 0 ]; then
		SUDO=""
	elif sudo -n true 2>/dev/null; then
		SUDO="sudo -n"
	else
		skip "no user namespaces (unshare -rn) and no root or passwordless sudo"
	fi

	NS="gwpns$$"		# all three fit IFNAMSIZ (15) for any pid width
	VH="gwpvh$$"
	VN="gwpvn$$"
	NODEV="gwpnd$$"

	cleanup_priv()
	{
		# PRIV_PID/PEER_PID are only assigned once the run gets that
		# far, but this handler is installed before that: under lib.sh's
		# `set -u` a bare reference would abort it on an early exit,
		# leaving a root-owned namespace and interface behind.
		[ -n "${PRIV_PID:-}" ] && gwp_kill_priv "$PRIV_PID"
		[ -n "${PEER_PID:-}" ] && $SUDO kill "$PEER_PID" 2>/dev/null
		$SUDO "$IP" link del "$VH" 2>/dev/null
		$SUDO "$IP" netns del "$NS" 2>/dev/null
		return 0
	}
	# _cleanup exits via the EXIT trap in lib.sh; chain ours ahead of it.
	trap 'cleanup_priv; _cleanup' EXIT
	trap 'exit 143' INT TERM

	# Unlike the namespace, the host may already be using the range.
	$SUDO "$IP" -o addr show 2>/dev/null | grep -q "inet $NET\." && \
		skip "$NET.0/24 is already configured on this host"

	bail_skip() { skip "$@"; }

	peer_exec() { $SUDO "$IP" netns exec "$NS" "$@"; }

	net_setup()
	{
		$SUDO "$IP" netns add "$NS" || return 1
		$SUDO "$IP" link add "$VH" type veth peer name "$VN" || return 1
		$SUDO "$IP" link set "$VN" netns "$NS" || return 1
		$SUDO "$IP" addr add "$NET.1/24" dev "$VH" || return 1
		$SUDO "$IP" addr add "$NET.3/24" dev "$VH" || return 1
		$SUDO "$IP" link set "$VH" up || return 1
		peer_exec "$IP" addr add "$NET.2/24" dev "$VN" || return 1
		peer_exec "$IP" link set "$VN" up || return 1
		peer_exec "$IP" link set lo up || return 1
		return 0
	}

	# The origin runs as root inside the namespace, so lib.sh's EXIT trap
	# cannot reap it; cleanup_priv does, by pid.
	start_origin()
	{
		$SUDO "$IP" netns exec "$NS" bash -c \
			"python3 '$SERVERS_DIR/peer_addr.py' '$NET.2' $1 \
			 >'$WORK/peer.log' 2>&1 & echo \$! >'$WORK/peer.pid'" \
			|| return 1
		sleep 0.5
		PEER_PID="$(cat "$WORK/peer.pid" 2>/dev/null)"
		return 0
	}

	# gwproxy runs under sudo to match the root-owned plumbing, not because
	# the bind needs a capability. $! is sudo's pid rather than the proxy's,
	# so gwp_kill_priv() finds the proxy below it by /proc/<pid>/exe.
	start_gwp()
	{
		local port="$1"
		shift
		$SUDO "$GWPROXY" --bind="127.0.0.1:$port" \
			--target="$NET.2:$pa" --nr-workers=1 --log-level=3 \
			--event-loop="$loop" "$@" >"$WORK/gwp.log" 2>&1 &
		PRIV_PID=$!
		wait_listen "$port" "$PRIV_PID" || {
			sed 's/^/# gwp: /' "$WORK/gwp.log" >&2
			fail "[$loop] gwproxy did not listen on $port (args: $*)"
		}
	}

	stop_gwp() { gwp_kill_priv "${PRIV_PID:-}"; sleep 0.2; return 0; }

	finish() { pass; }
else
	# ----------------------------------------------------- unprivileged --
	ns_inner_work "$2"
	GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
	rc=1

	VH=gwpvh0		# both fit IFNAMSIZ (15); the netns is private,
	VN=gwpvn0		# so fixed names cannot collide with another run
	NODEV=gwpnd0

	# setsid put this run in its own session, so the runner's process-group
	# sweep cannot see anything started here -- it has to reap itself.
	# "kill 0" signals exactly this group: the peer namespace holder, the
	# origin, and any proxy still up. The namespace and its veth die with
	# the last process in it.
	cleanup_inner()
	{
		echo "INNER-DONE rc=$rc"
		_release_ports		# lib.sh's _cleanup, which would, is replaced
		kill 0 2>/dev/null
	}
	trap cleanup_inner EXIT

	# lib.sh's skip() exits 77, but the outer half only ever sees
	# INNER-DONE, so carry the code in rc and let the trap report it.
	bail_skip() { rc=77; echo "SKIP: $*"; exit 0; }

	peer_exec() { nsenter -t "$NSPID" -n "$@"; }

	net_setup()
	{
		local i

		"$IP" link set lo up || return 1

		# The peer namespace is held open by a parked process and
		# addressed by its pid. "ip netns add" would want to bind-mount
		# under /run/netns, which needs CAP_SYS_ADMIN in the INITIAL
		# user namespace -- the one thing we deliberately do not have.
		rm -f "$WORK/ns.pid"
		unshare -n bash -c "echo \$\$ >'$WORK/ns.pid'; \
			'$IP' link set lo up; exec sleep 600" &
		for i in $(seq 1 50); do
			[ -s "$WORK/ns.pid" ] && break
			sleep 0.1
		done
		NSPID="$(cat "$WORK/ns.pid" 2>/dev/null)"
		[ -n "$NSPID" ] || return 1

		"$IP" link add "$VH" type veth peer name "$VN" || return 1
		"$IP" link set "$VN" netns "$NSPID" || return 1
		"$IP" addr add "$NET.1/24" dev "$VH" || return 1
		"$IP" addr add "$NET.3/24" dev "$VH" || return 1
		"$IP" link set "$VH" up || return 1
		peer_exec "$IP" addr add "$NET.2/24" dev "$VN" || return 1
		peer_exec "$IP" link set "$VN" up || return 1
		return 0
	}

	# cleanup_inner reaps this with the rest of the process group.
	start_origin()
	{
		peer_exec python3 "$SERVERS_DIR/peer_addr.py" "$NET.2" "$1" \
			>"$WORK/peer.log" 2>&1 &
		return 0
	}

	start_gwp()
	{
		local port="$1"
		shift
		"$GWPROXY" --bind="127.0.0.1:$port" --target="$NET.2:$pa" \
			--nr-workers=1 --log-level=3 --event-loop="$loop" "$@" \
			>"$WORK/gwp.log" 2>&1 &
		GWP_PID=$!
		wait_listen "$port" "$GWP_PID" || {
			sed 's/^/# gwp: /' "$WORK/gwp.log" >&2
			fail "[$loop] gwproxy did not listen on $port (args: $*)"
		}
	}

	stop_gwp()
	{
		kill "${GWP_PID:-}" 2>/dev/null
		wait "${GWP_PID:-}" 2>/dev/null
		sleep 0.2
		return 0
	}

	finish() { rc=0; }
fi

# --------------------------------------------------------------- shared --

net_setup || bail_skip "cannot build the veth/netns test network"

# Connect to <host>:<port> and print the source address the far end reports,
# or nothing at all if the connection was dropped without a reply. With a
# third argument, bind that source first -- used to check that a pinned source
# is observable at all on this host before asserting that gwproxy pins one.
peer_src()
{
	python3 -c 'import socket,sys
s=socket.socket()
if len(sys.argv) > 3:
    s.bind((sys.argv[3], 0))
s.settimeout(10); s.connect((sys.argv[1], int(sys.argv[2])))
print(s.recv(64).decode().strip())' "$1" "$2" ${3:+"$3"} 2>/dev/null
}

pa="$(pick_port)"
start_origin "$pa" || bail_skip "cannot start the origin server in the namespace"

# Wait for it rather than sleeping a fixed amount. Probing too early gets an
# instant refusal -- there is no firewall in that namespace to absorb the SYN --
# which reads exactly like "the test network is unusable" and would skip every
# assertion while still reporting green. wait_listen() cannot serve here: ss in
# our namespace cannot see a listener in the peer's, so ask inside it.
origin_ready()
{
	local i
	for i in $(seq 1 100); do
		peer_exec ss -ltnH "sport = :$pa" 2>/dev/null | grep -q . && \
			return 0
		sleep 0.1
	done
	return 1
}
origin_ready || bail_skip "the origin never listened in the peer namespace"

# Establish what the kernel does on its own: every "the bind took effect"
# assertion below is a departure from this.
direct="$(peer_src "$NET.2" "$pa")"
[ "$direct" = "$NET.1" ] || \
	bail_skip "the veth test network is unusable (direct connect saw '${direct:-<none>}')"

# ...and that a pinned source is visible to the origin at all. A NAT rule
# covering the test range would rewrite it back to the interface's primary
# address, silently turning the assertions below into assertions about nothing.
pinned="$(peer_src "$NET.2" "$pa" "$NET.3")"
[ "$pinned" = "$NET.3" ] || \
	bail_skip "a pinned source is not observable here (saw '${pinned:-<none>}'; NAT on $NET.0/24?)"

printf -- '%s\n' "-A OUTPUT -j BIND --to-iface $VH" '-P OUTPUT ACCEPT' \
	>"$WORK/iface.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# The device that actually reaches the origin: traffic flows.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$VH"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] --bind-iface=$VH broke the connection (saw '${src:-<none>}')"

	# A device that cannot reach it: the connection must die rather than
	# leave by the route the kernel would have chosen.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface=lo
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ -z "$src" ] || \
		fail "[$loop] --bind-iface=lo did not pin the interface (saw '$src')"

	# Both options at once, with a source the kernel would never pick.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$VH" --bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.3" ] || \
		fail "[$loop] --bind-source with --bind-iface did not pin the source (saw '${src:-<none>}')"

	# The rule replaces the global spec wholesale. It names only an
	# interface, so it must both override the global --bind-iface=lo (which
	# would drop the connection) and leave the source at the kernel's
	# default -- inheriting the global --bind-source would show $NET.3.
	p="$(pick_port)"
	start_gwp "$p" --acl-file="$WORK/iface.acl" --bind-iface=lo \
		--bind-source="$NET.3"
	src="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ "$src" = "$NET.1" ] || \
		fail "[$loop] -j BIND did not replace the global bind wholesale (saw '${src:-<none>}')"

	# A device that does not exist yet is accepted at startup but is strict
	# per connection. Dropping the connection must be all it does: the
	# failed bind belongs to that one client, so the proxy has to keep
	# listening and drop the next one the same way.
	p="$(pick_port)"
	start_gwp "$p" --acl-allow-all --bind-iface="$NODEV"
	src="$(peer_src 127.0.0.1 "$p")"
	sleep 0.3
	alive=0
	ss -ltnH "sport = :$p" 2>/dev/null | grep -q . && alive=1
	src2="$(peer_src 127.0.0.1 "$p")"
	stop_gwp
	[ -z "$src" ] || \
		fail "[$loop] a nonexistent --bind-iface was not strict (saw '$src')"
	[ "$alive" = 1 ] || \
		fail "[$loop] a failed --bind-iface bind stopped the proxy"
	[ -z "$src2" ] || \
		fail "[$loop] a nonexistent --bind-iface was not strict on reuse (saw '$src2')"
done

finish

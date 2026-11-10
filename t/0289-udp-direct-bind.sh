#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The direct SOCKS5 UDP relay (no upstream pool) must send its datagrams to
# the targets the way a TCP connection to them would go: from --bind-source,
# out of --bind-iface, with --mark, and with what an ACL -j BIND or -j MARK
# rule decides for each target. Its socket is bound to the wildcard address
# and also talks to the client, so none of that was applied to it: the
# datagrams left from routing's source, out of routing's interface, and a
# tunnel set up with these options leaked UDP past itself. --mark, set on
# the whole socket, marked the datagrams to the client as well, which the
# TCP path never does: policy routing by the mark took them away from the
# client. Through a pool server, the datagrams to its relay carry the mark
# of the control connection to it, the socket having none of its own now.
#
# The test network, in a private network namespace: a veth pair to a peer
# namespace holding the targets, our end with a second IPv4 and IPv6
# address that the kernel never picks by itself, and a dummy interface
# that swallows what routing sends to 198.51.100.0/24 and 2001:db8:51::/64.
# The peer has those addresses too, so a datagram reaches them only when
# it is sent out of the veth: by --bind-iface (IPv4), or by a mark that a
# policy routing rule sends that way. The targets answer with the source
# address they saw. On every event loop.
#
# The namespace is a user+network one where it can be had, else a network
# one under passwordless sudo; the test is skipped without either. The mark
# needs CAP_NET_ADMIN, which both give in the namespace.

. "$(dirname "$0")/lib.sh"
require python3

NET=192.0.2		# RFC 5737 TEST-NET-1: the veth
FAR=198.51.100		# RFC 5737 TEST-NET-2: behind the dummy, and the peer
NET6=2001:db8:2		# RFC 3849
FAR6=2001:db8:51

if [ "${1:-}" != --inner ]; then
	require unshare
	require nsenter
	require ip
	out="$WORK/inner.out"
	ns_drop_setup
	if $NS_DROP unshare -rn true 2>/dev/null; then
		timeout 300 $NS_DROP unshare -rn "$0" --inner "$WORK" \
			"$GWPROXY" </dev/null >"$out" 2>&1
	else
		# Root (or passwordless sudo) helps only where it may make a
		# namespace: a container's root often may not.
		S=""
		[ "$(id -u)" = 0 ] || S="sudo -n"
		$S unshare -n true 2>/dev/null ||
			skip "no network namespaces here (unshare -rn and unshare -n refused)"
		timeout 300 $S unshare -n "$0" --inner "$WORK" "$GWPROXY" \
			</dev/null >"$out" 2>&1
	fi
	sed 's/^/# /' "$out" >&2
	grep -q '^SKIP-INNER' "$out" && \
		skip "$(sed -n 's/^SKIP-INNER: //p' "$out" | head -1)"
	grep -q '^PASS-INNER' "$out" && pass
	fail "inner run failed (see above)"
fi

ns_inner_work "$2"
GWPROXY="$3"
VH=gwpvh0		# the namespace is private: fixed names cannot collide
VN=gwpvn0
DUM=gwpdum0
NSPID=

inner_cleanup()
{
	gwp_stop_pids "${_PIDS[@]}"
	[ -n "$NSPID" ] && kill "$NSPID" 2>/dev/null
	_release_ports
	return 0
}
trap inner_cleanup EXIT

inner_skip() { echo "SKIP-INNER: $*"; exit 0; }

peer_exec() { nsenter -t "$NSPID" -n "$@"; }

net_setup()
{
	local i

	ip link set lo up || return 1
	# The peer namespace is held by a parked process, addressed by pid:
	# "ip netns add" would want to mount under /run/netns.
	unshare -n bash -c "echo \$\$ >'$WORK/ns.pid'; exec sleep 600" \
		</dev/null >/dev/null 2>&1 &
	for i in $(seq 1 50); do
		[ -s "$WORK/ns.pid" ] && break
		sleep 0.1
	done
	NSPID="$(cat "$WORK/ns.pid" 2>/dev/null)"
	[ -n "$NSPID" ] || return 1

	ip link add "$VH" type veth peer name "$VN" || return 1
	ip link set "$VN" netns "$NSPID" || return 1
	ip addr add "$NET.1/24" dev "$VH" || return 1
	ip addr add "$NET.3/24" dev "$VH" || return 1
	ip -6 addr add "$NET6::1/64" dev "$VH" nodad || return 1
	# Deprecated: never picked as a source, but still one to bind.
	ip -6 addr add "$NET6::3/64" dev "$VH" nodad preferred_lft 0 || \
		return 1
	ip link set "$VH" up || return 1
	ip link add "$DUM" type dummy || return 1
	ip link set "$DUM" up || return 1
	ip route add "$FAR.0/24" dev "$DUM" || return 1
	ip -6 route add "$FAR6::/64" dev "$DUM" || return 1

	peer_exec ip link set lo up || return 1
	peer_exec ip addr add "$NET.2/24" dev "$VN" || return 1
	peer_exec ip addr add "$FAR.2/32" dev "$VN" || return 1
	peer_exec ip -6 addr add "$NET6::2/64" dev "$VN" nodad || return 1
	peer_exec ip -6 addr add "$FAR6::2/128" dev "$VN" nodad || return 1
	peer_exec ip link set "$VN" up || return 1

	# A mark of 0x29 routes the far networks out of the veth, and our
	# own network into the dummy: a datagram to the client in the peer
	# namespace that carries it is lost.
	ip rule add fwmark 0x29 lookup 29 || return 1
	ip route add "$FAR.0/24" dev "$VH" table 29 || return 1
	ip route add "$NET.0/24" dev "$DUM" table 29 || return 1
	ip -6 rule add fwmark 0x29 lookup 29 || return 1
	ip -6 route add "$FAR6::/64" dev "$VH" table 29 || return 1
	return 0
}

net_setup || inner_skip "cannot build the veth/netns test network"

# Not through peer_exec: a function run in the background is a subshell,
# whose pid is not the server's.
nsenter -t "$NSPID" -n python3 "$SERVERS_DIR/udp_src_echo.py" :: 0 \
	>"$WORK/echo.log" 2>&1 &
_PIDS+=("$!")
for i in $(seq 1 100); do
	ep="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$WORK/echo.log")"
	[ -n "$ep" ] && break
	sleep 0.05
done
[ -n "$ep" ] || { cat "$WORK/echo.log" >&2; fail "the target did not start"; }

loops()
{
	echo epoll
	have_io_uring && echo io_uring
}

# probe <want> <target>... -- [gwproxy options]: start a proxy with the
# options, send to each target ("ip"; the echo port is added) through one
# association from 127.0.0.1, and compare the answers, one per target
# ("<source seen>" or NONE), with <want>, a space separated list.
# With PROBE_PEER=1 the client is in the peer namespace, and the proxy
# listens on $NET.1 instead. The proxy's log is left in $PROBE_LOG.
probe()
{
	local want="$1" t=() got p bind=127.0.0.1 run=() proxy=127.0.0.1
	shift
	while [ "$1" != -- ]; do
		t+=("$1" "$ep")
		shift
	done
	shift
	if [ "${PROBE_PEER:-0}" = 1 ]; then
		bind="$NET.1"
		proxy="$NET.1"
		run=(peer_exec)
	fi
	p="$(pick_port)"
	gwp_start "$bind:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4 "$@"
	got="$("${run[@]}" timeout 120 python3 "$SERVERS_DIR/socks5_udp_src.py" \
		--proxy "$proxy" "$p" "${t[@]}" | sed 's/^SRC //' | tr '\n' ' ')"
	gwp_stop_pids "$GWP_PID"
	PROBE_LOG="$WORK/gwp.$p.log"
	got="${got% }"
	if [ "$got" != "REP 0 $want" ]; then
		sed 's/^/# gwp: /' "$WORK/gwp.$p.log" | tail -n 30 >&2
		fail "[$loop $*] to ${t[*]}: got '$got', want 'REP 0 $want'"
	fi
	echo "ok [$loop $*]: $want"
}

# acl <name> <rule>...: write an ACL file of the rules; print its path.
acl()
{
	local f="$WORK/$1.acl"

	shift

	printf '%s\n' "$@" '-P OUTPUT ACCEPT' >"$f"
	chmod 600 "$f"
	echo "$f"
}

# Sanity: routing on its own sends the far addresses into the dummy, and
# a pinned source is seen as it is.
sanity="$(python3 -c 'import socket,sys
for d, s in ((sys.argv[1], None), (sys.argv[2], None), (sys.argv[1], sys.argv[3])):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if s: u.bind((s, 0))
    u.settimeout(2); u.sendto(b"x", (d, int(sys.argv[4])))
    try: print(u.recv(64).decode())
    except OSError: print("NONE")' "$NET.2" "$FAR.2" "$NET.3" "$ep" | tr '\n' ' ')"
[ "$sanity" = "$NET.1 NONE $NET.3 " ] || \
	inner_skip "the test network does not behave as built (saw '$sanity')"

for loop in $(loops); do
	probe "$NET.1 $NET6::1 NONE NONE" "$NET.2" "$NET6::2" "$FAR.2" "$FAR6::2" --

	# --bind-source; an IPv4 one does not apply to an IPv6 target.
	probe "$NET.3 $NET6::1" "$NET.2" "$NET6::2" -- --bind-source="$NET.3"
	probe "$NET.1 $NET6::3" "$NET.2" "$NET6::2" -- --bind-source="$NET6::3"

	# --bind-iface: out of the veth even where routing says otherwise,
	# and nowhere when it cannot get there.
	probe "$NET.1 $NET.1 $NET6::1" "$NET.2" "$FAR.2" "$NET6::2" -- \
		--bind-iface="$VH"
	probe "NONE NONE" "$NET.2" "$NET6::2" -- --bind-iface=lo
	probe "$NET.3 $NET.3 $NET6::1" "$NET.2" "$FAR.2" "$NET6::2" -- \
		--bind-iface="$VH" --bind-source="$NET.3"
	# An IPv6 datagram cannot be held to both: it is not sent.
	probe "$NET.1 NONE" "$NET.2" "$NET6::2" -- \
		--bind-iface="$VH" --bind-source="$NET6::3"

	# -j BIND per target, replacing the defaults wholesale: the rule for
	# $NET.2 names no interface, the one for $FAR.2 no source, and the
	# IPv6 target, with no rule, keeps --bind-iface=lo.
	f="$(acl bind "-A OUTPUT -d $NET.2 -j BIND --to-source $NET.3" \
		"-A OUTPUT -d $FAR.2 -j BIND --to-iface $VH")"
	probe "$NET.3 $NET.1 NONE $NET.3" "$NET.2" "$FAR.2" "$NET6::2" "$NET.2" \
		-- --acl-file="$f" --bind-iface=lo --bind-source="$NET.1"

	# -j MARK per target, and --mark.
	f="$(acl mark "-A OUTPUT -d $FAR.2 -j MARK --set-mark 0x29")"
	probe "$NET.1 NONE $NET.1" "$FAR.2" "$FAR6::2" "$NET.2" -- \
		--acl-file="$f"
	probe "$NET.1 $NET6::1" "$FAR.2" "$FAR6::2" -- --mark=0x29
	# ...and -j MARK overrides it.
	f="$(acl remark "-A OUTPUT -d $FAR.2 -j MARK --set-mark 0x30")"
	probe "NONE $NET6::1" "$FAR.2" "$FAR6::2" -- --acl-file="$f" \
		--mark=0x29

	# The datagrams to the client are not marked: with the client in the
	# peer namespace, a marked one is lost in the dummy.
	PROBE_PEER=1 probe "$NET.1 $NET6::1" "$FAR.2" "$FAR6::2" -- --mark=0x29
	PROBE_PEER=1 probe "$NET.1" "$NET.2" -- --bind-iface=lo \
		--acl-file="$(acl peer "-A OUTPUT -d $NET.2 -j BIND --to-iface $VH")"

	# Through a pool server on $FAR.2, which only a mark reaches: the
	# datagrams to its relay carry the control connection's mark.
	up="$(pick_port)"
	nsenter -t "$NSPID" -n "$GWPROXY" --bind="$FAR.2:$up" --as-socks5=1 \
		--acl-allow-all --event-loop="$loop" --nr-workers=1 \
		--log-level=4 >"$WORK/up.$up.log" 2>&1 &
	up_pid=$!
	_PIDS+=("$up_pid")
	for i in $(seq 1 100); do
		peer_exec ss -ltnH "sport = :$up" 2>/dev/null | grep -q . && break
		kill -0 "$up_pid" 2>/dev/null || break
		sleep 0.1
	done
	f="$(acl pool "upstream p {" "	server socks5://$FAR.2:$up;" "}" \
		"-A OUTPUT -j UPSTREAM --to p")"
	probe "$NET.2" "$NET.2" -- --acl-file="$f" --mark=0x29
	grep -q 'Upstream UDP association established' "$PROBE_LOG" || \
		fail "[$loop] the association did not go through the pool"
	gwp_stop_pids "$up_pid"
done

echo PASS-INNER

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --as-transparent has no --target: the destination is the connection's
# SO_ORIGINAL_DST. An upstream that resolves names (socks5h://, http://) must
# be asked for that address like a socks5:// one, and neither may bring the
# proxy down when the first redirected client arrives. Runs on every event
# loop, in a private network namespace, as the REDIRECT rule and the conntrack
# entry behind SO_ORIGINAL_DST need one; skipped where it cannot be had.

. "$(dirname "$0")/lib.sh"
require python3
require ss
require ip
require_opt "--upstream-proxy"

IPT="$(command -v iptables 2>/dev/null || echo /usr/sbin/iptables)"
[ -x "$IPT" ] || skip "iptables not available"

if [ "${1:-}" != --inner ]; then
	ns_drop_setup
	$NS_DROP unshare -rn true 2>/dev/null || \
		skip "no user namespaces (unshare -rn)"
	$NS_DROP unshare -rn "$0" --inner "$WORK"
	r=$?
	[ "$r" = 0 ] && pass
	[ "$r" = "$SKIP_CODE" ] && exit "$r"
	fail "inner run failed"
fi

ns_inner_work "$2"
trap '_inner_cleanup' EXIT
_inner_cleanup()
{
	local pid
	for pid in "${_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
	done
	_release_ports
}

ip link set lo up || skip "cannot bring up lo in the namespace"

DPORT=7777			# what the clients aim at; never reached
PP="$(pick_port)"
"$IPT" -t nat -A OUTPUT -p tcp -d 127.0.0.2 --dport "$DPORT" \
	-j REDIRECT --to-ports "$PP" 2>"$WORK/ipt.err" \
	|| skip "cannot add a REDIRECT rule: $(cat "$WORK/ipt.err")"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scheme in socks5h http socks5; do
		kind=socks5
		want="atyp=1 addr=127.0.0.2 port=$DPORT"
		if [ "$scheme" = http ]; then
			kind=http
			want="authority=127.0.0.2:$DPORT"
		fi

		rlog="$WORK/up.$loop.$scheme.log"
		: >"$rlog"
		up="$(pick_port)"
		python3 "$SERVERS_DIR/stub_upstream.py" "$kind" "$up" "$rlog" \
			>"$WORK/up.err" 2>&1 &
		up_pid=$!
		_PIDS+=("$up_pid")
		wait_listen "$up" "$up_pid" || fail "stub upstream did not listen"

		glog="$WORK/gwp.$loop.$scheme.log"
		"$GWPROXY" --bind="127.0.0.1:$PP" --as-transparent=1 \
			--upstream-proxy="$scheme://127.0.0.1:$up" \
			--event-loop="$loop" --nr-workers=1 --acl-allow-all \
			--log-level=3 >"$glog" 2>&1 &
		gwp_pid=$!
		_PIDS+=("$gwp_pid")
		wait_listen "$PP" "$gwp_pid" \
			|| { sed 's/^/# gwp: /' "$glog" >&2; fail "[$loop/$scheme] gwproxy did not listen"; }

		got="$(python3 - "$DPORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.2", int(sys.argv[1])), timeout=20)
s.settimeout(20)
buf = b""
try:
    while b"\n" not in buf:
        d = s.recv(100)
        if not d:
            break
        buf += d
except OSError as e:
    print("error", e)
print(buf.decode(errors="replace").strip())
PY
)"
		[ "$got" = UPSTREAM-TUNNEL ] || {
			sed 's/^/# gwp: /' "$glog" | tail -20 >&2
			kill -0 "$gwp_pid" 2>/dev/null \
				|| fail "[$loop/$scheme] the first redirected client took the proxy down"
			fail "[$loop/$scheme] the client got '$got' through the upstream"
		}
		kill -0 "$gwp_pid" 2>/dev/null \
			|| fail "[$loop/$scheme] gwproxy died after the tunnel came up"
		seen="$(head -1 "$rlog")"
		case "$seen" in
		*" $want") ;;
		*) fail "[$loop/$scheme] upstream was asked for '$seen', want '$want'" ;;
		esac

		kill "$gwp_pid" "$up_pid" 2>/dev/null
		wait "$gwp_pid" "$up_pid" 2>/dev/null
	done
done

exit 0

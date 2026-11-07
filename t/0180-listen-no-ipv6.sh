#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Listening on a host without IPv6.
#
# On a kernel without IPv6 (booted with ipv6.disable=1) every AF_INET6 socket is
# refused, and gwproxy did not start with its default --bind, [::]:1080, nor
# with any other [::] bind. A wildcard [::] bind now listens on 0.0.0.0 with a
# warning; an IPv6 address, or [::] with --bind-ipv6-only=1, fails at startup
# with a message that says why. A seccomp filter stands in for that kernel, as
# in t/0148, on both event loops. The default bind is checked in a private
# network namespace, where its fixed port 1080 is free.
#
# A host that has IPv6 but turned it off with the disable_ipv6 sysctl still
# listens on [::] (dual-stack), while a bind to [::1] fails; the message then
# points at IPv6 being disabled. Checked in a private network namespace too.

. "$(dirname "$0")/lib.sh"
require python3

noipv6="$SERVERS_DIR/no_ipv6_exec.py"

# The filter must really work here, or this test proves nothing. The helper exits
# 77 where it cannot be installed; the nested python exits 3 if IPv6 still works.
r=0
python3 "$noipv6" "$(command -v python3)" -c '
import errno, socket, sys
try:
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
except OSError as e:
    sys.exit(0 if e.errno == errno.EAFNOSUPPORT else 3)
sys.exit(3)' || r=$?
[ "$r" != 77 ] || skip "cannot install a seccomp filter here"
[ "$r" = 0 ] || fail "the filter did not refuse AF_INET6 sockets ($r)"

real="$GWPROXY"
GWPROXY="$WORK/gwproxy-noipv6"
printf '#!/bin/sh\nexec python3 "%s" "%s" "$@"\n' "$noipv6" "$real" >"$GWPROXY"
chmod +x "$GWPROXY"

# socks5_ok <port>: a SOCKS5 CONNECT through 127.0.0.1:<port> to an IPv4 target
# of its own gets the target's banner.
socks5_ok()
{
	python3 - "$1" <<-'PY'
	import socket, struct, sys, threading
	ls = socket.socket()
	ls.bind(("127.0.0.1", 0))
	ls.listen(1)
	def serve():
	    c, _ = ls.accept()
	    c.sendall(b"banner")
	    c.close()
	threading.Thread(target=serve, daemon=True).start()
	c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
	c.sendall(b"\x05\x01\x00")
	assert c.recv(2) == b"\x05\x00"
	c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
	          struct.pack("!H", ls.getsockname()[1]))
	rep = c.recv(10)
	assert rep[:2] == b"\x05\x00", rep
	got = b""
	while len(got) < 6:
	    d = c.recv(64)
	    if not d:
	        break
	    got += d
	sys.exit(0 if got == b"banner" else 1)
	PY
}

# start_fail <expected message> <args...>: gwproxy must exit non-zero at startup
# and log the message.
start_fail()
{
	local want="$1" log="$WORK/fail.log" rc=0
	shift

	timeout 20 "$GWPROXY" --nr-workers=1 --as-socks5=1 "$@" >"$log" 2>&1 || rc=$?
	[ "$rc" != 0 ] && [ "$rc" != 124 ] \
		|| { sed 's/^/# gwp: /' "$log" >&2; fail "started with $* (rc=$rc)"; }
	grep -qF -- "$want" "$log" \
		|| { sed 's/^/# gwp: /' "$log" >&2; fail "no \"$want\" with $*"; }
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# The wildcard falls back to IPv4, and says so.
	pp="$(pick_port)"
	gwp_start "[::]:$pp" --as-socks5=1 --event-loop="$loop" --nr-workers=1
	grep -qF "IPv6 is not available on this host: listening on 0.0.0.0:$pp, IPv4 only, instead of [::]:$pp" \
		"$WORK/gwp.$pp.log" || fail "[$loop] no notice of the IPv4 fallback"
	socks5_ok "$pp" || fail "[$loop] the IPv4 fallback does not serve"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	# An IPv6 address cannot be had, nor IPv6 alone.
	pp="$(pick_port)"
	start_fail "Cannot listen on [::1]:$pp: IPv6 is not available on this host" \
		--event-loop="$loop" --bind="[::1]:$pp"
	start_fail "Cannot listen on [::]:$pp: IPv6 is not available on this host" \
		--event-loop="$loop" --bind="[::]:$pp" --bind-ipv6-only=1
done

# The default bind and the disable_ipv6 sysctl, in a network namespace of
# their own.
ns_drop_setup
if ! $NS_DROP unshare -rn true 2>/dev/null; then
	diag "no user+net namespaces (unshare -rn): default bind not checked"
	pass
fi

out="$($NS_DROP unshare -rn bash -s "$GWPROXY" "$real" "$WORK" <<'SH' 2>&1
noipv6_gwp="$1" real="$2" work="$3"
ip link set lo up || { echo "lo did not come up"; exit 1; }

# run_until <log> <line> <cmd...>: run <cmd> until <line> is in <log>, then
# check that it serves a SOCKS5 greeting on 127.0.0.1:1080.
run_until()
{
	local log="$1" want="$2" pid i ok=0
	shift 2

	"$@" >"$log" 2>&1 &
	pid=$!
	for i in $(seq 1 100); do
		grep -qF -- "$want" "$log" && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	grep -qF -- "$want" "$log" && python3 -c '
import socket
c = socket.create_connection(("127.0.0.1", 1080), timeout=10)
c.sendall(b"\x05\x01\x00")
assert c.recv(2) == b"\x05\x00"' && ok=1
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	[ "$ok" = 1 ] || { sed 's/^/gwp: /' "$log"; return 1; }
}

run_until "$work/ns-default.log" "Worker 0 is listening on 0.0.0.0:1080" \
	"$noipv6_gwp" --nr-workers=1 --as-socks5=1 \
	|| { echo "the default bind did not fall back to IPv4"; exit 1; }
grep -qF "listening on 0.0.0.0:1080, IPv4 only, instead of [::]:1080" \
	"$work/ns-default.log" || { echo "no notice of the fallback"; exit 1; }

if ! { echo 1 >/proc/sys/net/ipv6/conf/all/disable_ipv6 &&
       echo 1 >/proc/sys/net/ipv6/conf/lo/disable_ipv6; } 2>/dev/null; then
	echo "SYSCTL-SKIP"
	exit 0
fi

# IPv6 turned off: the wildcard is still dual-stack, [::1] is not there.
run_until "$work/ns-sysctl.log" "Worker 0 is listening on [::]:1080" \
	"$real" --nr-workers=1 --as-socks5=1 \
	|| { echo "the default bind failed with IPv6 disabled"; exit 1; }
rc=0
timeout 20 "$real" --nr-workers=1 --as-socks5=1 --bind='[::1]:1080' \
	>"$work/ns-v6.log" 2>&1 || rc=$?
[ "$rc" != 0 ] && [ "$rc" != 124 ] || { echo "[::1] did not fail (rc=$rc)"; exit 1; }
grep -qF "Failed to bind [::1]:1080: Cannot assign requested address (is IPv6 disabled on this host?)" \
	"$work/ns-v6.log" || { sed 's/^/gwp: /' "$work/ns-v6.log"; echo "no clear message for [::1]"; exit 1; }
echo "NS-OK"
SH
)" || { printf '%s\n' "$out" | sed 's/^/# /' >&2; fail "namespace checks failed"; }
case "$out" in
*SYSCTL-SKIP*) diag "cannot set disable_ipv6 in a namespace here: not checked" ;;
*NS-OK*) ;;
*) printf '%s\n' "$out" | sed 's/^/# /' >&2; fail "namespace checks did not finish" ;;
esac

pass

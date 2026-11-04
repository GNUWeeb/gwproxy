#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An attempt timer that expires just as the pair is torn down must not start
# another connect. Teardown has cancelled what was in flight by then, nothing
# would cancel the new attempt, and its reference would hold the client
# connection, its buffers and the target socket for as long as the kernel
# retries the SYN, about two minutes.
#
# A name with two black-holed addresses and --connect-attempt-delay just above
# --connect-timeout make the two timers expire a millisecond apart, for many
# connections at once. Every client must get REP 0x06, and the proxy must be
# back to its idle descriptor count soon after, on both event loops.
#
# Controlling which addresses a name has means controlling /etc/hosts, so the
# body runs in a private user+mount+net namespace, as t/0063 does.

. "$(dirname "$0")/lib.sh"
require python3
require unshare
require ip

if [ "${1:-}" != "--inner" ]; then
	ns_drop_setup
	$NS_DROP unshare -rmn --map-root-user true 2>/dev/null \
		|| skip "no user+mount+net namespaces (unshare -rmn) available"
	out="$WORK/inner.out"
	setsid $NS_DROP unshare -rmn --map-root-user "$0" --inner "$WORK" \
		</dev/null >"$out" 2>&1 &
	for i in $(seq 1 150); do
		grep -q '^INNER-DONE' "$out" 2>/dev/null && break
		sleep 1
	done
	sed 's/^/# /' "$out" >&2
	grep -q '^INNER-DONE rc=77' "$out" && skip "see the inner run above"
	grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
	pass
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
rc=1

cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	_release_ports
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

ip link set lo up || exit 1

printf '127.0.0.8 two-holes\n127.0.0.9 two-holes\n' >"$WORK/hosts"
cat /etc/hosts >>"$WORK/hosts"
mount --bind "$WORK/hosts" /etc/hosts || { rc=77; exit 0; }

# On the wildcard address, so that the one full accept queue drops SYNs to both.
python3 "$SERVERS_DIR/blackhole_listener.py" 0.0.0.0 >"$WORK/bh.port" 2>"$WORK/bh.log" &
for _ in $(seq 1 100); do
	bport="$(cat "$WORK/bh.port" 2>/dev/null)"
	[ -n "$bport" ] && break
	sleep 0.1
done
[ -n "${bport:-}" ] || { echo "black hole did not start"; exit 1; }

ulimit -n 4096 2>/dev/null

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	"$GWPROXY" --bind=127.0.0.1:"$pp" --as-socks5=1 --nr-workers=1 \
		--acl-allow-all --event-loop="$loop" --protocol-timeout=60 \
		--connect-timeout=1 --connect-attempt-delay=1001 --log-level=2 \
		>"$WORK/gwp.$loop.log" 2>&1 &
	gwp_pid=$!
	wait_listen "$pp" "$gwp_pid" || { echo "[$loop] gwproxy did not listen"; exit 1; }

	timeout 100 python3 - "$pp" "$gwp_pid" "$bport" <<-'PY' || { echo "[$loop] failed"; exit 1; }
	import os, select, socket, struct, sys, time
	port, pid, bport = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
	N = 300

	def fds():
	    return len(os.listdir("/proc/%d/fd" % pid))

	base = fds()
	cs = []
	for _ in range(N):
	    c = socket.create_connection(("127.0.0.1", port), timeout=30)
	    c.sendall(b"\x05\x01\x00")
	    if c.recv(2) != b"\x05\x00":
	        sys.exit("no greeting reply")
	    cs.append(c)
	name = b"two-holes"
	req = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", bport)
	for c in cs:
	    c.sendall(req)

	# Each client gets its REP 0x06 at the connect timeout.
	for c in cs:
	    c.settimeout(30)
	    rep = c.recv(10)
	    if rep[1:2] != b"\x06":
	        sys.exit("got %r, want REP 0x06" % rep)
	for c in cs:
	    c.close()

	# Well below the time a SYN is retried for.
	end = time.monotonic() + 30
	while fds() > base and time.monotonic() < end:
	    time.sleep(0.25)
	n = fds()
	if n > base:
	    sys.exit("%d descriptors open 30 s after the last reply, %d idle" %
	             (n, base))
	PY
	kill -0 "$gwp_pid" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	kill "$gwp_pid" 2>/dev/null
	wait "$gwp_pid" 2>/dev/null
	echo "[$loop] ok"
done

rc=0

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that sends more than the proxy's buffer holds behind a request whose
# name is still being resolved, sends its FIN, and waits for the answer. That is
# a working half-close, and nothing tells it apart from a client that has gone:
# the FIN must not end the pair. The target must get every byte and the FIN, the
# client the target's answer, and the pair must then go away. Run on both loops,
# with and without a connect timeout.
#
# The answer is held back until the client has done all that, so nothing here
# depends on how long a lookup takes. Controlling the resolver takes a resolv.conf
# of our own and a port 53, so the body runs in a private user+mount+net namespace;
# no name leaves it.

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

printf 'nameserver 127.0.0.1\noptions timeout:30 attempts:1\n' >"$WORK/resolv.conf"
mount --bind "$WORK/resolv.conf" /etc/resolv.conf || { rc=77; exit 0; }
# Keep every lookup on the server below, whatever the host's NSS would ask.
if [ -e /etc/nsswitch.conf ]; then
	printf 'hosts: files dns\n' >"$WORK/nsswitch.conf"
	mount --bind "$WORK/nsswitch.conf" /etc/nsswitch.conf || exit 1
fi

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for ct in 30 0; do
		names="$WORK/names.$loop.$ct"
		release="$WORK/release.$loop.$ct"
		python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" \
			>"$WORK/dns.$loop.$ct" 2>&1 &
		dns=$!
		for _ in $(seq 1 100); do
			grep -q READY "$WORK/dns.$loop.$ct" && break
			sleep 0.1
		done
		grep -q READY "$WORK/dns.$loop.$ct" || { echo "no DNS server"; exit 1; }

		p="$(pick_port)"
		gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --client-buf-size=4096 \
			--protocol-timeout=60 --connect-timeout="$ct"

		out="$(timeout 90 python3 - "$p" "$GWP_PID" "$names" "$release" <<-'PY'
		import os, socket, struct, sys, threading, time
		port, pid, names, release = int(sys.argv[1]), int(sys.argv[2]), *sys.argv[3:5]
		N = 16384

		def fds():
		    return len(os.listdir("/proc/%d/fd" % pid))

		base = fds()

		# The origin answers with what reached it, once it has seen the FIN.
		ls = socket.socket()
		ls.bind(("127.0.0.1", 0))
		ls.listen(1)
		def origin():
		    o, _ = ls.accept()
		    got = 0
		    while True:
		        d = o.recv(65536)
		        if not d:
		            break
		        got += len(d)
		    o.sendall(b"got %d" % got)
		    o.close()
		threading.Thread(target=origin, daemon=True).start()

		c = socket.create_connection(("127.0.0.1", port), timeout=30)
		c.sendall(b"\x05\x01\x00")
		if c.recv(2) != b"\x05\x00":
		    sys.exit("no greeting reply")
		name = b"hold.example"
		c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
		          struct.pack(">H", ls.getsockname()[1]))
		end = time.monotonic() + 30
		while not (os.path.exists(names) and "hold" in open(names).read()):
		    if time.monotonic() > end:
		        sys.exit("the lookup did not start")
		    time.sleep(0.05)

		c.sendall(b"x" * N)
		time.sleep(0.5)
		c.shutdown(socket.SHUT_WR)
		time.sleep(1)
		open(release, "w").close()

		buf = b""
		try:
		    while True:
		        d = c.recv(256)
		        if not d:
		            break
		        buf += d
		except OSError as e:
		    sys.exit("%s after %r" % (e, buf))
		if buf[:2] != b"\x05\x00":
		    sys.exit("got %r, want a success reply" % buf)
		if buf[10:] != b"got %d" % N:
		    sys.exit("the client got %r, want the origin's count of %d" % (buf, N))
		c.close()
		end = time.monotonic() + 30
		while fds() > base and time.monotonic() < end:
		    time.sleep(0.05)
		if fds() > base:
		    sys.exit("%d descriptors left after the pair ended" % (fds() - base))
		print("ok")
		PY
		)" || { echo "[$loop connect-timeout=$ct] $out"; exit 1; }
		[ "$out" = ok ] || { echo "[$loop connect-timeout=$ct] $out"; exit 1; }

		kill "$GWP_PID" "$dns" 2>/dev/null
		wait "$GWP_PID" "$dns" 2>/dev/null
	done
done

rc=0
exit 0

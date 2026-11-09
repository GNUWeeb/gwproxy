#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The getaddrinfo() threads are shared between client addresses. Each blocks in
# one lookup, and clients pick the names, so a single client asking for names
# that take long to answer used to occupy all of them and queue the rest of its
# requests in front of everyone: about 100 such requests a second stopped
# uncached lookups for every client of the proxy. Asserted here, on both loops:
#
#   (a) one client gets no more than half of the threads, and another client's
#       lookup is answered with all of the first one's still blocked;
#   (b) a name another client wants does not wait behind a long queue that it
#       happens to be queued in;
#   (c) two clients flooding together leave threads for a third, which is also
#       answered with all of theirs still blocked;
#   (d) nothing is lost: every request is answered once the names resolve.
#
# The answers are held back until the test has seen what it wants, so nothing
# depends on how long a lookup takes; the limits only have to be shorter than
# the resolver's own timeout of 30 s. Controlling the resolver takes a
# resolv.conf of our own and a port 53, so the body runs in a private
# user+mount+net namespace; no name leaves it.

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
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	names="$WORK/names.$loop"
	release="$WORK/release.$loop"
	python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns.$loop" 2>&1 &
	dns_pid=$!
	for i in $(seq 1 100); do
		grep -q READY "$WORK/dns.$loop" 2>/dev/null && break
		sleep 0.05
	done
	grep -q READY "$WORK/dns.$loop" || { echo "DNS server did not start"; exit 1; }

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout=120

	echo "[$loop]"
	timeout 120 python3 - "$p" "$GWP_PID" "$names" "$release" <<'PY' || exit 1
import os, socket, struct, sys, time

port, names_file, release_file = int(sys.argv[1]), sys.argv[3], sys.argv[4]
# Short of the resolver's 30 s, so a lookup that has to wait for a held one to
# end does not get its answer in time.
LIMIT = 20
THREADS = 64
FLOOD = 200


def die(msg):
    print(msg)
    sys.exit(1)


def request(src, name):
    c = socket.socket()
    c.settimeout(LIMIT)
    c.bind((src, 0))
    c.connect(("127.0.0.1", port))
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", 9))
    return c


def answered(c, what):
    """An address came back, so the connect was tried: 0x00 or refused, 0x05."""
    try:
        rep = c.recv(10)
    except OSError as e:
        die("%s: no answer: %s" % (what, e))
    if rep[:2] not in (b"\x05\x00", b"\x05\x05"):
        die("%s: reply %r" % (what, rep))


def names_seen():
    with open(names_file) as f:
        return f.read().split()


def wait_quiet(prefix):
    """How many names with @prefix have started, once they stop coming."""
    last, since = -1, time.monotonic()
    while time.monotonic() - since < 1.5:
        n = len([x for x in names_seen() if x.startswith(prefix)])
        if n != last:
            last, since = n, time.monotonic()
        time.sleep(0.05)
    return last


flood = [request("127.0.0.2", b"hold-a-%d.dns-share.invalid" % i) for i in range(FLOOD)]
# Its last name stays deep in the queue, for (b).
flood.append(request("127.0.0.2", b"hold-shared.dns-share.invalid"))

# (a) The client gets its share of the threads and no more...
n = wait_quiet("hold-a-")
if not 1 <= n <= THREADS // 2:
    die("one client runs %d lookups at once, of %d threads" % (n, THREADS))
if "hold-shared.dns-share.invalid" in names_seen():
    die("the last name of the queue has started")

# ...and the others do not notice.
c = request("127.0.0.3", b"other.dns-share.invalid")
answered(c, "another client's lookup")
c.close()

# (b) That name starts as soon as another client asks for it.
shared = request("127.0.0.3", b"hold-shared.dns-share.invalid")
end = time.monotonic() + LIMIT
while "hold-shared.dns-share.invalid" not in names_seen():
    if time.monotonic() > end:
        die("a name another client wants waits behind the first one's queue")
    time.sleep(0.05)

# (c) A second client takes all it can, and a third still gets through.
flood2 = [request("127.0.0.4", b"hold-b-%d.dns-share.invalid" % i) for i in range(FLOOD)]
n = wait_quiet("hold-b-")
if n < 1:
    die("the second client's lookups did not start")
c = request("127.0.0.5", b"third.dns-share.invalid")
answered(c, "a third client's lookup")
c.close()

# (d) Everything is answered in the end.
open(release_file, "w").close()
for i, c in enumerate(flood + [shared] + flood2):
    answered(c, "request %d after the release" % i)
    c.close()
print("OK")
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	kill "$GWP_PID" "$dns_pid" 2>/dev/null
	wait "$GWP_PID" "$dns_pid" 2>/dev/null
done

rc=0

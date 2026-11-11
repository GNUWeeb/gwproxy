#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A lookup that completes just as --protocol-timeout runs out must not have
# the connect it starts killed by that timeout. When the name resolves, the
# io_uring loop removes the protocol timer and arms the connect timer under
# the same user_data. A protocol timer that had fired already still
# completed, after the removal failed or in the same batch, and was taken
# for the connect timer: the client got REP 0x06 for a name that had
# resolved, and the connect, which the target had accepted already, was
# cancelled (an upstream would have been charged a timeout too).
#
# The DNS server answers each name at a moment the name gives, swept around
# its client's protocol deadline, for many clients, about one in ten of
# which then hit the window on an idle host. Every connection the target
# accepts must have been answered REP 0x00. Both loops, though epoll, which
# moves its single timer in place, never had this. The resolver must be one
# of our own, so the body runs in a private user+mount+net namespace with
# its own resolv.conf, as t/0125 does; no name leaves it.

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

printf 'nameserver 127.0.0.1\noptions timeout:5 attempts:1\n' >"$WORK/resolv.conf"
mount --bind "$WORK/resolv.conf" /etc/resolv.conf || { rc=77; exit 0; }
if [ -e /etc/nsswitch.conf ]; then
	printf 'hosts: files dns\n' >"$WORK/nsswitch.conf"
	mount --bind "$WORK/nsswitch.conf" /etc/nsswitch.conf || exit 1
fi

python3 "$SERVERS_DIR/dns_answer_at.py" 53 >"$WORK/dns.log" 2>&1 &
for i in $(seq 1 100); do
	grep -q READY "$WORK/dns.log" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns.log" || { echo "DNS server did not start"; exit 1; }

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout=1 --connect-timeout=5

	echo "[$loop]"
	timeout 120 python3 - "$p" "$loop" <<'PY' || exit 1
import random, socket, struct, sys, threading, time

port, loop = int(sys.argv[1]), sys.argv[2]
N = 120
# Started this far apart, so some 40 lookups are under way at once.
STAGGER = 0.025
PROTOCOL_TIMEOUT_NS = 1_000_000_000

accepted = []
origin = socket.socket()
origin.bind(("127.0.0.1", 0))
origin.listen(256)
oport = origin.getsockname()[1]


def accept_all():
    while True:
        c, _ = origin.accept()
        accepted.append(c)


threading.Thread(target=accept_all, daemon=True).start()

reps = [None] * N


def client(i):
    time.sleep(i * STAGGER)
    t0 = time.monotonic_ns()
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=30)
    except OSError as e:
        reps[i] = "connect: %s" % e
        return
    # The protocol timer starts as the proxy accepts, a little after t0.
    at = t0 + PROTOCOL_TIMEOUT_NS + random.randint(-600, 400) * 1000
    name = b"at-%d-%s%d.test" % (at, loop[0].encode(), i)
    c.sendall(b"\x05\x01\x00\x05\x01\x00\x03" + bytes([len(name)]) + name +
              struct.pack("!H", oport))
    got = b""
    try:
        while len(got) < 12:
            d = c.recv(12 - len(got))
            if not d:
                break
            got += d
    except OSError:
        pass
    c.close()
    reps[i] = got[3] if len(got) >= 4 and got[:2] == b"\x05\x00" else got


threads = [threading.Thread(target=client, args=(i,)) for i in range(N)]
for t in threads:
    t.start()
for t in threads:
    t.join()
# A connect the proxy started reaches the origin's queue before it is
# answered; this is only for the accept thread to catch up.
time.sleep(1)

stats = {}
for r in reps:
    stats[r] = stats.get(r, 0) + 1
ok = stats.get(0, 0)
print("REP counts %s; the origin accepted %d" % (stats, len(accepted)))
bad = [r for r in reps if not isinstance(r, int) or r not in (0, 6)]
if bad:
    print("unexpected answers: %r" % bad[:5])
    sys.exit(1)
if len(accepted) > ok:
    print("%d connects the origin accepted were not answered REP 0x00" %
          (len(accepted) - ok))
    sys.exit(1)
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done
rc=0

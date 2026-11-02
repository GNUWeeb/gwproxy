#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A pair that ends while it waits for a getaddrinfo() lookup must let go of it.
# The io_uring loop kept the pair alive for the lookup and never told the
# resolver it had lost interest, so
#
#   (a) --protocol-timeout did not bound the wait: the client stayed connected
#       and its descriptors stayed open until the name happened to resolve;
#   (b) every lookup still queued behind a busy resolver was run to the end
#       for nobody, in front of the next client's.
#
# With the raw resolver compiled in, the epoll loop also took such a pair's
# lookup for a raw DNS query's socket, which the pair does not have, and credited
# a descriptor too many to the accept throttle: (c) accept stopped on EMFILE must
# not resume early when these pairs time out.
#
# Run on both loops, which have to behave alike. The answers are held back
# until the test has seen what it wants, so nothing here depends on how long a
# lookup takes; the limits only have to be shorter than the resolver's own
# timeout of 30 s. Controlling the resolver takes a resolv.conf of our own and
# a port 53, so the body runs in a private user+mount+net namespace; no name
# leaves it.

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
		--nr-workers=1 --protocol-timeout=1

	echo "[$loop]"
	timeout 120 python3 - "$p" "$GWP_PID" "$names" "$release" <<'PY' || exit 1
import os, select, socket, struct, sys, time

port, pid, names_file, release_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
# Well past --protocol-timeout, short of the resolver's 30 s.
LIMIT = 20
BURST = 100
MAX_THREADS = 64


def die(msg):
    print(msg)
    sys.exit(1)


def nr_tcp_fds():
    """TCP only: a blocked lookup holds a UDP socket of the resolver's own."""
    inodes = set()
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(f) as fp:
                inodes.update(l.split()[9] for l in fp.readlines()[1:])
        except OSError:
            pass
    n = 0
    for fd in os.listdir("/proc/%d/fd" % pid):
        try:
            link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        if link.startswith("socket:[") and link[8:-1] in inodes:
            n += 1
    return n


def socks5_request(name):
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", 9))
    return c


def http_request(name):
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    hp = name + b":9"
    c.sendall(b"CONNECT " + hp + b" HTTP/1.1\r\nHost: " + hp + b"\r\n\r\n")
    return c


def wait_closed(c, what):
    end = time.monotonic() + LIMIT
    c.settimeout(1)
    while time.monotonic() < end:
        try:
            if not c.recv(4096):
                return
        except socket.timeout:
            pass
        except OSError:
            return
    die("%s: still connected %d s after a 1 s protocol timeout" % (what, LIMIT))


def wait_fds(want):
    end = time.monotonic() + LIMIT
    while nr_tcp_fds() > want:
        if time.monotonic() > end:
            die("%d TCP sockets held, %d before the requests" % (nr_tcp_fds(), want))
        time.sleep(0.05)


def names_seen():
    with open(names_file) as f:
        return f.read().split()


# (a) The timeout ends the wait, with the lookup still unanswered.
base = nr_tcp_fds()
for mk, name in ((socks5_request, b"hold-s5.dns-cancel.invalid"),
                 (http_request, b"hold-http.dns-cancel.invalid")):
    c = mk(name)
    wait_closed(c, mk.__name__)
    c.close()
    wait_fds(base)

# (b) A burst bigger than the pool: what is left in the queue when the pairs
# time out must never start. Which lookups the threads already took is up to
# the machine, so wait for the pool to stop taking any.
conns = [socks5_request(b"hold-burst-%d.dns-cancel.invalid" % i) for i in range(BURST)]
for c in conns:
    wait_closed(c, "burst")
    c.close()
wait_fds(base)

open(release_file, "w").close()
# The released threads free up here. With nothing left to run, the count of
# names stays put; give any lookup still queued the time to show up.
time.sleep(3)
burst = [n for n in names_seen() if n.startswith("hold-burst-")]
if len(burst) > MAX_THREADS:
    die("%d of %d lookups ran after their pairs were gone" % (len(burst), BURST))

# And the resolver is free for the next client.
c = socks5_request(b"next-client.dns-cancel.invalid")
c.settimeout(LIMIT)
rep = c.recv(10)
if rep[:2] not in (b"\x05\x00", b"\x05\x05"):
    die("next client got %r" % rep)
print("OK")
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	kill "$GWP_PID" "$dns_pid" 2>/dev/null
	wait "$GWP_PID" "$dns_pid" 2>/dev/null
done

# (c) Only the raw resolver's build has the query's socket to count.
if grep -q CONFIG_NEW_DNS_RESOLVER "$ROOT/config.h" 2>/dev/null; then
	names="$WORK/names.credit"
	release="$WORK/release.credit"
	python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns.credit" 2>&1 &
	dns_pid=$!
	for i in $(seq 1 100); do
		grep -q READY "$WORK/dns.credit" 2>/dev/null && break
		sleep 0.05
	done
	grep -q READY "$WORK/dns.credit" || { echo "DNS server did not start"; exit 1; }

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop=epoll --nr-workers=1 \
		--protocol-timeout=4

	echo "[accept credit]"
	timeout 60 python3 - "$p" "$GWP_PID" "$names" "$WORK/gwp.$p.log" <<'PY' || exit 1
import os, resource, socket, struct, sys, time

port, pid, names_file, log_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
# Accept resumes ahead of its timed retry (5 s, ACCEPT_STOP_MAX_MS) once more
# than 9 descriptors came back. These pairs return one each, so 8 are too few;
# counted double they are plenty.
NR_PAIRS = 8
RETRY = 5
NAME = b"hold-credit.dns-cancel.invalid"


def die(msg):
    print(msg)
    sys.exit(1)


def hello():
    c = socket.create_connection(("127.0.0.1", port), timeout=30)
    c.settimeout(30)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    return c


def request(c):
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(NAME)]) + NAME + struct.pack("!H", 80))


# The first request opens what the lookup takes of the table, so what is free
# after it stays free for the others, which share the lookup.
pairs = [hello()]
request(pairs[0])
end = time.monotonic() + 3
while time.monotonic() < end:
    with open(names_file) as f:
        if f.read().strip():
            break
    time.sleep(0.02)
else:
    print("the lookup did not start in time; inconclusive")
    sys.exit(0)
time.sleep(0.1)

# The limit counts numbers, not descriptors, so find the one that leaves room
# for just the others.
used = {int(n) for n in os.listdir("/proc/%d/fd" % pid)}
lim, free = 0, 0
while free < NR_PAIRS - 1:
    free += lim not in used
    lim += 1
resource.prlimit(pid, resource.RLIMIT_NOFILE, (lim, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))

# Accepting the last one fills the table, and the same round of accept then
# stops on EMFILE, ahead of the answer to that client's hello. So it stopped no
# earlier than t0 and, once the log says so, before the next client.
for _ in range(NR_PAIRS - 1):
    t0 = time.monotonic()
    pairs.append(hello())
    request(pairs[-1])

# Stalled until the first pair timed out, there was still room and accept went
# on, which says nothing.
with open(log_file) as f:
    if "pausing accept" not in f.read():
        print("accept did not stop; inconclusive")
        sys.exit(0)

waiter = socket.create_connection(("127.0.0.1", port), timeout=30)
waiter.sendall(b"\x05\x01\x00")
waiter.settimeout(30)
try:
    got = waiter.recv(2)
except OSError as e:
    got = repr(e)
spent = time.monotonic() - t0
if got != b"\x05\x00":
    die("the client after the pause got %r" % got)
# Only a miscount brings accept back before this, however slow the machine.
if spent < RETRY - 0.1:
    die("accept resumed %.2f s after it stopped; %d pairs must not do that" % (spent, NR_PAIRS))
print("resumed after %.2f s" % spent)
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[accept credit] proxy died"; exit 1; }
	: >"$release"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	kill "$dns_pid" 2>/dev/null
	wait "$dns_pid" 2>/dev/null
fi

rc=0

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that resets its connection while the proxy is still resolving the
# name it asked for has gone: the pair must end at once, and the target must
# never be dialled for it once the name resolves. The epoll loop watches the
# client during the lookup and did so; the io_uring loop armed nothing on the
# client until the connect had started, so it kept the pair for the whole
# lookup and then connected to the target once before it noticed the reset.
#
# Covered for a SOCKS5 CONNECT and an HTTP CONNECT on both loops. A client that
# only half-closes during the lookup is a working client (t/0110, t/0158); with
# --connect-timeout=0 and a target that never answers, --protocol-timeout
# bounds its connect once the name has resolved, which is checked last. The answers are held back until the test has reset the
# clients and seen the pairs go, so nothing here depends on how long a lookup
# takes. Controlling the resolver takes a resolv.conf of our own and a port 53,
# so the body runs in a private user+mount+net namespace; no name leaves it.

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
		--nr-workers=1 --protocol-timeout=60 --connect-timeout=0

	echo "[$loop]"
	timeout 120 python3 - "$p" "$GWP_PID" "$names" "$release" <<'PY' || exit 1
import os, select, socket, struct, sys, time

port, pid, names_file, release_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
# Well short of --protocol-timeout and the resolver's 30 s: only the reset can
# end these pairs in time.
LIMIT = 20


def die(msg):
    print(msg)
    sys.exit(1)


def nr_tcp_fds():
    """
    Sockets but UDP ones: a blocked lookup holds a UDP socket of the
    resolver's own. A reset TCP socket is in no table any more, so TCP ones
    are what is left rather than what /proc/net/tcp lists.
    """
    udp = set()
    for f in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(f) as fp:
                udp.update(l.split()[9] for l in fp.readlines()[1:])
        except OSError:
            pass
    n = 0
    for fd in os.listdir("/proc/%d/fd" % pid):
        try:
            link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        if link.startswith("socket:[") and link[8:-1] not in udp:
            n += 1
    return n


# The target counts every connection it gets.
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(16)
tport = ls.getsockname()[1]
dialled = []


def take_dials(wait):
    end = time.monotonic() + wait
    while True:
        left = end - time.monotonic()
        if left <= 0 or not select.select([ls], [], [], left)[0]:
            return
        c, _ = ls.accept()
        dialled.append(c)


def socks5_request(name):
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", tport))
    return c


def http_request(name):
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    hp = name + b":%d" % tport
    c.sendall(b"CONNECT " + hp + b" HTTP/1.1\r\nHost: " + hp + b"\r\n\r\n")
    return c


def wait_name(name):
    end = time.monotonic() + LIMIT
    while time.monotonic() < end:
        with open(names_file) as f:
            if name.decode() in f.read().split():
                return
        time.sleep(0.02)
    die("the lookup of %s did not start" % name.decode())


def reset(c):
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()


base = nr_tcp_fds()
for mk, name in ((socks5_request, b"hold-s5.dns-reset.invalid"),
                 (http_request, b"hold-http.dns-reset.invalid")):
    c = mk(name)
    wait_name(name)
    reset(c)

# The reset alone ends both pairs, with their lookups still unanswered.
end = time.monotonic() + LIMIT
while nr_tcp_fds() > base:
    if time.monotonic() > end:
        die("%d TCP sockets held %d s after the clients reset, %d before" %
            (nr_tcp_fds(), LIMIT, base))
    time.sleep(0.05)

# Now let the names resolve: nobody is left to dial the target for.
open(release_file, "w").close()
take_dials(3)
if dialled:
    die("the target was dialled %d time(s) for clients that had reset" % len(dialled))

# The control: the same request from a client that stays is connected.
c = socks5_request(b"hold-stay.dns-reset.invalid")
c.settimeout(LIMIT)
rep = c.recv(10)
if rep[:2] != b"\x05\x00":
    die("the client that stayed got %r" % rep)
take_dials(2)
if len(dialled) != 1:
    die("the client that stayed: %d dials" % len(dialled))
c.close()
print("OK")
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	kill "$GWP_PID" "$dns_pid" 2>/dev/null
	wait "$GWP_PID" "$dns_pid" 2>/dev/null
done

# A FIN during the lookup, with --connect-timeout=0 and a target that never
# answers. The lookup runs under the protocol timer; once the name resolves,
# the connect is bounded by --protocol-timeout from its start (t/0178 does it
# for a FIN during the connect). The pair must end once, by that bound: not
# by the lookup's timer left running, nor by a second timer armed at the FIN
# during the lookup, nor never. The same for a FIN that comes once the lookup
# is over: the pair's state still says lookup then, on io_uring.
python3 "$SERVERS_DIR/blackhole_listener.py" >"$WORK/bh.port" 2>&1 &
for i in $(seq 1 100); do
	bh="$(head -n 1 "$WORK/bh.port" 2>/dev/null)"
	[ -n "$bh" ] && break
	sleep 0.05
done
[ -n "$bh" ] || { echo "the black-hole target did not start"; exit 1; }

BOUND=8
for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	names="$WORK/names.fin.$loop"
	release="$WORK/release.fin.$loop"
	python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns.fin.$loop" 2>&1 &
	dns_pid=$!
	for i in $(seq 1 100); do
		grep -q READY "$WORK/dns.fin.$loop" 2>/dev/null && break
		sleep 0.05
	done
	grep -q READY "$WORK/dns.fin.$loop" || { echo "DNS server did not start"; exit 1; }

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout="$BOUND" --connect-timeout=0

	echo "[$loop fin]"
	timeout 120 python3 - "$p" "$GWP_PID" "$names" "$release" "$bh" "$BOUND" <<'PY' || exit 1
import os, socket, struct, sys, time

port, pid, names_file, release_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
bh, bound = int(sys.argv[5]), int(sys.argv[6])
LIMIT = 60
NAME = b"hold-fin.dns-reset.invalid"


def die(msg):
    print(msg)
    sys.exit(1)


def nr_sock_fds():
    udp = set()
    for f in ("/proc/net/udp", "/proc/net/udp6"):
        with open(f) as fp:
            udp.update(l.split()[9] for l in fp.readlines()[1:])
    n = 0
    for fd in os.listdir("/proc/%d/fd" % pid):
        try:
            link = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        n += link.startswith("socket:[") and link[8:-1] not in udp
    return n


def client(name):
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", bh))
    end = time.monotonic() + LIMIT
    while name.decode() not in open(names_file).read().split():
        if time.monotonic() > end:
            die("the lookup did not start")
        time.sleep(0.02)
    return c


def wait_end(c, t0, what):
    c.settimeout(max(t0 + LIMIT - time.monotonic(), 0.01))
    try:
        while c.recv(4096):
            pass
    except socket.timeout:
        die("%s: no end of stream %d s after the FIN" % (what, LIMIT))
    except OSError:
        pass
    spent = time.monotonic() - t0
    if spent < bound - 1:
        die("%s: the pair ended %.1f s in, short of the %d s bound" % (what, spent, bound))
    return spent


base = nr_sock_fds()
# @early half-closes during the lookup, @late once its lookup is over and the
# connect is under way: the watch's report of that FIN may come before or
# after the lookup's end is handled, and either way it must be bounded.
early = client(NAME)
late = client(b"hold-late-fin.dns-reset.invalid")
early.shutdown(socket.SHUT_WR)
# Well inside the lookup's own bound, so that the connect starts first.
time.sleep(3)
open(release_file, "w").close()
t0 = time.monotonic()
time.sleep(1)
late.shutdown(socket.SHUT_WR)
t1 = time.monotonic()

spent = wait_end(early, t0, "FIN during the lookup")
spent_late = wait_end(late, t1, "FIN after the lookup")
end = time.monotonic() + 10
while nr_sock_fds() > base:
    if time.monotonic() > end:
        die("%d sockets held after the pairs ended, %d before" % (nr_sock_fds(), base))
    time.sleep(0.05)
print("ended %.1f s into the connect; %.1f s after a FIN behind the lookup" % (spent, spent_late))
PY
	# Some time for anything left armed to fire on the freed pair.
	sleep 2
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop fin] proxy died"; exit 1; }
	n="$(grep -c 'Connection timeout!' "$WORK/gwp.$p.log")"
	[ "$n" = 2 ] || { echo "[$loop fin] $n connection timeouts logged, not 2"; exit 1; }
	kill "$GWP_PID" "$dns_pid" 2>/dev/null
	wait "$GWP_PID" "$dns_pid" 2>/dev/null
done

rc=0

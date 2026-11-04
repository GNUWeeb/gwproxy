#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --protocol-timeout also bounds the lookup of the target's name. When it runs
# out there, the client has made its request and is owed an answer: SOCKS5 REP
# 0x06, or HTTP 504. Both loops hung up without a word, as if the proxy had
# died. A client that has not finished its request still gets none, as a reply
# would answer something it never asked.
#
# The answers are held back for as long as the test runs, so nothing depends on
# how long a lookup takes. Controlling the resolver takes a resolv.conf of our
# own and a port 53, so the body runs in a private user+mount+net namespace; no
# name leaves it.

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
	for i in $(seq 1 120); do
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

names="$WORK/names"
release="$WORK/release"
python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns" 2>&1 &
dns_pid=$!
for i in $(seq 1 100); do
	grep -q READY "$WORK/dns" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns" || { echo "DNS server did not start"; exit 1; }

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --protocol-timeout=1

	echo "[$loop]"
	timeout 100 python3 - "$p" "$loop" <<'PY' || exit 1
import socket, struct, sys

port, loop = int(sys.argv[1]), sys.argv[2]
# Well past --protocol-timeout, short of the resolver's 30 s.
LIMIT = 20


def die(msg):
    print(msg)
    sys.exit(1)


def conn():
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.settimeout(LIMIT)
    return c


def read_all(c, what):
    """All the client gets until the proxy hangs up."""
    got = b""
    try:
        while True:
            d = c.recv(4096)
            if not d:
                return got
            got += d
    except socket.timeout:
        die("%s: no hang-up %d s after a 1 s protocol timeout" % (what, LIMIT))
    except ConnectionError:
        return got


def s5_hello(c):
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")


def s5_connect(name):
    return b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", 9)


# A complete request, waiting for its name.
c = conn()
s5_hello(c)
c.sendall(s5_connect(b"hold-s5-%s.dns-reply.invalid" % loop.encode()))
got = read_all(c, "SOCKS5")
c.close()
if got[:2] != b"\x05\x06":
    die("SOCKS5 CONNECT got %r, want REP 0x06" % got)

for what, req in (
    ("HTTP CONNECT", b"CONNECT hold-c-%s.dns-reply.invalid:9 HTTP/1.1\r\n"
                     b"Host: hold-c-%s.dns-reply.invalid:9\r\n\r\n"),
    ("HTTP GET", b"GET http://hold-g-%s.dns-reply.invalid/ HTTP/1.1\r\n"
                 b"Host: hold-g-%s.dns-reply.invalid\r\n\r\n"),
):
    c = conn()
    c.sendall(req % (loop.encode(), loop.encode()))
    got = read_all(c, what)
    c.close()
    if not got.startswith(b"HTTP/1.1 504"):
        die("%s got %r, want 504" % (what, got[:60]))

# Nothing requested: a silent close, as ever.
c = conn()
s5_hello(c)
got = read_all(c, "SOCKS5, no request")
c.close()
if got:
    die("SOCKS5 client that asked for nothing got %r" % got)

c = conn()
c.sendall(b"CONNECT hold-partial")
got = read_all(c, "HTTP, partial request")
c.close()
if got:
    die("HTTP client that asked for nothing got %r" % got)
print("OK")
PY
	kill -0 "$GWP_PID" 2>/dev/null || { echo "[$loop] proxy died"; exit 1; }
	# Stopping waits for the resolver threads: let their lookups end.
	: >"$release"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
	rm -f "$release"
done

kill "$dns_pid" 2>/dev/null
rc=0

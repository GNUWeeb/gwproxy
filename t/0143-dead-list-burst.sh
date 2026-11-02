#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# One finished lookup can end any number of pairs, all of them from a single
# event. The epoll loop kept the pairs to free after the batch in a list of a
# fixed size; when that filled up, it threw away the rest of the batch. Events
# of level-triggered descriptors come back, but a tunnel whose buffer is full
# waits edge-triggered for EPOLLOUT, so a discarded one stalled that tunnel for
# good, with its data held in the proxy, while the pairs that caused it had
# nothing to do with it.
#
# To have that EPOLLOUT right behind the lookup's event in one batch, the worker
# is held on a ptrace stop while the lookup ends and the tunnel's client reads.
# Only the worker: the resolver threads go on. Holding back the answer takes a
# resolv.conf of our own and a port 53, so the body runs in a private
# user+mount+net namespace; no name leaves it. epoll only: on io_uring there is
# no batch to discard.

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

names="$WORK/names"
release="$WORK/release"
python3 "$SERVERS_DIR/dns_hold.py" 53 "$names" "$release" >"$WORK/dns.out" 2>&1 &
for i in $(seq 1 100); do
	grep -q READY "$WORK/dns.out" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns.out" || { echo "DNS server did not start"; exit 1; }

p="$(pick_port)"
timeout 120 python3 - "$GWPROXY" "$p" "$WORK" "$names" "$release" <<'PY'
import ctypes, os, resource, signal, socket, struct, subprocess, sys, time

gw, port, work, names_file, release_file = sys.argv[1], int(sys.argv[2]), *sys.argv[3:]
# Well past the 544 entries the list used to have.
NR_PAIRS = 800
LIMIT = 30
NAME = b"holdnx-burst.dead-list.invalid"
PTRACE_DETACH, PTRACE_SEIZE, PTRACE_INTERRUPT = 17, 0x4206, 0x4207
WALL = 0x40000000

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
if hard != resource.RLIM_INFINITY and hard < 2 * NR_PAIRS + 64:
    print("RLIMIT_NOFILE's hard limit %d is too low" % hard)
    sys.exit(77)
resource.setrlimit(resource.RLIMIT_NOFILE, (2 * NR_PAIRS + 64, hard))

ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(16)
oport = ls.getsockname()[1]

log = open(work + "/gwp.log", "wb")
proxy = subprocess.Popen([gw, "--bind=127.0.0.1:%d" % port, "--log-level=2", "--acl-allow-all",
                          "--as-socks5=1", "--event-loop=epoll", "--nr-workers=1",
                          "--protocol-timeout=0", "--connect-timeout=0"],
                         stdout=log, stderr=subprocess.STDOUT)


def die(msg):
    print(msg)
    proxy.kill()
    sys.exit(1)


def wait_for(cond, what):
    end = time.monotonic() + LIMIT
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.01)
    die("timed out waiting for %s" % what)


def hello():
    c = socket.create_connection(("127.0.0.1", port), timeout=LIMIT)
    c.settimeout(LIMIT)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        die("no SOCKS5 method reply")
    return c


def listening():
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


wait_for(listening, "the proxy to listen")

# The tunnel: both ways stuffed until the proxy's buffers and socket buffers are
# full, so both of its sockets wait edge-triggered.
c = hello()
c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", oport))
if c.recv(10)[:2] != b"\x05\x00":
    die("no tunnel")
t, _ = ls.accept()
c.setblocking(False)
t.setblocking(False)
blob = b"x" * 65536
total = 0


def stuff():
    global total
    moved = 0
    for s in (c, t):
        try:
            while True:
                n = s.send(blob)
                moved += n
                if s is t:
                    total += n
        except BlockingIOError:
            pass
    return moved


while stuff() or (time.sleep(0.05), stuff())[1]:
    pass

# The burst, waiting on one lookup. Nothing can be read until it ends, and a
# last client answered after all the requests went in shows they were read.
burst = [hello() for _ in range(NR_PAIRS)]
request = b"\x05\x01\x00\x03" + bytes([len(NAME)]) + NAME + struct.pack("!H", 80)
for s in burst:
    s.sendall(request)
hello().close()
wait_for(lambda: open(names_file).read().strip(), "the lookup to start")
time.sleep(0.2)

# Worker 0 is the process's main thread.
try:
    for req in (PTRACE_SEIZE, PTRACE_INTERRUPT):
        if libc.ptrace(req, proxy.pid, None, None) < 0:
            raise OSError(ctypes.get_errno(), "ptrace")
except OSError as e:
    print("cannot trace: %s" % e)
    proxy.kill()
    sys.exit(77)
os.waitpid(proxy.pid, WALL)


def lookup_done():
    d = "/proc/%d/fdinfo" % proxy.pid
    for fd in os.listdir(d):
        try:
            with open(os.path.join(d, fd)) as f:
                for line in f:
                    if line.startswith("eventfd-count:") and int(line.split()[1], 16):
                        return True
        except OSError:
            pass
    return False


open(release_file, "w").close()
wait_for(lookup_done, "the lookup to end")
# The first entry signals; the others follow in no time.
time.sleep(0.5)

# Now the EPOLLOUT, behind the lookup's event: the client takes what the
# proxy's socket can send on its own.
got = 0
idle = 0
while idle < 3:
    try:
        d = c.recv(1 << 22)
        if not d:
            die("the tunnel closed")
        got += len(d)
        idle = 0
    except BlockingIOError:
        idle += 1
        time.sleep(0.02)
if libc.ptrace(PTRACE_DETACH, proxy.pid, None, None) < 0:
    die("cannot detach: errno %d" % ctypes.get_errno())

# All the data has to come through. Nothing else moves this tunnel: the target
# reads nothing and sends nothing, and the proxy has no timer on it.
c.setblocking(True)
c.settimeout(LIMIT)
while got < total:
    try:
        d = c.recv(1 << 20)
    except socket.timeout:
        die("the tunnel stalled: read %d of %d bytes" % (got, total))
    if not d:
        die("the tunnel closed after %d of %d bytes" % (got, total))
    got += len(d)

for s in burst:
    try:
        while s.recv(4096):
            pass
    except ConnectionError:
        pass
    except socket.timeout:
        die("a client of the failed lookup was left waiting")

if proxy.poll() is not None:
    die("the proxy died")
proxy.send_signal(signal.SIGTERM)
try:
    r = proxy.wait(LIMIT)
except subprocess.TimeoutExpired:
    die("the proxy did not stop")
if r:
    print("the proxy exited with %d" % r)
    sys.exit(1)
print("read all %d bytes, %d pairs ended" % (total, NR_PAIRS))
PY
r=$?
[ "$r" = 0 ] && rc=0
[ "$r" = 77 ] && rc=77
exit 0

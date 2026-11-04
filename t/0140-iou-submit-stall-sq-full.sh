#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# io_uring_enter(2) failing for a good while, as in a cgroup short of memory,
# while completions keep asking for more SQEs than the ring has room for: 800
# tunnels ending at once on a 1024-entry ring. The worker used to retry for a
# second and then abort the proxy, dropping every tunnel. The one stall goes
# through each transient error in turn, as opening the tunnels is what takes
# the time here.
#
# All of those tunnels must go away once the kernel recovers, and the proxy must
# stay up throughout: a tunnel that was left alone keeps working, a new one can
# be opened, and no descriptor is left behind.
#
# The errors come from a small preload shim, which can start and stop them at
# will, see t/servers/iou_enter_fail.c.

. "$(dirname "$0")/lib.sh"
require python3
require_io_uring

[ "$(uname -m)" = x86_64 ] || skip "the shim is x86-64 only"
built=""
for cc in cc gcc clang; do
	command -v "$cc" >/dev/null 2>&1 || continue
	"$cc" -shared -fPIC -O1 -o "$WORK/shim.so" \
		"$SERVERS_DIR/iou_enter_fail.c" 2>"$WORK/cc.log" && built=1 && break
done
[ -n "$built" ] || skip "cannot build the shim: $(head -1 "$WORK/cc.log" 2>/dev/null)"

ulimit -n 8192 2>/dev/null
[ "$(ulimit -n)" -ge 4096 ] || skip "needs 4096 descriptors"

real="$GWPROXY"
wrap="$WORK/gwproxy-shim"
ctl="$WORK/ctl"
head -c 4096 /dev/zero >"$ctl"
# Exec'ed, so the pid gwp_start records is the proxy's. A sanitizer runtime wants
# to come first, and it is fine with this shim coming first instead.
cat >"$wrap" <<-WRAP
	#!/bin/sh
	IOU_FAIL_CTL="$ctl" LD_PRELOAD="$WORK/shim.so" \
	ASAN_OPTIONS="\${ASAN_OPTIONS:+\$ASAN_OPTIONS:}verify_asan_link_order=0" \
	exec "$real" "\$@"
WRAP
chmod +x "$wrap"

# The shim exits 99 at startup where it cannot install its filter.
"$wrap" --help >/dev/null 2>&1
[ "$?" != 99 ] || skip "the shim cannot install its seccomp filter here"

pp="$(pick_port)"
GWPROXY="$wrap" gwp_start "127.0.0.1:$pp" --as-socks5=1 \
	--event-loop=io_uring --nr-workers=1 --protocol-timeout=0
log="$WORK/gwp.$pp.log"

out="$(timeout 120 python3 - "$pp" "$GWP_PID" "$ctl" 2>&1 <<'PY'
import errno, mmap, os, selectors, socket, struct, sys, threading, time
port, pid, ctlp = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
N = 800
# Seconds with each error. In all, more than the second the worker used to allow.
STALL = 1.0

f = open(ctlp, "r+b")
ctl = mmap.mmap(f.fileno(), 4096)

ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 0))
ls.listen(4096)
ls.setblocking(False)
sel = selectors.DefaultSelector()
sel.register(ls, selectors.EVENT_READ)

def origin():
    while True:
        for k, _ in sel.select():
            if k.fileobj is ls:
                try:
                    c, _a = ls.accept()
                except OSError:
                    continue
                c.setblocking(False)
                sel.register(c, selectors.EVENT_READ)
                continue
            try:
                d = k.fileobj.recv(4096)
            except OSError:
                d = b""
            if d:
                try:
                    k.fileobj.send(d)
                except OSError:
                    pass
            else:
                sel.unregister(k.fileobj)
                k.fileobj.close()

threading.Thread(target=origin, daemon=True).start()

def fds():
    return len(os.listdir("/proc/%d/fd" % pid))

def alive():
    try:
        with open("/proc/%d/stat" % pid) as st:
            return st.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False

def tunnel():
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        sys.exit("no greeting reply")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
              struct.pack(">H", ls.getsockname()[1]))
    r = b""
    while len(r) < 10:
        b = s.recv(10 - len(r))
        if not b:
            sys.exit("closed during CONNECT")
        r += b
    if r[1] != 0:
        sys.exit("CONNECT got %r" % r)
    s.sendall(b"ping")
    if s.recv(4) != b"ping":
        sys.exit("no echo")
    return s

base = fds()
witness = tunnel()
one = fds()
tunnels = [tunnel() for _ in range(N)]

def failed():
    return struct.unpack("<Q", ctl[8:16])[0]

ERRS = (errno.ENOMEM, errno.EAGAIN, errno.EBUSY)
ctl[0:4] = struct.pack("<I", ERRS[0])
t0 = time.monotonic()
for s in tunnels:
    s.close()
for err in ERRS:
    ctl[0:4] = struct.pack("<I", err)
    seen = failed()
    start = time.monotonic()
    # At least one failed call with each, however slowly the worker gets to it.
    while (time.monotonic() - start < STALL or
           (failed() == seen and time.monotonic() - start < 30)):
        if not alive():
            sys.exit("proxy died %.2f s into the stall, on %s" %
                     (time.monotonic() - t0, errno.errorcode[err]))
        time.sleep(0.02)
    if failed() == seen:
        if err == ERRS[0]:
            print("no failure injected")
            sys.exit(0)
        sys.exit("no submit saw %s" % errno.errorcode[err])
ctl[0:4] = b"\0\0\0\0"

witness.settimeout(30)
witness.sendall(b"wit!")
if witness.recv(4) != b"wit!":
    sys.exit("the other tunnel was cut")
tunnel().close()

end = time.monotonic() + 60
while fds() > one and time.monotonic() < end:
    time.sleep(0.1)
if fds() > one:
    sys.exit("%d descriptors left, want %d" % (fds(), one))
print("ok")
PY
)" || fail "$out"
[ "$out" != "no failure injected" ] || skip "the shim did not take effect"
[ "$out" = ok ] || fail "$out"
kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
# Without this the test would prove nothing: the SQ must have overflowed.
grep -q 'holding back' "$log" || fail "the ring never filled up"
kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null

pass

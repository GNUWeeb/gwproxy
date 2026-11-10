#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A close the io_uring loop queues that completes with -EINVAL was refused
# before it ran, so its descriptor is still open. The loop used to only log
# "close(N) failed" and drop it, which leaked both sockets of every pair. Now
# it closes the descriptor itself.
#
# No supported kernel refuses a close this way (older ones did, for the
# IOSQE_CQE_SKIP_SUCCESS flag, and are now refused at startup, see t/0250). A
# preload shim makes the kernel fail every io_uring close with -EINVAL (see
# t/servers/iou_old_kernel.c); after 60 connections through a plain proxy to an
# origin that answers and closes, the proxy's descriptor count must be back
# where it started.

. "$(dirname "$0")/lib.sh"
require python3
require_io_uring

[ "$(uname -m)" = x86_64 ] || skip "the shim is x86-64 only"
built=""
for cc in cc gcc clang; do
	command -v "$cc" >/dev/null 2>&1 || continue
	"$cc" -shared -fPIC -O1 -o "$WORK/shim.so" \
		"$SERVERS_DIR/iou_old_kernel.c" 2>"$WORK/cc.log" && built=1 && break
done
[ -n "$built" ] || skip "cannot build the shim: $(head -1 "$WORK/cc.log" 2>/dev/null)"

real="$GWPROXY"
wrap="$WORK/gwproxy-shim"
# See t/0250 for why the shim is preloaded into the proxy alone.
cat >"$wrap" <<-WRAP
	#!/bin/sh
	IOU_OLD_KERNEL=close-einval LD_PRELOAD="$WORK/shim.so" \
	ASAN_OPTIONS="\${ASAN_OPTIONS:+\$ASAN_OPTIONS:}verify_asan_link_order=0" \
	exec "$real" "\$@"
WRAP
chmod +x "$wrap"

"$wrap" --help >/dev/null 2>&1
[ "$?" != 99 ] || skip "the shim cannot install its seccomp filter here"

# The origin: answers each connection with "hello" and closes.
op="$(pick_port)"
python3 -c '
import socket, sys
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", int(sys.argv[1])))
ls.listen(128)
while True:
    c, _a = ls.accept()
    c.sendall(b"hello")
    c.close()
' "$op" >/dev/null 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "the origin did not start"

pp="$(pick_port)"
GWPROXY="$wrap" gwp_start "127.0.0.1:$pp" --event-loop=io_uring \
	--nr-workers=1 --target="127.0.0.1:$op"
log="$WORK/gwp.$pp.log"

out="$(timeout 120 python3 - "$pp" "$GWP_PID" 2>&1 <<'PY'
import os, socket, sys, time
port, pid = int(sys.argv[1]), int(sys.argv[2])
N = 60

def fds():
    return len(os.listdir("/proc/%d/fd" % pid))

def fetch():
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    d = b""
    while True:
        b = s.recv(64)
        if not b:
            break
        d += b
    s.close()
    if d != b"hello":
        sys.exit("got %r through the proxy" % d)

def settle(want):
    end = time.monotonic() + 20
    while fds() > want and time.monotonic() < end:
        time.sleep(0.1)
    return fds()

# One pair first, so whatever the worker sets up for good on the way is
# counted in the baseline; then give its closes time to complete.
fetch()
time.sleep(0.5)
base = fds()
for _ in range(N):
    fetch()
now = settle(base)
print("descriptors: %d before, %d after %d pairs" % (base, now, N))
sys.exit(0 if now <= base else 1)
PY
)"; rc=$?
echo "$out" | sed 's/^/# /' >&2
grep -v "Closing connection pair\|New connection" "$log" | tail -20 | \
	sed 's/^/# gwp: /' >&2
[ "$rc" = 0 ] || fail "io_uring leaked the descriptors of closes the kernel refused"
grep -q "failed: Invalid argument" "$log" \
	|| fail "the shim refused no close: nothing was tested"
pass

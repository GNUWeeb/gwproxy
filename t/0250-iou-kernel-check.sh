#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The io_uring loop needs Linux 5.19: it queues every close with
# IOSQE_CQE_SKIP_SUCCESS (5.17) and ends a pair's requests with
# IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_ALL (5.19). An older kernel
# fails those requests with -EINVAL before they run, so the proxy used to start
# there and then leak both sockets of every pair (before 5.17), or every pair
# that timed out or failed (5.17 and 5.18).
#
# On this host's kernel the loop must start and serve. Then, with a preload
# shim that makes io_uring look like 5.15's or 5.18's (see
# t/servers/iou_old_kernel.c), --event-loop=io_uring must refuse to start,
# saying which kernel it needs, instead of serving.

. "$(dirname "$0")/lib.sh"
require python3
require_io_uring

TO="$(( ${GWP_TEST_TIMEOUT:-30} > 30 ? ${GWP_TEST_TIMEOUT:-30} : 30 ))"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100000
start_httpd "$hp" "$WORK" "1.1"

# This kernel: the check passes and the loop works.
pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --event-loop=io_uring --nr-workers=2 \
	--target="127.0.0.1:$hp"
for i in 1 2 3; do
	python3 - "$pp" "$WORK/out.bin" <<-'PY' || fail "fetch $i through io_uring failed"
	import socket, sys
	s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
	s.sendall(b"GET /payload.bin HTTP/1.0\r\nHost: x\r\n\r\n")
	d = b""
	while True:
	    b = s.recv(65536)
	    if not b:
	        break
	    d += b
	open(sys.argv[2], "wb").write(d.split(b"\r\n\r\n", 1)[1])
	PY
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"io_uring corrupted the payload"
done
log="$WORK/gwp.$pp.log"
grep -q "needs Linux" "$log" && fail "the check refused this kernel: $(cat "$log")"
kill "$GWP_PID" 2>/dev/null

# Older kernels, as the shim shows them.
[ "$(uname -m)" = x86_64 ] || pass "older kernels not checked: the shim is x86-64 only"
built=""
for cc in cc gcc clang; do
	command -v "$cc" >/dev/null 2>&1 || continue
	"$cc" -shared -fPIC -O1 -o "$WORK/shim.so" \
		"$SERVERS_DIR/iou_old_kernel.c" 2>"$WORK/cc.log" && built=1 && break
done
[ -n "$built" ] || pass "older kernels not checked: cannot build the shim: $(head -1 "$WORK/cc.log" 2>/dev/null)"

real="$GWPROXY"
wrap="$WORK/gwproxy-old"
# Only the proxy gets the shim: a filter installed in a parent would trap the
# calls of the proxy's own copy of the shim too. Exec'ed, so its pid is the
# proxy's. A sanitizer runtime wants to come first, and it is fine with this
# shim coming first instead.
cat >"$wrap" <<-WRAP
	#!/bin/sh
	LD_PRELOAD="$WORK/shim.so" \
	ASAN_OPTIONS="\${ASAN_OPTIONS:+\$ASAN_OPTIONS:}verify_asan_link_order=0" \
	exec "$real" "\$@"
WRAP
chmod +x "$wrap"

# The shim exits 99 at startup where it cannot install its filter.
IOU_OLD_KERNEL=5.18 "$wrap" --help >/dev/null 2>&1
[ "$?" != 99 ] || pass "older kernels not checked: the shim cannot install its seccomp filter here"

for k in 5.15 5.18; do
	case "$k" in
	5.15) lacks="IOSQE_CQE_SKIP_SUCCESS" ;;
	5.18) lacks="IORING_ASYNC_CANCEL_FD" ;;
	esac
	pp="$(pick_port)"
	log="$WORK/old-$k.log"
	rc=0
	IOU_OLD_KERNEL="$k" timeout "$TO" "$wrap" --bind="127.0.0.1:$pp" \
		--event-loop=io_uring --nr-workers=2 --acl-allow-all \
		--target="127.0.0.1:$hp" >"$log" 2>&1 </dev/null || rc=$?
	sed "s/^/# [$k] /" "$log" >&2
	[ "$rc" = 124 ] && fail "[$k] io_uring started on a kernel that lacks $lacks"
	[ "$rc" != 0 ] || fail "[$k] the proxy exited 0"
	grep -q "io_uring event loop needs Linux 5.19 or later: this kernel lacks $lacks" \
		"$log" || fail "[$k] no clear refusal in the log (exit $rc)"
done

pass

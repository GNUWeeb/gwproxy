#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# accept() failing for a reason that freeing descriptors does not cure: a
# security module refusing the connection (EPERM, EACCES), or the kernel
# out of socket memory (ENOBUFS). The connection stays at the head of the
# backlog and the listener stays readable, so the epoll worker tried again
# at once, logged an error for every try, and spun at 100% CPU for as long
# as the condition lasted. It must pause accept instead, say so once, and
# keep serving.
#
# The errors are injected with a seccomp filter on accept4(), which
# io_uring's accept does not go through; this runs on epoll only.

. "$(dirname "$0")/lib.sh"
require python3

real="$GWPROXY"
wrap="$WORK/gwproxy-accept-err"

for err in EPERM EACCES ENOBUFS; do
	printf '#!/bin/sh\nexec python3 "%s" %s "%s" "$@"\n' \
		"$SERVERS_DIR/seccomp_errno.py" "$err" "$real" >"$wrap"
	chmod +x "$wrap"
	python3 "$SERVERS_DIR/seccomp_errno.py" "$err" /bin/true || \
		skip "cannot install a seccomp filter here"

	p="$(pick_port)"
	GWPROXY="$wrap" gwp_start "127.0.0.1:$p" --as-socks5=1 \
		--event-loop=epoll --nr-workers=1
	log="$WORK/gwp.$p.log"

	out="$(python3 - "$p" "$GWP_PID" <<'PY'
import socket, sys, time
port, pid = int(sys.argv[1]), int(sys.argv[2])

def ticks():
    with open("/proc/%d/stat" % pid) as f:
        v = f.read().rsplit(")", 1)[1].split()
    return int(v[11]) + int(v[12])

# Completes in the kernel; the proxy can never accept it.
c = socket.create_connection(("127.0.0.1", port), timeout=5)
time.sleep(0.2)
t0 = ticks()
time.sleep(1.0)
spent = ticks() - t0
print("%d" % spent)
c.close()
PY
)" || fail "[$err] client failed: $out"

	kill -0 "$GWP_PID" 2>/dev/null || fail "[$err] proxy died"
	[ "$out" -le 20 ] || \
		fail "[$err] the worker spun on the failing accept ($out ticks in 1 s)"
	n="$(grep -c 'pausing accept' "$log")"
	[ "$n" = 1 ] || fail "[$err] want one pause line, got $n"
	n="$(grep -c 'Failed to accept' "$log")"
	[ "$n" = 1 ] || fail "[$err] want one accept failure logged, got $n"
	diag "$err: $out ticks in 1 s"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

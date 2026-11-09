#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A lookup by the system resolver that cannot even be queued, for want of
# memory, is answered as one that failed: SOCKS5 REP 0x04 (host unreachable),
# HTTP 502. It closed the connection without a word before, so a SOCKS5
# client had no reply and an HTTP client no status, as a raw lookup that
# could not start did (t/0186).
#
# The failure comes from a malloc() wrapper preloaded into the proxy: once
# armed (a file exists), it fails every allocation of exactly the size of the
# resolver's request for the probe name, which holds the name. Nothing else
# needs to fail, and nothing fails before the proxy is up. The wrapper cannot
# share a process with the sanitizers' allocator, so the test skips in a
# sanitizer build. It needs glibc too: musl, once malloc() is replaced,
# refuses aligned_alloc() and posix_memalign(), and the proxy cannot start.
#
# The reason goes to the debug log. Both event loops.

. "$(dirname "$0")/lib.sh"
require python3

grep -q -- '-fsanitize' "$ROOT/config.make" 2>/dev/null && \
	skip "a preloaded malloc() cannot coexist with the sanitizers"
cc="$(sed -n 's/^CC=//p' "$ROOT/config.make" 2>/dev/null)"
[ -n "$cc" ] || skip "no compiler in config.make"

# A name of its own length, so that its request's size is its own too.
l50="$(printf 'x%.0s' $(seq 1 50))"
name="probe.$l50.$l50.$l50.invalid"

cat >"$WORK/size.c" <<'EOF'
#include <stdio.h>
#include <gwproxy/dns.h>

int main(void)
{
	printf("%zu\n", sizeof(struct gwp_dns_entry));
	return 0;
}
EOF
"$cc" -D_GNU_SOURCE -include "$ROOT/config.h" -I"$ROOT/src" \
	-o "$WORK/size" "$WORK/size.c" >"$WORK/size.log" 2>&1 || \
	skip "cannot build the size probe: $(head -n 3 "$WORK/size.log")"
size=$(( $("$WORK/size") + ${#name} + 1 ))

cat >"$WORK/failmalloc.c" <<'EOF'
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef __GLIBC__
#error "needs glibc's __libc_malloc()"
#endif
extern void *__libc_malloc(size_t n);

void *malloc(size_t n)
{
	static void *(*real)(size_t);
	static const char *arm;
	static size_t size;

	if (!real) {
		const char *s = getenv("FAILMALLOC_SIZE");

		arm = getenv("FAILMALLOC_ARM");
		size = s ? strtoul(s, NULL, 10) : 0;
		real = __libc_malloc;
	}
	if (n && n == size && arm && !access(arm, F_OK)) {
		errno = ENOMEM;
		return NULL;
	}
	return real(n);
}
EOF
"$cc" -D_GNU_SOURCE -shared -fPIC -o "$WORK/failmalloc.so" \
	"$WORK/failmalloc.c" >"$WORK/failmalloc.log" 2>&1 || \
	skip "cannot build the malloc() wrapper: $(head -n 3 "$WORK/failmalloc.log")"
diag "failing allocations of $size bytes"

# ask <socks5|http|get> <proxy port>: the SOCKS5 reply code, or the HTTP
# status of a CONNECT or of a forwarded GET, or NONE when the connection
# closed or nothing came back within the timeout.
ask()
{
	python3 -c '
import socket, sys
kind, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x00\x50")
        r = s.recv(16)
        print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
    else:
        if kind == "http":
            req = "CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n"
        else:
            req = "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n"
        s.sendall((req % (name, name)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        print(r[1].decode() if len(r) > 1 else "NONE")
    s.close()
except Exception:
    print("NONE")' "$@" "$name" 2>/dev/null
}

run_case()
{
	local loop="$1" p got arm="$WORK/arm.$1"

	p="$(pick_port)"
	FAILMALLOC_SIZE="$size" FAILMALLOC_ARM="$arm" \
	LD_PRELOAD="$WORK/failmalloc.so" \
		gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=1 --protocol-timeout=120 \
		--log-level=4
	: >"$arm"

	got="$(ask socks5 "$p")"
	[ "$got" = REP=0x04 ] || fail "$loop: SOCKS5 got '$got' (want REP=0x04)"
	got="$(ask http "$p")"
	[ "$got" = 502 ] || fail "$loop: HTTP CONNECT got '$got' (want 502)"
	got="$(ask get "$p")"
	[ "$got" = 502 ] || fail "$loop: HTTP GET got '$got' (want 502)"
	kill -0 "$GWP_PID" 2>/dev/null || fail "$loop: proxy died"
	grep -q "Failed to allocate DNS entry for $name" "$WORK/gwp.$p.log" || \
		fail "$loop: the allocation did not fail"
	grep -q "DNS query could not be started: $name" "$WORK/gwp.$p.log" || \
		fail "$loop: reason not logged"
	rm -f "$arm"
	return 0
}

cases=(epoll)
if have_io_uring; then
	cases+=(io_uring)
else
	diag "no usable io_uring here; skipping that loop"
fi
gwp_parallel run_case "${cases[@]}"

pass

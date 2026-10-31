#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Stopping the proxy while a raw-DNS query is still waiting for its answer.
# Normal connection teardown frees the query's packet and closes its
# socket, but the shutdown path that frees every live connection pair did
# not, so each pending query leaked its packet and host name at exit. The
# leak is only visible to LeakSanitizer, so this test needs a --sanitize
# build and skips otherwise.
#
# Raw DNS runs on epoll only: gwproxy refuses --raw-dns together with
# --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"
grep -q -- '-fsanitize=address' "$ROOT/config.make" 2>/dev/null || \
	skip "gwproxy built without --sanitize; the leak is only visible to LSan"

# A DNS server that takes 2 s to answer; it records how many queries came.
dp="$(pick_port)"
cnt="$WORK/dns.count"
python3 "$SERVERS_DIR/dns_malformed.py" slow "$dp" "$cnt" 2>/dev/null &
_PIDS+=("$!")
sleep 0.4

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1
log="$WORK/gwp.$p.log"

# Ask for a name and keep the client connected while it is resolved.
python3 - "$p" <<'PY' &
import socket, struct, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
c.sendall(b"\x05\x01\x00")
assert c.recv(2) == b"\x05\x00"
name = b"pending.example"
c.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name +
          struct.pack(">H", 80))
time.sleep(10)
PY
_PIDS+=("$!")

for _ in $(seq 1 100); do
	[ -s "$cnt" ] && break
	sleep 0.02
done
[ -s "$cnt" ] || fail "the proxy never sent the DNS query"

# Stop the proxy while the query is still pending.
kill -TERM "$GWP_PID"
for _ in $(seq 1 250); do
	kill -0 "$GWP_PID" 2>/dev/null || break
	sleep 0.02
done
kill -0 "$GWP_PID" 2>/dev/null && fail "gwproxy did not exit on SIGTERM"
wait "$GWP_PID"
st=$?

if grep -q 'LeakSanitizer\|AddressSanitizer' "$log"; then
	sed -n '/Sanitizer/,$p' "$log" | head -40 | sed 's/^/# gwp: /' >&2
	fail "gwproxy leaked memory at shutdown with a DNS query in flight"
fi
[ "$st" -eq 0 ] || fail "gwproxy exited with status $st"

pass

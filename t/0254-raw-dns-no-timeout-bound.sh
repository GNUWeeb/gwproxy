#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# With --protocol-timeout=0 nothing but the raw resolver's own tries bounds a
# lookup. A client that closes its write side during the lookup has made its
# request and is still owed the answer, so its FIN ends nothing; the lookup
# used to have no end of its own either, and with a DNS server that never
# answers, each such client left its socket and the query's for the life of
# the process.
#
# Twenty clients (SOCKS5 and HTTP CONNECT) ask for names the server never
# answers and close at once; the proxy's descriptor count must come back to
# where it was before them once the tries are spent (7 s). A client that stays
# connected gets REP 0x04 then, where it used to wait for ever.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

log="$WORK/dns.log"
python3 "$SERVERS_DIR/dns_drop_first.py" "$WORK/queries" >"$log" 2>&1 &
_PIDS+=("$!")
dp=
for _ in $(seq 1 200); do
	dp="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$log")"
	[ -n "$dp" ] && break
	sleep 0.05
done
[ -n "$dp" ] || fail "the DNS responder did not start"

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1 --protocol-timeout=0

nr_fds() { ls "/proc/$GWP_PID/fd" 2>/dev/null | wc -l; }
base="$(nr_fds)"
[ "$base" -gt 0 ] || fail "cannot count the proxy's descriptors"

# One client stays and waits for its answer; it prints it when it comes.
python3 -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
s.sendall(b"\x05\x01\x00"); s.recv(2)
d = b"silent-stay.example"
s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x00\x50")
try:
    r = s.recv(16)
    print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
except OSError:
    print("NONE")' "$p" >"$WORK/stay.out" 2>&1 &
stay=$!
_PIDS+=("$stay")

# The others close right after their request, with a FIN.
python3 -c '
import socket, sys, time
port = int(sys.argv[1])
for i in range(20):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    name = "silent-%d.example" % i
    if i % 2:
        s.sendall(("CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n"
                   % (name, name)).encode())
    else:
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x00\x50")
    s.close()' "$p" || fail "the closing clients could not connect"

# Every lookup has started: 21 first queries have come.
first=0
for _ in $(seq 1 200); do
	first="$(awk '!seen[$1]++' "$WORK/queries" 2>/dev/null | wc -l)"
	[ "$first" -ge 21 ] && break
	sleep 0.05
done
[ "$first" -ge 21 ] || fail "only $first of 21 lookups started"
diag "descriptors: $base before, $(nr_fds) with the lookups pending"

# The tries take 7 s; give them twice that, and more on a loaded host.
n=0
for _ in $(seq 1 300); do
	n="$(nr_fds)"
	[ "$n" -le "$base" ] && break
	sleep 0.1
done
diag "descriptors: $n after the wait"
[ "$n" -le "$base" ] || \
	fail "the proxy holds $n descriptors, $base before the lookups"

for _ in $(seq 1 100); do
	kill -0 "$stay" 2>/dev/null || break
	sleep 0.1
done
res="$(cat "$WORK/stay.out")"
[ "$res" = REP=0x04 ] || fail "the client that stayed got '$res' (want REP=0x04)"

kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
pass

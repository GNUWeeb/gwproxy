#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Two things about descriptors and time while a connection is being set up.
#
# A client may send its request and close its write side before the target is
# connected; the proxy holds the FIN and passes it on once the target is up,
# as the client may only have finished sending (t/0100). With
# --connect-timeout=0 nothing then bounded the wait: a target that never
# answered held the pair until the kernel gave up on the SYN, and a silent
# upstream proxy held it for ever. Once the client has half-closed during the
# connect, --protocol-timeout bounds it instead. Checked on both event loops
# through SOCKS5, HTTP CONNECT, plain forwarding and an upstream proxy that
# never answers; a client that keeps its write side open still waits without
# a limit, and a half-closed client of a slow but working target still gets
# its answer.
#
# A raw DNS query's socket closed at the end of its lookup was not credited
# to the accept throttle, which only counted it when the pair went away
# before the lookup ended. With accept stopped for want of descriptors, the
# lookups that ended then left accept stopped until its timed retry. Here
# lookups that fail free two descriptors each, the query's socket and the
# client's, which is enough to rearm accept at once; the client's alone is
# not.

. "$(dirname "$0")/lib.sh"
require python3

# A target whose accept queue is full: every SYN goes unanswered.
BH_PORT=""
python3 "$SERVERS_DIR/blackhole_listener.py" >"$WORK/bh.port" 2>&1 &
_PIDS+=("$!")
for _ in $(seq 1 100); do
	BH_PORT="$(head -n 1 "$WORK/bh.port" 2>/dev/null)"
	[ -n "$BH_PORT" ] && break
	sleep 0.05
done
[ -n "$BH_PORT" ] || fail "the black-hole target did not start"

# An upstream proxy that accepts and then never says a word.
SILENT_PORT=""
python3 -c '
import socket, threading
def hold(c):
    while c.recv(4096):
        pass
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(64)
print(s.getsockname()[1], flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=hold, args=(c,), daemon=True).start()' \
	>"$WORK/silent.port" 2>&1 &
_PIDS+=("$!")
for _ in $(seq 1 100); do
	SILENT_PORT="$(head -n 1 "$WORK/silent.port" 2>/dev/null)"
	[ -n "$SILENT_PORT" ] && break
	sleep 0.05
done
[ -n "$SILENT_PORT" ] || fail "the silent upstream did not start"

BOUND=2

# fin_bound <loop> <name> <client args>... -- <proxy args>...
fin_bound()
{
	local loop="$1" name="$2" pp got log
	local -a cargs=()

	shift 2
	while [ "$1" != -- ]; do
		cargs+=("$1")
		shift
	done
	shift
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --event-loop="$loop" --nr-workers=1 \
		--connect-timeout=0 --protocol-timeout="$BOUND" "$@"
	log="$WORK/gwp.$pp.log"
	got="$(timeout 120 python3 "$SERVERS_DIR/fin_during_connect.py" \
		"${cargs[0]}" "$pp" "${cargs[@]:1}" "$BOUND")"
	case "$got" in
	OK*) diag "[$loop] $name: $got" ;;
	*) fail "[$loop] $name: $got" ;;
	esac
	grep -q "Connection timeout!" "$log" || \
		fail "[$loop] $name: no connection timeout logged"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

run_loop()
{
	local loop="$1" pp tp d got

	fin_bound "$loop" "SOCKS5" socks5 "$BH_PORT" -- --as-socks5=1
	fin_bound "$loop" "HTTP CONNECT" http "$BH_PORT" -- --as-http=1
	fin_bound "$loop" "plain forwarding" plain -- \
		--target="127.0.0.1:$BH_PORT"
	fin_bound "$loop" "silent upstream" plain -- \
		--target="127.0.0.1:$BH_PORT" \
		--upstream-proxy="socks5://127.0.0.1:$SILENT_PORT"

	# A target that answers late, but within the bound: the half-closed
	# client still gets the answer to its request.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --connect-timeout=0 --protocol-timeout=30
	for d in data nodata; do
		got="$(timeout 60 python3 "$SERVERS_DIR/connect_eof.py" socks5 "$pp" "$d")"
		[ "$got" = OK ] || fail "[$loop] slow target, SOCKS5, $d: $got"
	done
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	pp="$(pick_port)"
	tp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--event-loop="$loop" --nr-workers=1 --connect-timeout=0 \
		--protocol-timeout=30
	got="$(timeout 60 python3 "$SERVERS_DIR/connect_eof.py" plain "$pp" "$tp" data)"
	[ "$got" = OK ] || fail "[$loop] slow target, plain forwarding: $got"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

loops=(epoll)
if grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null; then
	loops+=(io_uring)
else
	diag "gwproxy built without io_uring; skipping that loop"
fi
gwp_parallel run_loop "${loops[@]}"

# ------------------------------------------------- raw DNS and accept ----
if ! grep -q CONFIG_NEW_DNS_RESOLVER "$ROOT/config.h" 2>/dev/null; then
	diag "gwproxy built without the raw DNS resolver; skipping that part"
	pass
fi
soft="$(ulimit -Sn)"
if [ "$soft" != unlimited ] && [ "$soft" -lt 256 ]; then
	diag "harness fd limit ($soft) too low; skipping the raw DNS part"
	pass
fi

names="$WORK/dns.names"
release="$WORK/dns.release"
dport="$(pick_port)"
python3 "$SERVERS_DIR/dns_hold.py" "$dport" "$names" "$release" \
	>"$WORK/dns.log" 2>&1 &
_PIDS+=("$!")
for _ in $(seq 1 100); do
	grep -q READY "$WORK/dns.log" 2>/dev/null && break
	sleep 0.05
done
grep -q READY "$WORK/dns.log" || fail "the DNS server did not start"

# One worker: accept rearms early once more than 9 descriptors were returned
# (rearm_accept()), else after 5 seconds. Seven failed lookups return 14
# with the query sockets, 7 without.
pp="$(pick_port)"
( ulimit -n 64; exec "$GWPROXY" --event-loop=epoll --as-socks5=1 \
	--bind="127.0.0.1:$pp" --acl-allow-all --nr-workers=1 \
	--raw-dns=1 --dns-server="127.0.0.1:$dport" --protocol-timeout=60 \
	--log-level=3 ) >"$WORK/gwp.dns.log" 2>&1 &
gwp_pid=$!
_PIDS+=("$gwp_pid")
wait_listen "$pp" "$gwp_pid" || fail "proxy did not listen"

out="$(timeout 120 python3 - "$pp" "$names" "$release" <<-'PY'
import os, socket, struct, sys, time
port, names, release = int(sys.argv[1]), sys.argv[2], sys.argv[3]
NR_LOOKUPS = 7

def greet(c, timeout):
    c.settimeout(timeout)
    try:
        return c.recv(2) == b"\x05\x00"
    except (socket.timeout, ConnectionResetError):
        return False

# Lookups held by the DNS server, each with a query socket open.
lookups = []
for i in range(NR_LOOKUPS):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    host = b"holdnx%d.test" % i
    c.sendall(b"\x05\x01\x00" + b"\x05\x01\x00\x03" + bytes([len(host)]) +
              host + struct.pack(">H", 80))
    if not greet(c, 10):
        print("lookup client %d: no greeting reply" % i)
        sys.exit(1)
    lookups.append(c)
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        with open(names) as f:
            if len(f.read().split()) == NR_LOOKUPS:
                break
    except OSError:
        pass
    time.sleep(0.05)
else:
    print("the lookups did not all reach the DNS server")
    sys.exit(1)

# Idle clients until one is left waiting in the listen backlog.
idle, waiting = [], None
for _ in range(64):
    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    t0 = time.monotonic()
    c.sendall(b"\x05\x01\x00")
    if greet(c, 0.5):
        idle.append(c)
        continue
    waiting = c
    break
if waiting is None:
    print("never ran out of descriptors (%d idle clients)" % len(idle))
    sys.exit(1)

# Let the lookups fail: each pair answers its client and goes.
open(release, "w").close()
for i, c in enumerate(lookups):
    c.settimeout(10)
    try:
        rep = c.recv(16)
    except OSError as e:
        rep = repr(e).encode()
    if rep[:1] != b"\x05" or rep[1:2] == b"\x00":
        print("lookup client %d: reply %r" % (i, rep))
        sys.exit(1)
    c.close()

# Accept must come back at once, not at its 5 s timed retry.
ok = greet(waiting, 10)
took = time.monotonic() - t0
if not ok:
    print("the waiting client was never accepted")
    sys.exit(1)
if took >= 4.0:
    print("accept resumed only after %.1f s, at its timed retry" % took)
    sys.exit(2)
print("ok: accept resumed after %.1f s, %d idle clients" % (took, len(idle)))
PY
)"
rc=$?
diag "raw DNS: $out"
kill -0 "$gwp_pid" 2>/dev/null || fail "proxy died"
[ "$rc" = 0 ] || fail "raw DNS: $out"
kill "$gwp_pid" 2>/dev/null
wait "$gwp_pid" 2>/dev/null

pass

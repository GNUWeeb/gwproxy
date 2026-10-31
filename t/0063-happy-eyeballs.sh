#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Multi-address targets (RFC 8305). A name that resolves to several addresses
# must not be hostage to the first one:
#
#   (a) fallback -- when the first address actively fails (refused), the next
#       is tried and the transfer still succeeds;
#   (b) racing   -- when the first address is black-holed (SYNs dropped, so it
#       never reports anything), the next joins the race after the Connection
#       Attempt Delay. Without racing this case costs the entire
#       --connect-timeout, so the assertion is on elapsed time, not just
#       success: a passing run must beat the timeout by a wide margin.
#
# Controlling which addresses a name has means controlling /etc/hosts, so the
# body runs inside a private user+mount namespace with a hosts file bind-mounted
# over the real one. Nothing outside the namespace is touched.
#
# The namespace has its own network stack too. The body listens on fixed ports
# (it has to name them in the hosts entries' targets and in each request), and
# on the host's network two runs of this test at once -- `make -jN` in two
# checkouts, say -- would fight over them and fail at random.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require unshare
require ip

# Re-exec: everything below the marker runs inside the namespace. ns_drop_setup
# has to stay in this branch -- inside, "id -u" is the MAPPED root, and its
# chown to the outer uid would fail with EINVAL, that uid having no mapping
# there. See lib.sh for why the drop is needed at all.
if [ "${1:-}" != "--inner" ]; then
	ns_drop_setup
	$NS_DROP unshare -rmn --map-root-user true 2>/dev/null \
		|| skip "no user+mount+net namespaces (unshare -rmn) available"
	out="$WORK/inner.out"
	# Detached: a backgrounded proxy holding the pipe would wedge the read.
	setsid $NS_DROP unshare -rmn --map-root-user "$0" --inner "$WORK" \
		</dev/null >"$out" 2>&1 &
	for i in $(seq 1 60); do
		grep -q '^INNER-DONE' "$out" 2>/dev/null && break
		sleep 1
	done
	sed 's/^/# /' "$out" >&2
	grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
	pass
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
rc=1

# setsid put this run in its own session, so the runner's process-group sweep
# cannot see anything started here -- it has to reap itself. "kill 0" signals
# exactly this group: the origin, the black hole and any proxy still up.
cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	_release_ports		# lib.sh's _cleanup, which would, is replaced
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

ip link set lo up || exit 1

# 127.0.0.7 is refused (nothing listens), 127.0.0.8 black-holes, 127.0.0.9 lives.
op=39701
printf '127.0.0.7 he-refused\n127.0.0.9 he-refused\n' >"$WORK/hosts"
printf '127.0.0.8 he-blackhole\n127.0.0.9 he-blackhole\n' >>"$WORK/hosts"
cat /etc/hosts >>"$WORK/hosts"
mount --bind "$WORK/hosts" /etc/hosts || exit 1

# The live origin.
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header('Content-Length','2'); s.end_headers()
        s.wfile.write(b'ok')
    def log_message(*a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.9', $op), H).serve_forever()" >/dev/null 2>&1 &
origin_pid=$!

# The black hole: smallest backlog, then fill the accept queue so further SYNs
# are dropped and connect() sits in SYN_SENT instead of being refused.
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.8', $op)); s.listen(0)
f = []
for _ in range(16):
    c = socket.socket(); c.setblocking(False)
    try: c.connect_ex(('127.0.0.8', $op))
    except OSError: pass
    f.append(c)
print('READY', flush=True)
while True: time.sleep(3600)" >"$WORK/blackhole.out" 2>&1 &
bh_pid=$!

# Both listen on port $op, so only the pid tells whose listener ss sees. The
# black hole is ready once its queue is full, which it reports.
wait_listen "$op" "$origin_pid" || { echo "origin did not listen"; exit 1; }
for i in $(seq 1 100); do
	grep -q '^READY' "$WORK/blackhole.out" 2>/dev/null && break
	kill -0 "$bh_pid" 2>/dev/null || break
	sleep 0.1
done
grep -q '^READY' "$WORK/blackhole.out" || { echo "black hole did not start"; exit 1; }

# The resolver decides the order (RFC 6724), so only run the cases whose bad
# address really is tried first -- otherwise the test proves nothing.
order_of() {
	python3 -c "
import socket, sys
print(' '.join(r[4][0] for r in
      socket.getaddrinfo(sys.argv[1], 80, socket.AF_UNSPEC, socket.SOCK_STREAM)))" "$1"
}

fetch() {				# $1=port $2=host $3=delay ; prints code+secs
	python3 -c "
import subprocess, sys, time
t0 = time.time()
p = subprocess.run(['curl','-s','-o','/dev/null','-w','%{http_code}',
                    '--max-time','20','-x','socks5h://127.0.0.1:'+sys.argv[1],
                    'http://'+sys.argv[2]+':'+sys.argv[3]+'/x'],
                   capture_output=True, text=True)
print('%s %.2f' % (p.stdout.strip() or '000', time.time() - t0))" "$1" "$2" "$op"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# (a) Fallback past a refused address.
	if [ "$(order_of he-refused | cut -d' ' -f1)" = "127.0.0.7" ]; then
		pp=39711
		"$GWPROXY" --bind=127.0.0.1:$pp --as-socks5=1 --nr-workers=1 \
			--acl-allow-all --event-loop="$loop" --connect-timeout=10 \
			>/dev/null 2>&1 &
		gwp_pid=$!
		wait_listen "$pp" "$gwp_pid" || { echo "[$loop] gwproxy did not listen on $pp"; exit 1; }
		set -- $(fetch "$pp" he-refused)
		echo "[$loop] refused-first: code=$1 elapsed=$2"
		kill "$gwp_pid" 2>/dev/null
		[ "$1" = 200 ] || exit 1
	else
		echo "[$loop] refused-first: skipped (resolver put the live address first)"
	fi

	# (b) Race past a black-holed address. Without racing this costs the
	#     full --connect-timeout=10, so require it well under that.
	if [ "$(order_of he-blackhole | cut -d' ' -f1)" = "127.0.0.8" ]; then
		pp=39712
		"$GWPROXY" --bind=127.0.0.1:$pp --as-socks5=1 --nr-workers=1 \
			--acl-allow-all --event-loop="$loop" --connect-timeout=10 \
			--connect-attempt-delay=250 >/dev/null 2>&1 &
		gwp_pid=$!
		wait_listen "$pp" "$gwp_pid" || { echo "[$loop] gwproxy did not listen on $pp"; exit 1; }
		set -- $(fetch "$pp" he-blackhole)
		echo "[$loop] blackhole-first: code=$1 elapsed=$2"
		kill "$gwp_pid" 2>/dev/null
		[ "$1" = 200 ] || exit 1
		# 3s leaves room for scheduling noise while staying far below
		# the 10s timeout a non-racing build would take.
		python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 3.0 else 1)" "$2" \
			|| exit 1
	else
		echo "[$loop] blackhole-first: skipped (resolver put the live address first)"
	fi

	# (c) A denial that is not the reason the request failed. The first
	#     address is allowed and refuses the connection; the second is
	#     denied by the ACL. The client must be told the connection was
	#     refused (REP 0x05), not that the ACL rejected it (REP 0x02) --
	#     the denial only applies to an address that was never the
	#     problem.
	if [ "$(order_of he-refused | cut -d' ' -f1)" = "127.0.0.7" ]; then
		printf -- '%s\n' \
			'-A OUTPUT -d 127.0.0.9 -j REJECT' \
			'-P OUTPUT ACCEPT' >"$WORK/mixed.acl"
		pp=39713
		"$GWPROXY" --bind=127.0.0.1:$pp --as-socks5=1 --nr-workers=1 \
			--acl-file="$WORK/mixed.acl" --event-loop="$loop" \
			--connect-timeout=10 >/dev/null 2>&1 &
		gwp_pid=$!
		wait_listen "$pp" "$gwp_pid" || { echo "[$loop] gwproxy did not listen on $pp"; exit 1; }
		rep=$(python3 "$ROOT/t/servers/socks5_probe.py" \
			--atyp domain --dst he-refused "$pp" "$op")
		echo "[$loop] refused-then-denied: $rep"
		kill "$gwp_pid" 2>/dev/null
		[ "$rep" = "REP=0x05" ] || exit 1
	else
		echo "[$loop] refused-then-denied: skipped (resolver put the live address first)"
	fi
done

rc=0

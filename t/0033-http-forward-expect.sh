#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Forwarding HTTP proxy + "Expect: 100-continue" (RFC 9110 Section 10.1.1).
# The proxy forwards the expectation to the origin, so:
#   (a) an authenticated POST is forwarded and its body is relayed (the origin
#       drives the 100 Continue), and
#   (b) a POST that fails proxy authentication is rejected with 407 *before* the
#       origin is contacted, so the body is never sent upstream (no wasted
#       round-trip). The origin logs one line per request it receives, so the
#       test can confirm a rejected request left nothing behind.
# A run of interim responses longer than the proxy's buffer is relayed whole.

. "$(dirname "$0")/lib.sh"
require curl
require python3

op="$(pick_port)"
olog="$WORK/origin.log"
: >"$olog"
python3 "$SERVERS_DIR/expect_origin.py" "$op" "$olog" >"$WORK/origin.out" 2>&1 &
opid=$!
_PIDS+=("$opid")
wait_listen "$op" "$opid" || fail "Expect origin did not start on port $op"

printf 'user:pass\n' >"$WORK/auth"
make_payload "$WORK/body.bin" 8000	# large enough that curl uses Expect

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2

	# (a) Unauthenticated POST: 407, and the origin must not be contacted.
	before="$(wc -l <"$olog")"
	code="$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
		-x "http://127.0.0.1:$pp" -H 'Expect: 100-continue' \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$op/x")"
	[ "$code" = 407 ] \
		|| fail "[$loop] unauthenticated forward POST got $code, expected 407"
	after="$(wc -l <"$olog")"
	[ "$before" = "$after" ] \
		|| fail "[$loop] rejected request body was forwarded to the origin"

	# (b) Authenticated POST: forwarded, and the whole body reaches the origin.
	code="$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
		-x "http://user:pass@127.0.0.1:$pp" -H 'Expect: 100-continue' \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$op/x")"
	[ "$code" = 200 ] \
		|| fail "[$loop] authenticated forward POST got $code, expected 200"
	got="$(tail -n1 "$olog")"
	[ "$got" = 8000 ] \
		|| fail "[$loop] origin received $got body bytes, expected 8000"

	# (c) The interim response must actually reach the client. curl waits
	#     only ~1s for the 100 Continue and then sends the body anyway, so
	#     the assertions above hold even if the 100 never arrives. This
	#     client writes no body byte until it sees the 100, so a proxy that
	#     withholds origin->client data until the client writes more is
	#     caught here instead of silently passing.
	python3 "$SERVERS_DIR/expect_client.py" "$pp" "$op" \
		|| fail "[$loop] proxy did not relay the origin's 100 Continue"

	kill "$GWP_PID" 2>/dev/null

	# (d) A burst of interim responses larger than the proxy's buffer, sent
	#     at once, reaches the client whole, followed by the final response.
	#     A read that filled the room left for the header exactly was taken
	#     for a header too large, and the client got a 502 instead.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --target-buf-size=1024
	out="$(timeout 60 python3 - "$pp" <<'PY'
import socket, sys, threading

INTERIM = b"HTTP/1.1 100 Continue\r\n\r\n"
N = 2000
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(1)


def origin():
    c, _ = ls.accept()
    c.recv(65536)
    c.sendall(INTERIM * N + b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
    c.shutdown(socket.SHUT_WR)
    try:
        c.recv(1)
    except OSError:
        pass
    c.close()


threading.Thread(target=origin, daemon=True).start()
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
c.sendall(b"GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n\r\n" % ls.getsockname()[1])
got = b""
while True:
    d = c.recv(65536)
    if not d:
        break
    got += d
n = got.count(INTERIM)
final = got[len(INTERIM) * n:]
if n != N or not final.startswith(b"HTTP/1.1 200 OK\r\n") or not final.endswith(b"\r\n\r\ndone"):
    print("%d of %d interim responses, then %r" % (n, N, final[:80]))
    sys.exit(1)
PY
)" || fail "[$loop] interim burst: $out"
	kill "$GWP_PID" 2>/dev/null
done

pass

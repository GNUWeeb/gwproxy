#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A forwarding request is served one per connection, against an origin that
# would like it otherwise.
#
# The proxy used to rewrite only the first request header and then relay both
# directions raw. An origin answering "Connection: keep-alive" got the client
# to reuse its proxy connection, and the client's next request -- meant for
# another host, carrying that host's cookies and the client's
# Proxy-Authorization -- went to the first origin instead, past the ACL. curl
# does this when given two URLs. A 407 from the origin was relayed too, inviting
# the client to resend with its proxy credentials.
#
# keepalive_origin.py is that origin: it ignores "Connection: close", answers
# keep-alive, and logs every byte it receives. Checked on every event loop:
#   (1) neither a second URL (curl) nor a pipelined second request (raw client,
#       which ignores what the proxy says) reaches it, and Proxy-Authorization
#       never does;
#   (2) the client is told "Connection: close", not the origin's keep-alive;
#   (3) request bodies framed by Content-Length and by chunked encoding still
#       arrive intact, and nothing after them does;
#   (4) its 407 reaches the client as a 502, without the challenge;
#   (5) a request whose Connection header names Content-Length is refused with
#       400 and never forwarded.

. "$(dirname "$0")/lib.sh"
require curl
require python3

ep="$(pick_port)"
raw="$WORK/evil.raw"
reqs="$WORK/evil.req"
: >"$raw"
: >"$reqs"
python3 "$SERVERS_DIR/keepalive_origin.py" "$ep" "$raw" "$reqs" \
	>"$WORK/evil.out" 2>&1 &
_PIDS+=("$!")
wait_listen "$ep" "$!" || fail "keep-alive origin did not listen on $ep"

# The honest origin the second URL is meant for.
DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/other.bin" 3000
hp="$(pick_port)"
start_httpd "$hp" "$DOC"

make_payload "$WORK/body.bin" 300000
body_sha="$(sha256sum "$WORK/body.bin" | cut -d' ' -f1)"
printf 'alice:secret\n' >"$WORK/auth"

# raw_exchange <proxy port> <bytes as a Python literal>: send the bytes in one
# write, as a client that pipelines would, and print the response header.
raw_exchange()
{
	timeout 20 python3 -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(5)
s.sendall(eval(sys.argv[2]))
buf = b""
try:
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            break
        buf += d
except OSError:
    pass
sys.stdout.write(buf.partition(b"\r\n\r\n")[0].decode("latin-1") + "\n")
' "$1" "$2"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2
	px="http://alice:secret@127.0.0.1:$pp"
	: >"$raw"
	: >"$reqs"

	# (1) + (2): curl reuses a proxy connection the origin calls keep-alive.
	curl -sv --max-time 20 -x "$px" \
		"http://127.0.0.1:$ep/first" -o "$WORK/first.out" \
		"http://localhost:$hp/other.bin" -o "$WORK/other.out" \
		2>"$WORK/curl.$loop.err" \
		|| fail "[$loop] curl through the proxy failed"
	assert_files_equal "$DOC/other.bin" "$WORK/other.out" \
		"[$loop] the second URL was not answered by its own origin"
	grep -qi '^< Connection: close' "$WORK/curl.$loop.err" \
		|| fail "[$loop] client was not told Connection: close"
	! grep -qi '^< Connection: keep-alive\|^< Keep-Alive' \
		"$WORK/curl.$loop.err" \
		|| fail "[$loop] origin's keep-alive reached the client"

	# A client that pipelines regardless of what it is told.
	hdr="$(raw_exchange "$pp" "b'GET http://127.0.0.1:$ep/a HTTP/1.1\\r\\nHost: x\\r\\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\\r\\n\\r\\nGET http://localhost:$hp/pipelined HTTP/1.1\\r\\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\\r\\n\\r\\n'")"
	case "$hdr" in
	"HTTP/1.1 200 OK"*) ;;
	*) fail "[$loop] pipelined request: got '$hdr'" ;;
	esac
	sleep 0.5

	! grep -q 'other\.bin\|pipelined' "$raw" \
		|| fail "[$loop] a request meant for another host reached the origin"
	! grep -qi 'Proxy-Authorization' "$raw" \
		|| fail "[$loop] Proxy-Authorization reached the origin"
	[ "$(wc -l <"$reqs")" = 2 ] \
		|| fail "[$loop] origin saw $(wc -l <"$reqs") requests, want 2"

	# (3) Request bodies, as Content-Length and as chunked.
	: >"$reqs"
	curl -s --max-time 20 -o /dev/null -x "$px" \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$ep/cl" \
		|| fail "[$loop] Content-Length POST failed"
	curl -s --max-time 20 -o /dev/null -x "$px" \
		-H 'Transfer-Encoding: chunked' \
		--data-binary @"$WORK/body.bin" "http://127.0.0.1:$ep/chunked" \
		|| fail "[$loop] chunked POST failed"
	hdr="$(raw_exchange "$pp" "b'POST http://127.0.0.1:$ep/trailer HTTP/1.1\\r\\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n3;x=y\\r\\nabc\\r\\n0\\r\\nX-T: 1\\r\\n\\r\\nGET /smuggled HTTP/1.1\\r\\n\\r\\n'")"
	case "$hdr" in
	"HTTP/1.1 200 OK"*) ;;
	*) fail "[$loop] chunked request with trailers: got '$hdr'" ;;
	esac
	sleep 0.5
	grep -qx "POST /cl 300000 $body_sha" "$reqs" \
		|| fail "[$loop] Content-Length body did not arrive intact"
	grep -qx "POST /chunked 300000 $body_sha" "$reqs" \
		|| fail "[$loop] chunked body did not arrive intact"
	grep -qx "POST /trailer 3 $(printf abc | sha256sum | cut -d' ' -f1)" \
		"$reqs" || fail "[$loop] chunked body with trailers did not arrive"
	! grep -q smuggled "$reqs" \
		|| fail "[$loop] bytes after a chunked body reached the origin"

	# (4) The origin's 407 is not passed on as a challenge.
	code="$(curl -s --max-time 20 -D "$WORK/h407" -o /dev/null \
		-w '%{http_code}' -x "$px" "http://127.0.0.1:$ep/407")"
	[ "$code" = 502 ] || fail "[$loop] origin's 407 reached the client as $code"
	! grep -qi 'Proxy-Authenticate' "$WORK/h407" \
		|| fail "[$loop] origin's Proxy-Authenticate reached the client"

	# (5) Connection: Content-Length would split the request at the origin.
	: >"$reqs"
	hdr="$(raw_exchange "$pp" "b'POST http://127.0.0.1:$ep/cc HTTP/1.1\\r\\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\\r\\nConnection: Content-Length\\r\\nContent-Length: 30\\r\\n\\r\\nGET /split HTTP/1.1\\r\\nX: y\\r\\n\\r\\n'")"
	case "$hdr" in
	"HTTP/1.1 400 "*) ;;
	*) fail "[$loop] Connection: Content-Length got '$hdr', want 400" ;;
	esac
	sleep 0.3
	[ ! -s "$reqs" ] || fail "[$loop] refused request reached the origin"

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

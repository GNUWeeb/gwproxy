#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The authority of an absolute-form request-target ends at the first '/', '?'
# or '#' (RFC 3986 Section 3.2). Ending it only at '/' let
# "http://A?@B/" and "http://A#@B/" connect to B, while every other URL parser
# (a filter, a log reader) reads the host as A. Here A is a closed port and B
# the origin: the request must not reach the origin. A query right after the
# authority ("http://B?q") is a valid target and must be served, with "/?q" as
# the origin-form target. A port that is not a decimal 1-65535 (one that would
# wrap modulo 65536, or a service name) is refused with a 400.
# Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 1000

hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# A reserved port nothing listens on.
cp="$(pick_port)"

# fetch <proxy port> <request-target>: print the status line of the reply
# ("<no reply>" when the proxy closes without one), then the body.
fetch()
{
	python3 -c '
import socket, sys
proxy, target = int(sys.argv[1]), sys.argv[2]
req = ("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % target).encode()
s = socket.create_connection(("127.0.0.1", proxy), timeout=10)
s.sendall(req)
buf = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        buf += c
except Exception:
    pass
s.close()
head, _, body = buf.partition(b"\r\n\r\n")
sys.stdout.write((head.split(b"\r\n")[0].decode() if head else "<no reply>") + "\n")
sys.stdout.flush()
sys.stdout.buffer.write(body)' "$1" "$2"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-http=1 --as-socks5=0 \
		--event-loop="$loop" --nr-workers=1

	# Control: the plain target is served.
	out="$WORK/out.$loop"
	fetch "$p" "http://127.0.0.1:$hp/index.html" >"$out"
	st="$(head -1 "$out")"
	case "$st" in
	"HTTP/1.1 200 OK"|"HTTP/1.0 200 OK") ;;
	*) fail "[$loop] control request got '$st' (want 200)" ;;
	esac

	# The host before '?' or '#' is the target, not the one after '@'.
	for t in "http://127.0.0.1:$cp?@127.0.0.1:$hp/index.html" \
		 "http://127.0.0.1:$cp#@127.0.0.1:$hp/index.html"; do
		st="$(fetch "$p" "$t" | head -1)"
		case "$st" in
		*" 200 "*) fail "[$loop] $t reached the origin after '@' ('$st')" ;;
		esac
	done

	# A query with an empty path is forwarded with "/" as its path.
	fetch "$p" "http://127.0.0.1:$hp?x=1" >"$out"
	st="$(head -1 "$out")"
	case "$st" in
	"HTTP/1.1 200 OK"|"HTTP/1.0 200 OK") ;;
	*) fail "[$loop] query without a path got '$st' (want 200)" ;;
	esac
	tail -n +2 "$out" >"$out.body"
	assert_files_equal "$DOC/index.html" "$out.body" \
		"[$loop] query without a path: wrong body"

	# Ports that are not ports: wrapping, service names, signs.
	for t in "http://127.0.0.1:$((hp + 65536))/index.html" \
		 "http://127.0.0.1:http/index.html" \
		 "http://127.0.0.1:+$hp/index.html"; do
		st="$(fetch "$p" "$t" | head -1)"
		case "$st" in
		"HTTP/1."?" 400 "*) ;;
		*) fail "[$loop] $t got '$st' (want 400)" ;;
		esac
	done

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

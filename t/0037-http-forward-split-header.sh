#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A forwarding request whose header arrives in more than one read.
#
# The proxy rewrites an absolute-form request into origin-form before sending
# it on, and it sized the buffer for that from how much header the parser
# consumed on its final call. But the caller advances its buffer by whatever
# was consumed each time, so a resumed parse only ever sees the remainder: on
# the last call that number describes the tail, not the header. A request
# large enough to span two reads therefore got a buffer sized for its last few
# bytes, overran it, and was dropped -- and not even as an HTTP error, since
# the -E2BIG was flattened into "invalid request" and the connection simply
# closed.
#
# Headers cross a segment boundary routinely: cookies alone take an ordinary
# browser request past a single MSS. Nothing else in t/ splits one, which is
# why this survived.
#
# The header here is padded well past any plausible single-write size, and the
# split point is swept from one byte to several hundred. The old code failed
# for every tail below roughly half the header; a fixed threshold would let a
# future regression hide on either side of it, so the sweep covers both.
#
# Asserted on every event loop, and against the payload rather than just the
# status line, so a 200 carrying the wrong body still fails.

. "$(dirname "$0")/lib.sh"
require python3

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 4096

hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# Send an absolute-form request, optionally splitting the final <tail> bytes
# into a second write, and print the status line followed by the body.
fetch_split()
{
	python3 -c '
import socket, sys, time
proxy, origin, tail = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
pad = "".join("X-Pad-%03d: %s\r\n" % (i, "p" * 40) for i in range(30))
req = ("GET http://127.0.0.1:%d/index.html HTTP/1.1\r\n"
       "Host: 127.0.0.1:%d\r\n%s\r\n" % (origin, origin, pad)).encode()
s = socket.socket()
s.settimeout(10)
s.connect(("127.0.0.1", proxy))
if tail <= 0:
    s.sendall(req)
else:
    s.sendall(req[:-tail])
    time.sleep(0.15)
    s.sendall(req[-tail:])
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
sys.stdout.buffer.write(body)' "$1" "$2" "$3"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-http=1 --as-socks5=0 \
		--event-loop="$loop" --nr-workers=1

	# tail=0 is the unsplit control: if it fails, the rest means nothing.
	for tail in 0 1 5 20 200 700; do
		out="$WORK/out.$loop.$tail"
		fetch_split "$p" "$hp" "$tail" >"$out" 2>/dev/null

		status="$(head -1 "$out")"
		case "$status" in
		"HTTP/1.1 200 OK"|"HTTP/1.0 200 OK")
			;;
		*)
			fail "[$loop] tail=$tail: expected 200, got '${status:-<nothing>}'"
			;;
		esac

		tail -n +2 "$out" >"$out.body"
		assert_files_equal "$DOC/index.html" "$out.body" \
			"[$loop] tail=$tail: wrong body"
	done

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

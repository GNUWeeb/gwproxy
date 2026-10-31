#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Request headers the proxy refuses, and how it says so.
#
# Every field line costs a lookup among the fields already stored, so a header
# made of thousands of tiny fields costs time quadratic in its size, before
# any authentication. The proxy accepts at most 128 field lines and answers
# 431 past that, as it does for a header longer than it accepts.
#
# A field that may appear only once (Host, Content-Length, ...) sent twice is
# refused too, and used to be answered with a bare close; it gets a 400.
#
# A header just under the field limit is the control, so a proxy refusing
# everything could not pass. Checked on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

DOC="$WORK/doc"
mkdir -p "$DOC"
make_payload "$DOC/index.html" 1024

hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# status <proxy_port> <origin_port> <case>: send the request for <case> and
# print the status line of the reply ("NOREPLY" if the proxy just closed).
# NOTE: <<- strips leading tabs, so the python below indents with spaces.
status()
{
	python3 - "$1" "$2" "$3" <<-'PY'
	import socket, sys
	proxy, origin, case = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
	head = "GET http://127.0.0.1:%d/index.html HTTP/1.1\r\n" % origin
	# The limit is on field lines, merged or not. Repeated Accept lines
	# reach the origin as one field, which keeps the test's origin (it
	# refuses more than 100 fields itself) out of the way.
	if case == "fields-ok":
	    fields = "Host: 127.0.0.1\r\n" + "Accept: */*\r\n" * 127
	elif case == "fields-over":
	    fields = "Host: 127.0.0.1\r\n" + "Accept: */*\r\n" * 128
	elif case == "long-field":
	    fields = "X-Long: " + "a" * 17000 + "\r\n"
	elif case == "dup-host":
	    fields = "Host: 127.0.0.1\r\nHost: example.com\r\n"
	else:
	    raise SystemExit("unknown case " + case)
	req = (head + fields + "\r\n").encode()
	s = socket.create_connection(("127.0.0.1", proxy))
	s.settimeout(10)
	try:
	    s.sendall(req)
	except OSError:
	    pass
	buf = b""
	try:
	    while b"\r\n" not in buf:
	        c = s.recv(4096)
	        if not c:
	            break
	        buf += c
	except OSError:
	    pass
	print(buf.split(b"\r\n", 1)[0].decode("latin-1") if buf else "NOREPLY")
	PY
}

# expect <loop> <case> <status line>: the reply must start with exactly this
# status line; the reason phrase tells the proxy's own replies apart from the
# origin's.
expect()
{
	local loop="$1" case="$2" want="$3" got
	got="$(status "$p" "$hp" "$case")"
	[ "$got" = "$want" ] || fail "[$loop] $case: expected '$want', got '$got'"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-http=1 --as-socks5=0 \
		--event-loop="$loop" --nr-workers=1

	expect "$loop" fields-ok "HTTP/1.1 200 OK"
	expect "$loop" fields-over "HTTP/1.1 431 Request Header Fields Too Large"
	expect "$loop" long-field "HTTP/1.1 431 Request Header Fields Too Large"
	expect "$loop" dup-host "HTTP/1.1 400 Bad Request"

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

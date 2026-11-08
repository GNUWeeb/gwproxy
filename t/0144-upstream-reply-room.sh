#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The reply to a client goes in front of whatever the destination sent behind
# the upstream proxy's own CONNECT reply, and it can be longer than that reply.
# However much of the destination's data the first read brought, there must be
# room for it: the client gets its reply and every byte, in order, also when
# the upstream's reply and the early data fill the target buffer. A reply that
# really cannot fit is still answered with a failure, at once.

. "$(dirname "$0")/lib.sh"
require python3

have_v6=0
python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::1", 0)); s.close()' 2>/dev/null && have_v6=1

# drive <proxy port> <upstream addr> <upstream port> <socks5|http> <client> <n>...
# Be the upstream, and the client. For each size, the upstream answers the
# CONNECT with its reply and n bytes of early data in one send. Prints a line
# per size: "<n> ok" or "<n> <what went wrong>".
drive()
{
	python3 - "$@" <<-'PY'
	import os, socket, sys, threading
	pp, addr, up, scheme, front = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
	S5_REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"
	if "S5_LONG_BOUND" in os.environ:
	    S5_REPLY = b"\x05\x00\x00\x03\xff" + b"a" * 255 + b"\x00\x50"
	HTTP_REPLY = b"HTTP/1.0 200\r\n\r\n"
	OK_200 = b"HTTP/1.1 200 OK\r\n\r\n"
	fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
	ls = socket.socket(fam)
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ls.bind((addr, up))
	ls.listen(8)
	def upstream(early):
	    c, _ = ls.accept()
	    c.settimeout(60)
	    try:
	        if scheme == "socks5":
	            c.recv(100)
	            c.sendall(b"\x05\x00")
	            c.recv(4096)
	            c.sendall(S5_REPLY + early)
	        else:
	            c.recv(4096)
	            c.sendall(HTTP_REPLY + early)
	        while c.recv(65536):
	            pass
	    except OSError:
	        pass
	    c.close()
	def one(n):
	    early = os.urandom(n)
	    t = threading.Thread(target=upstream, args=(early,), daemon=True)
	    t.start()
	    c = socket.create_connection(("127.0.0.1", pp))
	    c.settimeout(60)
	    if front == "socks5":
	        c.sendall(b"\x05\x01\x00")
	        c.recv(2)
	        c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
	    else:
	        c.sendall(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
	    got = b""
	    want = None
	    res = None
	    try:
	        while True:
	            if front == "socks5" and want is None and len(got) >= 4:
	                want = {1: 10, 4: 22}.get(got[3], 0) + n
	            elif front != "socks5":
	                want = len(OK_200) + n
	            if want is not None and len(got) >= want:
	                break
	            d = c.recv(65536)
	            if not d:
	                res = "closed after %d bytes: %r" % (len(got), got[:12])
	                break
	            got += d
	    except socket.timeout:
	        res = "timeout after %d bytes" % len(got)
	    except OSError as e:
	        res = "%s after %d bytes" % (e, len(got))
	    if res is None:
	        hdr = want - n
	        if front == "socks5":
	            good = got[:2] == b"\x05\x00"
	        else:
	            good = got[:hdr] == OK_200
	        res = "ok" if good and got[hdr:] == early else "wrong data"
	    c.close()
	    t.join(60)
	    return res
	for a in sys.argv[6:]:
	    print(a, one(int(a)).replace(" ", "_"), flush=True)
	PY
}

# check <label> <proxy port> <upstream addr> <upstream port> <socks5|http> <client> <n>...
check()
{
	local label="$1" n res rest
	shift
	rest=0
	while read -r n res; do
		rest=$((rest + 1))
		diag "$label, $n early bytes: $res"
		[ "$res" = ok ] || fail "$label, $n early bytes: $res"
	done < <(drive "$@")
	[ "$rest" = $(($# - 5)) ] || fail "$label: only $rest of $(($# - 5)) sizes ran"
}

T=4096
# The sizes around a full buffer, and past it.
SIZES="4070 4077 4078 4080 4086 4096 6000"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for scheme in socks5 http; do
		up="$(pick_port)"
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
			--nr-workers=1 --target-buf-size="$T" \
			--upstream-proxy="$scheme://127.0.0.1:$up"
		for front in http socks5; do
			# shellcheck disable=SC2086
			check "[$loop] $front client, $scheme upstream" \
				"$pp" 127.0.0.1 "$up" "$scheme" "$front" $SIZES
		done
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	done

	# An upstream on IPv6 makes the SOCKS5 reply its longest, with a 22-byte
	# bound address, against the upstream's 10-byte reply.
	if [ "$have_v6" = 1 ]; then
		up="$(pick_port)"
		pp="$(pick_port)"
		gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=1 --target-buf-size="$T" \
			--upstream-proxy="socks5://[::1]:$up"
		# shellcheck disable=SC2086
		check "[$loop] socks5 client, socks5 upstream on IPv6" \
			"$pp" ::1 "$up" socks5 socks5 $SIZES
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null
	fi

	# The smallest buffer chaining allows still takes the longest SOCKS5
	# reply, with a 255-byte bound name, and early data up to its end.
	up="$(pick_port)"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --target-buf-size=1280 \
		--upstream-proxy="socks5://127.0.0.1:$up"
	for front in http socks5; do
		S5_LONG_BOUND=1 check "[$loop] $front client, longest SOCKS5 reply" \
			"$pp" 127.0.0.1 "$up" socks5 "$front" 990 996 997 3000
	done
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null

	# An HTTP CONNECT reply header longer than the buffer can ever hold. The
	# client hears at once rather than at a timeout, with the worker spinning
	# on a full buffer until then.
	up="$(pick_port)"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --target-buf-size=1280 \
		--upstream-proxy="http://127.0.0.1:$up"
	res="$(python3 - "$pp" "$up" <<-'PY'
	import socket, sys, threading
	pp, up = int(sys.argv[1]), int(sys.argv[2])
	ls = socket.socket()
	ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	ls.bind(("127.0.0.1", up))
	ls.listen(8)
	def upstream():
	    c, _ = ls.accept()
	    c.settimeout(60)
	    try:
	        c.recv(4096)
	        # A header that never ends, past the end of the buffer.
	        c.sendall(b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 2000)
	        while c.recv(65536):
	            pass
	    except OSError:
	        pass
	    c.close()
	threading.Thread(target=upstream, daemon=True).start()
	c = socket.create_connection(("127.0.0.1", pp))
	c.settimeout(10)
	c.sendall(b"\x05\x01\x00")
	c.recv(2)
	c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
	try:
	    print(c.recv(2).hex() or "-")
	except OSError as e:
	    print(type(e).__name__)
	PY
	)"
	diag "[$loop] CONNECT reply too long for the buffer: $res"
	[ "$res" = 0501 ] || fail "[$loop] CONNECT reply too long for the buffer: expected REP 0x01, got $res"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

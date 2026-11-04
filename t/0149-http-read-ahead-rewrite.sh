#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The first read of a forwarding request can fill the client buffer, with the
# start of the body behind the header, and the rewrite then makes the header
# longer. That must not cost the request: all of it reaches the origin, byte
# for byte, in the worst case too (every line a bare LF and no space after the
# colon, as many lines as are allowed). Only a header that does not fit in the
# buffer itself is answered with 431.
#
# The proxy is stopped while the request is written, so that its first read
# finds the buffer's worth of bytes however fast or loaded the machine is.

. "$(dirname "$0")/lib.sh"
require python3

BUF=1024

op="$(pick_port)"
mkdir -p "$WORK/reqs"
python3 "$SERVERS_DIR/raw_origin.py" "$op" "$WORK/reqs" \
	>"$WORK/raw_origin.log" 2>&1 &
_PIDS+=("$!")
wait_listen "$op" "$!" || fail "raw origin did not listen on $op"

cat >"$WORK/drive.py" <<'EOF'
import os, signal, socket, sys, time

pid, port, oport, reqs, buf = int(sys.argv[1]), int(sys.argv[2]), \
	int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
auth = b'127.0.0.1:%d' % oport
errors = 0


def send(data):
    """Write @data while the proxy is stopped; return the reply's status."""
    s = socket.create_connection(('127.0.0.1', port))
    os.kill(pid, signal.SIGSTOP)
    try:
        s.setblocking(False)
        try:
            n = s.send(data)
        except BlockingIOError:
            n = 0
        time.sleep(0.05)
    finally:
        os.kill(pid, signal.SIGCONT)
    s.settimeout(30)
    # A refused request may be answered and reset before the rest is written.
    # That costs only the write: the reply is still there to read.
    try:
        s.sendall(data[n:])
    except OSError:
        pass
    r = b''
    try:
        while b'\r\n' not in r:
            c = s.recv(4096)
            if not c:
                break
            r += c
    except OSError:
        pass
    s.close()
    return r.split(b'\r\n', 1)[0].decode('latin-1') or 'CLOSED'


def check(name, data, want_status, want_req):
    global errors
    before = len(os.listdir(reqs))
    got = send(data)
    if not got.startswith(want_status):
        print('%s: got status %r, want %r' % (name, got, want_status))
        errors += 1
        return
    files = len(os.listdir(reqs))
    if want_req is None:
        if files != before:
            print('%s: refused, but the origin got a request' % name)
            errors += 1
        return
    if files != before + 1:
        print('%s: origin got %d requests' % (name, files - before))
        errors += 1
        return
    with open('%s/req.%d' % (reqs, files), 'rb') as f:
        req = f.read()
    if req != want_req:
        print('%s: origin got %d bytes, want %d; start %r' %
              (name, len(req), len(want_req), req[:120]))
        errors += 1


body = bytes(ord('a') + i % 26 for i in range(20000))
cl = b'Content-Length: %d' % len(body)
head = b'POST http://%s/ HTTP/1.1' % auth
out = b'POST / HTTP/1.1\r\nHost: %s\r\n' % auth
close = b'Connection: close\r\n\r\n'

# No Connection line and no Host to drop: the rewrite only adds.
check('plain', head + b'\r\n' + cl + b'\r\n\r\n' + body, 'HTTP/1.1 200 ',
      out + cl + b'\r\n' + close + body)

# The most a rewrite can add: 128 field lines, each two bytes longer.
names = [b'x%d' % i for i in range(127)]
check('worst case',
      head + b'\n' + b''.join(n + b':1\n' for n in names) +
      b'Content-Length:%d\n\n' % len(body) + body,
      'HTTP/1.1 200 ',
      out + b''.join(n + b': 1\r\n' for n in names) + cl + b'\r\n' + close +
      body)


# A header of @n bytes, with the end of the body behind it.
def sized(n):
    start = head + b'\r\n' + cl + b'\r\nX-Pad: '
    return start + b'p' * (n - len(start) - 4) + b'\r\n\r\n'


# It fills the buffer on its own, and still fits once rewritten.
h = sized(buf)
check('header fills the buffer', h + body, 'HTTP/1.1 200 ',
      out + cl + b'\r\nX-Pad: ' + b'p' * (buf - len(head) - len(cl) - 15) +
      b'\r\n' + close + body)
check('header over the buffer', sized(buf + 1) + body, 'HTTP/1.1 431 ', None)

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" \
		--nr-workers=1 --client-buf-size="$BUF"
	rc=0
	timeout 120 python3 "$WORK/drive.py" "$GWP_PID" "$pp" "$op" \
		"$WORK/reqs" "$BUF" >"$WORK/drive.$loop.out" 2>&1 || rc=$?
	kill -CONT "$GWP_PID" 2>/dev/null
	kill "$GWP_PID" 2>/dev/null
	if [ "$rc" != 0 ]; then
		sed 's/^/# /' "$WORK/drive.$loop.out" >&2
		fail "[$loop] read-ahead behind a rewritten request (rc=$rc)"
	fi
done

pass

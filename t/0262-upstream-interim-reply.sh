#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An http:// upstream proxy may answer the CONNECT with interim responses (100
# Continue, 102 Processing, 103 Early Hints) before its 200; a client MUST
# read past them (RFC 9110 Section 15.2). The tunnel is then up, for a SOCKS5
# and an HTTP client alike, whether the interim responses come in the segment
# of the 200 or apart from it, and the data behind the 200 is the tunnel's.
# A 101 is not taken for one: nobody asked to switch protocols.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

cat >"$WORK/drive.py" <<'EOF'
import socket, sys, threading, time

front, mode = int(sys.argv[1]), sys.argv[2]
upstream = socket.socket()
upstream.bind(('127.0.0.1', int(sys.argv[3])))
upstream.listen(16)
case = [None]
errors = 0

# Each case: the pieces the upstream sends after the CONNECT, a pause between
# them, then the tunnel's banner; and whether the tunnel must come up.
CASES = {
    'no interim': ([b'HTTP/1.1 200 OK\r\n\r\nbanner'], True),
    'one 100, apart': ([b'HTTP/1.1 100 Continue\r\n\r\n',
                        b'HTTP/1.1 200 OK\r\n\r\nbanner'], True),
    '100 and 200 together': ([b'HTTP/1.1 100 Continue\r\n\r\n'
                              b'HTTP/1.1 200 OK\r\n\r\nbanner'], True),
    '103 with a field, 102, LF only': (
        [b'HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n'
         b'HTTP/1.1 102 Processing\n\n',
         b'HTTP/1.0 200 Connection established\r\n\r\nbanner'], True),
    'many interim': ([b'HTTP/1.1 100 Continue\r\n\r\n' * 50 +
                      b'HTTP/1.1 200 OK\r\n\r\nbanner'], True),
    'a 101': ([b'HTTP/1.1 101 Switching Protocols\r\n\r\n'
               b'HTTP/1.1 200 OK\r\n\r\nbanner'], False),
}


def serve():
    while True:
        c, _ = upstream.accept()
        buf = b''
        while b'\r\n\r\n' not in buf:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        pieces, _ = CASES[case[0]]
        for i, p in enumerate(pieces):
            if i:
                time.sleep(0.2)
            c.sendall(p)
        try:
            c.settimeout(5)
            d = c.recv(4096)
            if d:
                c.sendall(b'echo:' + d)
            c.recv(4096)
        except OSError:
            pass
        c.close()


threading.Thread(target=serve, daemon=True).start()


def one():
    s = socket.create_connection(('127.0.0.1', front))
    s.settimeout(20)
    if mode == 'socks5':
        s.sendall(b'\x05\x01\x00')
        assert s.recv(2) == b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50')
        rep = b''
        while len(rep) < 10:
            d = s.recv(10 - len(rep))
            if not d:
                break
            rep += d
        ok = rep[:2] == b'\x05\x00'
        what = rep.hex()
        got = b''
    else:
        s.sendall(b'CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n')
        rep = b''
        while b'\r\n\r\n' not in rep:
            d = s.recv(4096)
            if not d:
                break
            rep += d
        ok = rep.startswith(b'HTTP/1.1 200 ')
        what = rep
        # The tunnel's first bytes may come with the reply.
        got = rep.partition(b'\r\n\r\n')[2]
    if not ok:
        s.close()
        return False, what
    while len(got) < 6:
        d = s.recv(4096)
        if not d:
            break
        got += d
    s.sendall(b'ping')
    while len(got) < 15:
        d = s.recv(4096)
        if not d:
            break
        got += d
    s.close()
    return got == b'bannerecho:ping', got


for name, (_, up) in CASES.items():
    case[0] = name
    ok, what = one()
    if ok != up:
        errors += 1
        print('%s: tunnel %s, got %r' % (name, 'up' if ok else 'down', what))

sys.exit(1 if errors else 0)
EOF

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	for front in socks5 http; do
		up="$(pick_port)"
		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-$front=1 --event-loop="$loop" \
			--nr-workers=1 --upstream-proxy="http://127.0.0.1:$up"
		rc=0
		timeout 120 python3 "$WORK/drive.py" "$fp" "$front" "$up" \
			>"$WORK/drive.out" 2>&1 || rc=$?
		kill "$GWP_PID" 2>/dev/null
		if [ "$rc" != 0 ]; then
			sed 's/^/# /' "$WORK/drive.out" >&2
			fail "[$loop $front] interim upstream replies (rc=$rc)"
		fi
	done
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A TLS client that sends a request needing a name lookup, a close_notify and
# then more bytes must not wedge its worker. Nothing can be decrypted after a
# close_notify, so the bytes behind it stay queued; the handshake loop, asking
# whether the engine holds more, must not keep going round for them, or the
# worker never gets back to its event loop to collect the lookup's result. It
# would serve nobody, and not even stop on SIGTERM. Check over SOCKS5 and HTTP
# that the proxy uses no CPU once the client has gone, that another client is
# served and that the proxy still stops. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require openssl

require_opt --tls-cert

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

closed_port

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --as-http=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1
	out="$(timeout 60 python3 - "$pp" "$GWP_PID" "$CLOSED_PORT" <<-'PY'
	import os, socket, ssl, struct, sys, time

	port, pid, dport = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
	hz = os.sysconf("SC_CLK_TCK")

	def ticks():
	    with open("/proc/%s/stat" % pid) as f:
	        st = f.read().rsplit(")", 1)[1].split()
	    return int(st[11]) + int(st[12])     # utime + stime

	def tls_client():
	    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
	    ctx.check_hostname = False
	    ctx.verify_mode = ssl.CERT_NONE
	    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
	    o = ctx.wrap_bio(inb, outb, server_side=False)
	    s = socket.create_connection(("127.0.0.1", port), timeout=5)
	    while True:
	        try:
	            o.do_handshake()
	            break
	        except ssl.SSLWantReadError:
	            d = outb.read()
	            if d:
	                s.sendall(d)
	            inb.write(s.recv(65536))
	    d = outb.read()
	    if d:
	        s.sendall(d)
	    return s, o, inb, outb

	def wedge(req):
	    s, o, inb, outb = tls_client()
	    time.sleep(0.2)                  # let the session tickets go by
	    o.write(req)
	    try:
	        o.unwrap()                   # queues the close_notify
	    except ssl.SSLWantReadError:
	        pass
	    s.sendall(outb.read() + b"\x17")
	    time.sleep(0.5)
	    s.close()

	host = b"localhost"
	reqs = {
	    "http": b"CONNECT localhost:%d HTTP/1.1\r\nHost: localhost\r\n\r\n" % dport,
	    "socks5": b"\x05\x01\x00\x05\x01\x00\x03" + bytes([len(host)]) + host +
	              struct.pack(">H", dport),
	}
	for name, req in reqs.items():
	    wedge(req)
	    time.sleep(0.3)
	    t0 = ticks()
	    time.sleep(0.5)
	    used = ticks() - t0
	    if used > int(0.5 * hz / 4):
	        print("%s: worker spinning, %d ticks in 0.5 s" % (name, used))
	        sys.exit(0)
	    try:
	        tls_client()[0].close()
	    except OSError as e:
	        print("%s: next client not served: %s" % (name, e))
	        sys.exit(0)
	print("ok")
	PY
	)"
	[ "$out" = ok ] || fail "[$loop] $out"

	kill "$GWP_PID" 2>/dev/null
	for i in $(seq 1 50); do
		kill -0 "$GWP_PID" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$GWP_PID" 2>/dev/null && fail "[$loop] SIGTERM did not stop the proxy"
done

pass

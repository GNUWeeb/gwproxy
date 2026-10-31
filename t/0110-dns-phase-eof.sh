#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A client that sends a complete request for a name, then closes its write
# side while the proxy is still resolving that name, must be served: the
# connect goes ahead, and the client's bytes and its FIN reach the target
# once it is up. The epoll loop read the FIN during the lookup and tore the
# connection down, as if the client had given up halfway through its
# handshake; the client got a reset instead of an answer.
#
# Covered for a SOCKS5 CONNECT and an HTTP CONNECT, each with and without
# bytes behind the request. The lookup is made slow with the raw resolver
# and a DNS server that answers after 2 s, so this runs on epoll only:
# gwproxy refuses --raw-dns together with --event-loop=io_uring, whose loop
# posts no client recv while a lookup is pending.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

dp="$(pick_port)"
python3 "$SERVERS_DIR/dns_malformed.py" slow "$dp" 2>/dev/null &
_PIDS+=("$!")
sleep 0.4

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1 --protocol-timeout=30

for prot in socks5 http; do
	for d in data nodata; do
		out="$(timeout 30 python3 - "$p" "$prot" "$d" <<'PY'
import socket, struct, sys, threading

port, prot = int(sys.argv[1]), sys.argv[2]
data = b"" if sys.argv[3] == "nodata" else b"request"

# The target reads until end of stream and answers with what it got.
ls = socket.socket()
ls.bind(("127.0.0.1", 0))
ls.listen(1)
tport = ls.getsockname()[1]

def target():
    c, _ = ls.accept()
    c.settimeout(10)
    got = b""
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            got += d
        c.sendall(b"EOF:" + got)
    except OSError as e:
        c.sendall(b"NO EOF (%s):" % str(e).encode() + got)
    c.close()

threading.Thread(target=target, daemon=True).start()

name = ("%s-%s.dns-phase-eof.example" % (prot, sys.argv[3])).encode()
c = socket.create_connection(("127.0.0.1", port), timeout=15)
if prot == "socks5":
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        print("no SOCKS5 method reply")
        sys.exit(1)
    req = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + \
        struct.pack(">H", tport)
else:
    hp = name + b":%d" % tport
    req = b"CONNECT " + hp + b" HTTP/1.1\r\nHost: " + hp + b"\r\n\r\n"
c.sendall(req + data)
c.shutdown(socket.SHUT_WR)

got = b""
try:
    while True:
        d = c.recv(65536)
        if not d:
            break
        got += d
except OSError as e:
    print("%s after %r" % (e, got))
    sys.exit(1)

if prot == "socks5":
    if got[:2] != b"\x05\x00":
        print("SOCKS5 reply %r" % got[:10])
        sys.exit(1)
    got = got[10:]
else:
    head, sep, got = got.partition(b"\r\n\r\n")
    if not sep or b" 200" not in head.split(b"\r\n")[0]:
        print("HTTP reply %r" % head[:40])
        sys.exit(1)
if got != b"EOF:" + data:
    print("got %r, want %r" % (got, b"EOF:" + data))
    sys.exit(1)
print("OK")
PY
)"
		[ "$out" = OK ] || fail "$prot, $d: ${out:-no output}"
	done
done

kill -0 "$GWP_PID" 2>/dev/null || fail "proxy died"
pass

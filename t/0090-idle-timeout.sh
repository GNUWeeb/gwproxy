#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --idle-timeout: a tunnel or UDP association that moves no data for that
# long is closed, so idle or trickling-nothing clients cannot hold
# descriptors and buffers for ever. Activity in either direction keeps it
# open, and without the option nothing is closed for being idle.
# Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3

start_udp_echo 127.0.0.1
uport="$UDP_ECHO_PORT"

# The client: a SOCKS5 CONNECT to an echo origin of its own, or a UDP
# ASSOCIATE to the UDP echo server, then a scenario. Prints "ok" or what
# went wrong.
client() {
	python3 - "$@" <<'PY'
import socket, struct, sys, threading, time
port, scen, uport = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])

def closed_within(c, secs):
    c.settimeout(secs)
    try:
        return c.recv(64) == b""
    except socket.timeout:
        return False
    except ConnectionResetError:
        return True

c = socket.create_connection(("127.0.0.1", port), timeout=5)
c.sendall(b"\x05\x01\x00")
assert c.recv(2) == b"\x05\x00"

if scen == "udp":
    c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = c.recv(10)
    if rep[1] != 0:
        print("UDP ASSOCIATE refused: %r" % rep); sys.exit(0)
    relay = ("127.0.0.1", struct.unpack(">H", rep[8:10])[0])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", uport)
    u.sendto(hdr + b"ping", relay)
    if not u.recv(256).endswith(b"ping"):
        print("no UDP echo"); sys.exit(0)
    print("ok" if closed_within(c, 6) else "UDP association still open after idling")
    sys.exit(0)

lsock = socket.socket()
lsock.bind(("127.0.0.1", 0))
lsock.listen(1)
def echo():
    o, _ = lsock.accept()
    while True:
        d = o.recv(4096)
        if not d:
            break
        o.sendall(d)
threading.Thread(target=echo, daemon=True).start()
c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", lsock.getsockname()[1]))
rep = c.recv(10)
if rep[1] != 0:
    print("CONNECT refused: %r" % rep); sys.exit(0)

if scen == "idle":
    print("ok" if closed_within(c, 6) else "idle tunnel still open after 6 s")
elif scen == "busy":
    c.settimeout(3)
    for i in range(6):
        time.sleep(1)
        c.sendall(b"x")
        if c.recv(1) != b"x":
            print("busy tunnel closed after %d s" % (i + 1)); sys.exit(0)
    print("ok" if closed_within(c, 6) else "tunnel still open once it went idle")
elif scen == "off":
    print("closed without --idle-timeout" if closed_within(c, 4) else "ok")
PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --idle-timeout=2
	for scen in idle busy udp; do
		got="$(client "$p" "$scen" "$uport")"
		[ "$got" = ok ] || fail "[$loop] $scen: $got"
	done
	grep -q 'Idle timeout' "$WORK/gwp.$p.log" \
		|| fail "[$loop] the idle timeout was not logged"
	kill "$GWP_PID" 2>/dev/null

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1
	got="$(client "$p" off "$uport")"
	[ "$got" = ok ] || fail "[$loop] off: $got"
	kill "$GWP_PID" 2>/dev/null
done

pass

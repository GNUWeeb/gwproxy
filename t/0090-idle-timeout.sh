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

# Whether the proxy closes @c within @secs. When it does not, @late says
# when the wait ended, to line up with the proxy's log.
#
# An idle pair is closed within 4 s of its last activity at
# --idle-timeout=2 (the check runs on whole seconds); WAIT leaves 4 s on
# top for a loaded machine, where the proxy may not get to run for a few
# seconds. For a pair idle from the start it stays short of the 10 s
# protocol timeout, which must not be what closes it.
WAIT = 8
late = ""
def closed_within(c, secs):
    global late
    c.settimeout(secs)
    try:
        return c.recv(64) == b""
    except socket.timeout:
        late = " (gave up at %s)" % time.strftime("%H:%M:%S")
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
    print("ok" if closed_within(c, WAIT) else "UDP association still open after idling" + late)
    sys.exit(0)

lsock = socket.socket()
lsock.bind(("127.0.0.1", 0))
lsock.listen(8)
def echo():
    while True:
        o, _ = lsock.accept()
        threading.Thread(target=echo_one, args=(o,), daemon=True).start()
def echo_one(o):
    while True:
        try:
            d = o.recv(4096)
        except OSError:
            break
        if not d:
            break
        o.sendall(d)
threading.Thread(target=echo, daemon=True).start()
c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", lsock.getsockname()[1]))
rep = c.recv(10)
if rep[1] != 0:
    print("CONNECT refused: %r" % rep); sys.exit(0)

if scen == "idle":
    print("ok" if closed_within(c, WAIT) else "idle tunnel still open after %d s%s" % (WAIT, late))
elif scen == "busy":
    c.settimeout(3)
    for i in range(6):
        time.sleep(1)
        c.sendall(b"x")
        if c.recv(1) != b"x":
            print("busy tunnel closed after %d s" % (i + 1)); sys.exit(0)
    print("ok" if closed_within(c, WAIT) else "tunnel still open once it went idle" + late)
elif scen == "gap":
    # The timeout is counted in whole seconds. Connect just after a second
    # starts, so the idle check falls just after a second two later, and
    # leave a gap well under the timeout across it: last activity at K+0.7,
    # check at K+2.05, next byte at K+2.3. A try the machine delayed past
    # the next check says nothing, so it does not count.
    c.close()
    def until(frac):
        now = time.monotonic()
        base = int(now)
        at = base + frac if now - base < frac else base + 1 + frac
        time.sleep(at - now)
        return int(at)
    for attempt in range(4):
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
        c.sendall(b"\x05\x01\x00")
        c.recv(2)
        k = until(0.05)
        c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                  struct.pack(">H", lsock.getsockname()[1]))
        c.recv(10)
        until(0.7)
        c.sendall(b"x")
        c.recv(1)
        time.sleep(k + 2.3 - time.monotonic())
        if time.monotonic() >= k + 2.8:
            c.close()
            continue
        try:
            c.sendall(b"y")
            alive = c.recv(1) == b"y"
        except OSError:
            alive = False
        print("ok" if alive else "active tunnel closed 1.6 s after its last byte")
        sys.exit(0)
    print("ok")
elif scen == "off":
    print("closed without --idle-timeout" if closed_within(c, 4) else "ok")
PY
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --idle-timeout=2
	for scen in idle busy gap udp; do
		got="$(client "$p" "$scen" "$uport")"
		if [ "$got" != ok ]; then
			# What the proxy last did, and when, for the record.
			tail -n 15 "$WORK/gwp.$p.log" | sed 's/^/# gwp: /' >&2
			fail "[$loop] $scen: $got"
		fi
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

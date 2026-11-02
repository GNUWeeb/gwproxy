#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The built-in default ACL lets a target through only if it is public unicast.
# Check the edges of each non-public range and the public addresses right next
# to them. Nothing leaves the host and nothing is resolved: the proxy hands
# what it allows to a stub upstream that says yes to everything, so a target
# gets REP 0x00 if the ACL let it through and REP 0x02 if not. Runs on every
# event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

DENY="
192.0.2.0 192.0.2.255 192.88.99.0 192.88.99.255 198.51.100.0 198.51.100.255
203.0.113.0 203.0.113.255 ::ffff:192.0.2.1 ::ffff:203.0.113.1
::ffff:0:7f00:1 ::ffff:0:a00:1 ::2:0:1 ff::1
100::1 100:0:0:1::1 1ff:ffff::1 200::1 3ff::1 400::1 800::1 1000::1 1fff::1
2001::1 2001:0:ffff::1 2001:2::1 2001:2:0:ffff::1 2001:10::1 2001:1f:ffff::1
2001:db8::1 2001:db8:ffff::1 3fff::1 3fff:fff:ffff::1
4000::1 5f00::1 6000::1 8000::1 a000::1 c000::1 e000::1 f000::1 f800::1
fe00::1 fe7f::1
"

ALLOW="
8.8.8.8 192.0.1.255 192.0.3.0 192.88.98.255 192.88.100.0 198.51.99.255
198.51.101.0 203.0.112.255 203.0.114.0 ::ffff:8.8.8.8 ::ffff:192.0.1.1
2000::1 2001:1::1 2001:3::1 2001:f::1 2001:20::1 2001:db7:ffff::1 2001:db9::1
2606:4700::1 3ffe:ffff::1 3fff:1000::1 3fff:ffff::1
"

# check <proxy_port> <want REP> <addr...>: fail naming each address answered
# otherwise. One process, or the list costs a python start per address.
check()
{
	python3 - "$@" <<'PY'
import ipaddress, socket, struct, sys

port, want = int(sys.argv[1]), int(sys.argv[2], 16)
bad = 0
for addr in sys.argv[3:]:
    ip = ipaddress.ip_address(addr)
    c = socket.create_connection(("127.0.0.1", port), timeout=30)
    c.settimeout(30)
    c.sendall(b"\x05\x01\x00")
    c.recv(2)
    c.sendall(b"\x05\x01\x00" + (b"\x01" if ip.version == 4 else b"\x04") +
              ip.packed + struct.pack("!H", 80))
    r = c.recv(4)
    c.close()
    if len(r) < 2 or r[1] != want:
        print("%s: got %s, want REP=0x%02x" % (addr, r.hex() or "nothing", want))
        bad = 1
sys.exit(bad)
PY
}

rlog="$WORK/up.log"
up="$(pick_port)"
python3 "$SERVERS_DIR/stub_upstream.py" socks5 "$up" "$rlog" >"$WORK/up.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$up" "$!" || fail "stub upstream did not listen"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	# An empty --acl-file selects the built-in rules.
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="socks5h://127.0.0.1:$up" --acl-file=

	: >"$rlog"
	# shellcheck disable=SC2086
	out="$(check "$pp" 02 $DENY)" || fail "[$loop] let through: $out"
	[ ! -s "$rlog" ] || fail "[$loop] reached the upstream: $(cat "$rlog")"

	# shellcheck disable=SC2086
	out="$(check "$pp" 00 $ALLOW)" || fail "[$loop] refused: $out"

	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

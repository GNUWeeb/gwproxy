#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A raw-DNS answer naming a denied target must fail that one request only.
#
# With --raw-dns the connect that follows a resolution runs from the DNS
# socket's event, not from an event belonging to the connection pair. A
# per-connection error there (an ACL denial, or a connect that fails at
# once) used to escape to the worker loop as if the worker itself had
# broken: the worker exited, the others were told to stop, and a single
# SOCKS5 CONNECT to a name resolving to 127.0.0.1 took the whole proxy down
# under the default ACL.
#
# Each case asserts the client got REP 0x02 (not allowed by ruleset) and
# that the proxy keeps serving afterwards, not merely that it still runs.

. "$(dirname "$0")/lib.sh"
require python3

grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

DOC="$WORK/doc"
mkdir -p "$DOC"
echo "raw-dns-acl-ok" >"$DOC/index.html"
hp="$(pick_port)"
start_httpd "$hp" "$DOC"

# The responder answers every name with 127.0.0.1.
dp="$(pick_port)"
python3 "$SERVERS_DIR/dns_malformed.py" good "$dp" 2>/dev/null &
_PIDS+=("$!")
sleep 0.4

# SOCKS5 CONNECT to probe.example.com:<port> via the proxy on $1. Prints the
# reply byte, then (on success) the first line of an HTTP GET sent through
# the tunnel; NONE if the proxy answered nothing.
ask()					# $1=proxy_port $2=dst_port
{
	python3 -c '
import socket, sys
try:
    s = socket.socket(); s.settimeout(4)
    s.connect(("127.0.0.1", int(sys.argv[1])))
    s.sendall(b"\x05\x01\x00"); s.recv(2)
    d = b"probe.example.com"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d
              + int(sys.argv[2]).to_bytes(2, "big"))
    r = s.recv(10)
    if len(r) < 2:
        print("NONE"); sys.exit(0)
    print("REP=0x%02x" % r[1])
    if r[1] == 0:
        s.sendall(b"GET /index.html HTTP/1.0\r\nHost: x\r\n\r\n")
        b = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            b += c
        print("BODY=" + ("ok" if b"raw-dns-acl-ok" in b else "bad"))
    s.close()
except Exception:
    print("NONE")' "$1" "$2" 2>/dev/null
}

# 1) The built-in default ACL denies loopback. Launch directly to bypass
#    gwp_start's automatic --acl-allow-all. Several workers, because the
#    failure mode was one worker taking all of them down.
p="$(pick_port)"
"$GWPROXY" --bind="127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=2 --log-level=3 \
	>"$WORK/defacl.log" 2>&1 &
dpid=$!
_PIDS+=("$dpid")
wait_listen "$p" "$dpid" || fail "default-ACL proxy did not listen"

for i in 1 2 3; do
	rep="$(ask "$p" "$hp")"
	[ "$rep" = "REP=0x02" ] || {
		sed 's/^/# gwp: /' "$WORK/defacl.log" >&2
		fail "default ACL: request $i got '$rep', want REP=0x02"
	}
	kill -0 "$dpid" 2>/dev/null || {
		sed 's/^/# gwp: /' "$WORK/defacl.log" >&2
		fail "default ACL: proxy died after denied request $i"
	}
done
kill "$dpid" 2>/dev/null
wait "$dpid" 2>/dev/null

# 2) An ACL file denying one port: the denied request must not stop the
#    proxy from resolving and tunnelling the next, allowed, one.
denied="$(pick_port)"
printf -- '%s\n' \
	'-P INPUT ACCEPT' \
	"-A OUTPUT --dports $denied -j REJECT" \
	'-P OUTPUT ACCEPT' >"$WORK/port.acl"

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1 \
	--acl-file="$WORK/port.acl"

rep="$(ask "$p" "$denied")"
[ "$rep" = "REP=0x02" ] || fail "ACL file: denied port got '$rep', want REP=0x02"
kill -0 "$GWP_PID" 2>/dev/null || fail "ACL file: proxy died after a denied request"

out="$(ask "$p" "$hp" | tr '\n' ' ')"
[ "$out" = "REP=0x00 BODY=ok " ] || \
	fail "ACL file: allowed request after a denied one failed (got '$out')"
kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null

pass

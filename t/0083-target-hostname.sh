#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A requested target hostname is checked before the ACL, the resolver or an
# upstream proxy sees it. A SOCKS5 DOMAINNAME is up to 255 arbitrary bytes:
# with an http:// upstream, CR/LF or ':' in it would be pasted into the
# upstream CONNECT request, injecting headers or a different target than
# the one the ACL judged. Such names get REP 0x01 (and a 400 for an HTTP
# CONNECT) and never reach the upstream; a well-formed name still does.
# Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

rp="$(pick_port)"
rlog="$WORK/rec.log"
: >"$rlog"
python3 "$SERVERS_DIR/recording_proxy.py" http 127.0.0.1 "$rp" "$rlog" \
	>"$WORK/rec.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$rp" "$!" || fail "recording upstream did not listen"

probe() {
	python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 --atyp domain \
		--dst "$2" "$1" "$hp"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	: >"$rlog"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="http://127.0.0.1:$rp"

	for bad in $'evil.example:80 HTTP/1.1\r\nX-A: x.allowed.com' \
		   'internal.corp:22' 'a..b' '.lead' 'sp ace' $'nul\x01x'; do
		rep="$(probe "$fp" "$bad")"
		[ ! -s "$rlog" ] \
			|| fail "[$loop] malformed name $(printf %q "$bad") reached the upstream: $(cat -v "$rlog")"
		[ "$rep" = "REP=0x01" ] \
			|| fail "[$loop] malformed name $(printf %q "$bad") got '$rep' (want REP=0x01)"
	done

	rep="$(probe "$fp" localhost)"
	[ "$rep" = "REP=0x00" ] \
		|| fail "[$loop] well-formed name got '$rep' (want REP=0x00)"
	got="$(head -1 "$rlog")"
	[ "$got" = "authority=localhost:$hp" ] \
		|| fail "[$loop] upstream saw '$got' for a well-formed name"
	kill "$GWP_PID" 2>/dev/null

	# The HTTP front: a CONNECT authority with a bad host gets a 400.
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-http=1 --event-loop="$loop" --nr-workers=1
	st="$(python3 - "$pp" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"CONNECT bad;host:80 HTTP/1.1\r\nHost: x\r\n\r\n")
print(s.recv(200).split(b"\r\n")[0].decode(errors="replace"))
PY
)"
	case "$st" in
	"HTTP/1."?" 400 "*) ;;
	*) fail "[$loop] HTTP CONNECT to a malformed host got '$st' (want 400)" ;;
	esac
	kill "$GWP_PID" 2>/dev/null
done

pass

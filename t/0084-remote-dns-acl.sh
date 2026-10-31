#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# ACL address and port rules with a remote-DNS upstream (socks5h://), where
# the requested name goes to the upstream unresolved. A "name" that is
# really an IP literal ("127.0.0.1", "::1", "2130706433") must still meet
# the -d rules, --dports rules must still see the requested port, and the
# built-in default ACL must refuse "localhost" (and *.localhost with PCRE),
# which the upstream would resolve to its own loopback. Such requests get
# REP 0x02 (403 over HTTP) and never reach the upstream; an allowed name
# still does. Exercised on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

rp="$(pick_port)"
rlog="$WORK/rec.log"
: >"$rlog"
python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$rp" "$rlog" \
	>"$WORK/rec.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$rp" "$!" || fail "recording upstream did not listen"

# probe <proxy_port> <name> [dst_port]
probe() {
	python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 --atyp domain \
		--dst "$2" "$1" "${3:-$hp}"
}

# denied <loop> <proxy_port> <name> [dst_port]: REP 0x02, upstream untouched.
denied() {
	local rep
	: >"$rlog"
	rep="$(probe "$2" "$3" "${4:-}")"
	[ ! -s "$rlog" ] \
		|| fail "[$1] '$3' reached the upstream: $(cat "$rlog")"
	[ "$rep" = "REP=0x02" ] \
		|| fail "[$1] '$3' got '$rep' (want REP=0x02)"
}

printf -- '%s\n' '-A OUTPUT -d 127.0.0.0/8 -j REJECT' \
	'-A OUTPUT -d ::1/128 -j REJECT' \
	'-A OUTPUT --dports 22 -j REJECT' \
	'-P OUTPUT ACCEPT' >"$WORK/rules.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=1 \
		--upstream-proxy="socks5h://127.0.0.1:$rp" \
		--acl-file="$WORK/rules.acl"

	for name in 127.0.0.1 2130706433 127.1 ::1; do
		denied "$loop" "$fp" "$name"
	done
	denied "$loop" "$fp" localhost 22

	# An allowed name still goes to the upstream as a name.
	: >"$rlog"
	rep="$(probe "$fp" localhost)"
	[ "$rep" = "REP=0x00" ] \
		|| fail "[$loop] allowed name got '$rep' (want REP=0x00)"
	got="$(head -1 "$rlog")"
	[ "$got" = "atyp=3 addr=localhost port=$hp" ] \
		|| fail "[$loop] upstream saw '$got' for an allowed name"

	# HTTP CONNECT takes the same path.
	: >"$rlog"
	st="$(python3 - "$fp" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: x\r\n\r\n")
print(s.recv(200).split(b"\r\n")[0].decode(errors="replace"))
PY
)"
	case "$st" in
	"HTTP/1."?" 403 "*) ;;
	*) fail "[$loop] HTTP CONNECT to 127.0.0.1 got '$st' (want 403)" ;;
	esac
	[ ! -s "$rlog" ] \
		|| fail "[$loop] HTTP CONNECT to 127.0.0.1 reached the upstream"
	kill "$GWP_PID" 2>/dev/null

	# The built-in default ACL (an empty --acl-file selects it).
	dp="$(pick_port)"
	gwp_start "127.0.0.1:$dp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="socks5h://127.0.0.1:$rp" \
		--acl-file=
	for name in localhost LocalHost 169.254.169.254; do
		denied "$loop" "$dp" "$name"
	done
	grep -q CONFIG_PCRE "$ROOT/config.h" 2>/dev/null &&
		denied "$loop" "$dp" app.localhost
	kill "$GWP_PID" 2>/dev/null
done

pass

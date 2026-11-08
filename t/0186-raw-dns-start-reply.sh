#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A raw DNS lookup that cannot even be started is answered as one that failed:
# SOCKS5 REP 0x04 (host unreachable), HTTP 502. Only a name DNS cannot carry
# was answered before (REP 0x01, HTTP 400, t/0187); any other failure to
# start the lookup closed the connection without a word, so a SOCKS5 client
# had no reply and an HTTP client no status.
#
# Two ways to fail the start, without privilege:
#
#   - The DNS server is the broadcast address. Connecting the query's socket
#     to it is refused (EACCES, no SO_BROADCAST; ENETUNREACH without a route).
#   - The proxy runs out of descriptors between the client's socket and the
#     query's: its RLIMIT_NOFILE is lowered, once it is up, to admit exactly
#     one more descriptor (EMFILE).
#
# The reason goes to the debug log. epoll only: gwproxy refuses --raw-dns
# together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

# ask <socks5|http|get> <proxy port>: the SOCKS5 reply code, or the HTTP
# status of a CONNECT or of a forwarded GET, or NONE when the connection
# closed or nothing came back within the timeout.
ask()
{
	python3 -c '
import socket, sys
kind, port, name = sys.argv[1], int(sys.argv[2]), "probe.example"
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    if kind == "socks5":
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        d = name.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + b"\x00\x50")
        r = s.recv(16)
        print("REP=0x%02x" % r[1] if len(r) > 1 else "NONE")
    else:
        if kind == "http":
            req = "CONNECT %s:80 HTTP/1.1\r\nHost: %s:80\r\n\r\n"
        else:
            req = "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n"
        s.sendall((req % (name, name)).encode())
        r = s.recv(256).split(b"\r\n")[0].split()
        print(r[1].decode() if len(r) > 1 else "NONE")
    s.close()
except Exception:
    print("NONE")' "$@" 2>/dev/null
}

# check <case> <proxy port>: every front-end gets host unreachable.
check()
{
	local c="$1" p="$2" got

	got="$(ask socks5 "$p")"
	[ "$got" = REP=0x04 ] || fail "$c: SOCKS5 got '$got' (want REP=0x04)"
	got="$(ask http "$p")"
	[ "$got" = 502 ] || fail "$c: HTTP CONNECT got '$got' (want 502)"
	got="$(ask get "$p")"
	[ "$got" = 502 ] || fail "$c: HTTP GET got '$got' (want 502)"
	kill -0 "$GWP_PID" 2>/dev/null || fail "$c: proxy died"
	grep -q "DNS query could not be started: probe.example" \
		"$WORK/gwp.$p.log" || fail "$c: reason not logged"
}

# The query's socket cannot be connected to its server.
start_case()
{
	local p

	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
		--dns-server=255.255.255.255:53 --nr-workers=1 \
		--protocol-timeout=120 --log-level=4
	check broadcast "$p"
}

# The proxy has room for the client's socket, and none for the query's.
emfile_case()
{
	local p lim

	start_dns_responder good
	p="$(pick_port)"
	gwp_start "127.0.0.1:$p" --as-socks5=1 --as-http=1 --raw-dns=1 \
		--dns-server="127.0.0.1:$DNS_PORT" --nr-workers=1 \
		--protocol-timeout=120 --log-level=4

	# Descriptors are handed out lowest first: allow the lowest free
	# one, which the accepted client takes, and not the next.
	lim="$(python3 -c '
import os, resource, sys
pid = int(sys.argv[1])
used = {int(f) for f in os.listdir("/proc/%d/fd" % pid)}
free = [n for n in range(len(used) + 2) if n not in used]
hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)[1]
resource.prlimit(pid, resource.RLIMIT_NOFILE, (free[1], hard))
print(free[1])' "$GWP_PID" 2>&1)" || \
		skip "cannot lower the proxy's descriptor limit: $lim"
	diag "proxy descriptor limit lowered to $lim"

	check emfile "$p"

	# Room again, for the sanitizers' work at exit.
	python3 -c '
import resource, sys
pid = int(sys.argv[1])
hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)[1]
resource.prlimit(pid, resource.RLIMIT_NOFILE, (hard, hard))' "$GWP_PID" || \
		fail "cannot restore the proxy's descriptor limit"
	return 0
}

run_case()
{
	case "$1" in
	broadcast) start_case ;;
	emfile) emfile_case ;;
	esac
}

gwp_parallel run_case broadcast emfile

pass

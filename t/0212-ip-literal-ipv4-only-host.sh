#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An IPv6 literal requested by name (an HTTP CONNECT or forward to [::1], a
# SOCKS5 domain-typed "::1") on a host whose only IPv6 address is the
# loopback's: a container with IPv4 networking alone, say.
#
# glibc's getaddrinfo() with AI_ADDRCONFIG leaves IPv6 out on such a host, a
# numeric IPv6 host included, so a literal handed to the system resolver came
# back as a name that does not resolve: HTTP 502 / SOCKS5 REP 0x04, before the
# ACL had seen the address. The built-in default ACL must refuse ::1 (403 /
# REP 0x02) as it refuses 127.0.0.1, and with --acl-allow-all the request must
# reach the service on ::1, as an IPv6 SOCKS5 address does.
#
# Two ways to get such a host, each run where it can be:
#  - a getaddrinfo() wrapper preloaded into the proxy that answers a numeric
#    IPv6 host as glibc does there (EAI_ADDRFAMILY). It needs the compiler of
#    config.make, and no sanitizer (whose runtime must come first);
#  - a private user+net namespace with the loopback and a dummy interface
#    with an IPv4 address and IPv6 turned off: the real thing, but it needs
#    unprivileged user namespaces, which containers often refuse.
# Both event loops.

. "$(dirname "$0")/lib.sh"
require curl
require python3

http_connect_code()			# $1=proxy_port $2=authority
{
	python3 - "$@" 2>/dev/null <<-'PY'
	import socket, sys
	s = socket.create_connection(('127.0.0.1', int(sys.argv[1])))
	s.settimeout(10)
	a = sys.argv[2]
	s.sendall(('CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (a, a)).encode())
	print(s.recv(64).split(b' ')[1].decode())
	PY
}

socks5_rep()				# $1=proxy_port $2=dst $3=dst_port
{
	python3 "$SERVERS_DIR/socks5_probe.py" --atyp domain --dst "$2" \
		"$1" "$3" 2>/dev/null
}

# check <tag> <what> <got> <want>
check()
{
	[ "$3" = "$4" ] || fail "[$1] $2 got '${3:-<none>}' (want $4)"
}

# run_checks <tag>: the requests, on both loops, against the service on port
# $hp, through proxies started in the caller's environment (LD_PRELOAD).
run_checks()
{
	local tag="$1" loop pp ap

	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! have_io_uring && continue

		# No ACL argument at all: the built-in default ACL. gwp_start
		# would add --acl-allow-all, so start it by hand.
		pp="$(pick_port)"
		"$GWPROXY" --bind="127.0.0.1:$pp" --log-level=3 --as-socks5=1 \
			--as-http=1 --nr-workers=1 --event-loop="$loop" \
			>"$WORK/gwp.$pp.log" 2>&1 &
		GWP_PID=$!
		_PIDS+=("$GWP_PID")
		wait_listen "$pp" "$GWP_PID" || \
			fail "[$tag $loop] gwproxy did not listen"

		check "$tag $loop" "default ACL: HTTP CONNECT [::1]" \
			"$(http_connect_code "$pp" "[::1]:$hp")" 403
		check "$tag $loop" "default ACL: HTTP forward to [::1]" \
			"$(curl -s --max-time 10 -x "http://127.0.0.1:$pp" \
				"http://[::1]:$hp/payload.bin" -o /dev/null \
				-w '%{http_code}')" 403
		check "$tag $loop" "default ACL: SOCKS5 domain ::1" \
			"$(socks5_rep "$pp" ::1 "$hp")" REP=0x02
		kill "$GWP_PID" 2>/dev/null

		ap="$(pick_port)"
		gwp_start "127.0.0.1:$ap" --as-socks5=1 --as-http=1 \
			--nr-workers=1 --event-loop="$loop" --acl-allow-all

		check "$tag $loop" "--acl-allow-all: HTTP CONNECT [::1]" \
			"$(http_connect_code "$ap" "[::1]:$hp")" 200
		curl -s --max-time 20 -x "http://127.0.0.1:$ap" \
			"http://[::1]:$hp/payload.bin" -o "$WORK/out.bin" || \
			fail "[$tag $loop] --acl-allow-all: HTTP forward to [::1] failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$tag $loop] --acl-allow-all: HTTP forward to [::1] corrupted the payload"
		check "$tag $loop" "--acl-allow-all: SOCKS5 domain ::1" \
			"$(socks5_rep "$ap" ::1 "$hp")" REP=0x00
		kill "$GWP_PID" 2>/dev/null
	done
}

if [ "${1:-}" != "--inner" ]; then
	python3 -c 'import socket; socket.socket(socket.AF_INET6).bind(("::1", 0))' \
		2>/dev/null || skip "no IPv6 loopback"

	ran=""

	# ------------------------------------------- the preloaded wrapper ----
	cc="$(sed -n 's/^CC=//p' "$ROOT/config.make" 2>/dev/null)"
	if grep -q -- '-fsanitize' "$ROOT/config.make" 2>/dev/null; then
		diag "sanitizer build: no preloaded getaddrinfo() wrapper"
	elif [ -z "$cc" ]; then
		diag "no compiler in config.make: no getaddrinfo() wrapper"
	else
		cat >"$WORK/noaddrconfig6.c" <<-'EOF'
		#include <arpa/inet.h>
		#include <dlfcn.h>
		#include <netdb.h>

		/*
		 * What glibc's AI_ADDRCONFIG does on a host with no IPv6
		 * address but the loopback's: an IPv6 host, even a numeric
		 * one, has no address of a family the host can use.
		 */
		int getaddrinfo(const char *node, const char *service,
				const struct addrinfo *hints, struct addrinfo **res)
		{
			static int (*real)(const char *, const char *,
					   const struct addrinfo *,
					   struct addrinfo **);
			struct in6_addr a6;

			if (node && hints && (hints->ai_flags & AI_ADDRCONFIG) &&
			    inet_pton(AF_INET6, node, &a6) == 1)
				return EAI_ADDRFAMILY;
			if (!real)
				real = (int (*)(const char *, const char *,
						const struct addrinfo *,
						struct addrinfo **))
					dlsym(RTLD_NEXT, "getaddrinfo");
			return real(node, service, hints, res);
		}
		EOF
		if "$cc" -D_GNU_SOURCE -shared -fPIC \
			-o "$WORK/noaddrconfig6.so" "$WORK/noaddrconfig6.c" \
			-ldl >"$WORK/cc.log" 2>&1; then
			hp="$(pick_port)"
			make_payload "$WORK/payload.bin" 4096
			start_httpd "$hp" "$WORK" "1.1"		# dual-stack [::]
			LD_PRELOAD="$WORK/noaddrconfig6.so" run_checks preload
			ran="$ran preload"
		else
			diag "cannot build the getaddrinfo() wrapper:" \
			     "$(head -n 3 "$WORK/cc.log")"
		fi
	fi

	# ------------------------------------------------ the namespace ----
	# Re-exec: the inner half runs below. See t/0063 for why ns_drop_setup
	# stays in this branch and why the run is detached.
	NS_DROP=""
	if command -v unshare >/dev/null && command -v ip >/dev/null; then
		ns_drop_setup
	fi
	if command -v unshare >/dev/null && command -v ip >/dev/null &&
	   $NS_DROP unshare -rn true 2>/dev/null; then
		out="$WORK/inner.out"
		setsid $NS_DROP unshare -rn "$0" --inner "$WORK" \
			</dev/null >"$out" 2>&1 &
		for i in $(seq 1 120); do
			grep -q '^INNER-DONE' "$out" 2>/dev/null && break
			sleep 1
		done
		sed 's/^/# /' "$out" >&2
		grep -q '^INNER-DONE rc=0' "$out" || fail "inner run failed (see above)"
		ran="$ran netns"
	else
		diag "no user+net namespaces (unshare -rn): no IPv4-only namespace"
	fi

	[ -n "$ran" ] || skip "neither a getaddrinfo() wrapper nor a namespace here"
	pass "ran:$ran"
fi

# ---------------------------------------------------------------- inner ----
ns_inner_work "$2"
rc=1

# setsid put this run in its own session: reap it here (see t/0063).
cleanup_inner()
{
	echo "INNER-DONE rc=$rc"
	_release_ports
	kill 0 2>/dev/null
}
trap cleanup_inner EXIT

ip link set lo up || exit 1
ip link add eth0 type dummy || { echo "cannot add a dummy interface"; exit 1; }
echo 1 >/proc/sys/net/ipv6/conf/eth0/disable_ipv6 || exit 1
ip link set eth0 up || exit 1
ip addr add 10.99.0.2/24 dev eth0 || exit 1

# Whether this resolver drops the literal here: if it does not (musl does not),
# the checks still hold, but they do not show the bug.
python3 -c '
import socket
socket.getaddrinfo("::1", None, 0, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG)
' 2>/dev/null && echo "getaddrinfo() keeps ::1 here; the checks pass either way"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 4096
start_httpd "$hp" "$WORK" "1.1"		# dual-stack [::]
run_checks netns
echo "netns ok"
rc=0

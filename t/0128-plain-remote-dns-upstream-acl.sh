#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Plain --target forwarding through an upstream that resolves names (socks5h://,
# http://) goes through the OUTPUT chain like every other request, though it
# has no address when --target is a hostname: policy and -s rules still apply,
# -m domain matches the name, -d an IP literal, and -j DNAT and -j BIND take
# effect. Nothing here is resolved: the stub upstream only records what it was
# asked for. Runs on every event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt "--upstream-proxy"

NAME=target.invalid
LIT=203.0.113.5
NET="-P INPUT ACCEPT"

# Connect, and print what the proxy's upstream tunnel said, or "closed" if the
# client was hung up on instead.
client()
{
	python3 - "$1" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
s.settimeout(20)
buf = b""
try:
    while b"\n" not in buf:
        d = s.recv(100)
        if not d:
            break
        buf += d
except ConnectionResetError:
    pass
except socket.timeout:
    print("timeout")
    sys.exit(0)
print(buf.decode(errors="replace").strip() or "closed")
PY
}

# want_req <socks5|http> <host> <port>: what the upstream should log.
want_req()
{
	if [ "$1" = http ]; then
		case "$2" in
		*:*) echo "authority=[$2]:$3" ;;
		*) echo "authority=$2:$3" ;;
		esac
		return
	fi
	case "$2" in
	*:*) echo "atyp=4 addr=$2 port=$3" ;;
	[0-9]*.[0-9]*) echo "atyp=1 addr=$2 port=$3" ;;
	*) echo "atyp=3 addr=$2 port=$3" ;;
	esac
}

# run_case <what> <--target> <rules or "-" for the default ACL> <want>
# want: "denied", or "up <host> <port> [src]" for what the upstream is asked.
run_case()
{
	local what="$1" target="$2" rules="$3" want="$4" tag aclopt got seen
	local -a w
	local i

	tag="[$loop/$scheme] $what"
	aclopt=""
	if [ "$rules" != - ]; then
		printf '%s\n%b\n' "$NET" "$rules" >"$WORK/acl"
		aclopt="--acl-file=$WORK/acl"
	fi
	: >"$rlog"
	pp="$(pick_port)"
	glog="$WORK/gwp.log"
	"$GWPROXY" --bind="127.0.0.1:$pp" --target="$target" $aclopt \
		--upstream-proxy="$scheme://127.0.0.1:$up" --event-loop="$loop" \
		--nr-workers=1 --log-level=3 >"$glog" 2>&1 &
	gwp_pid=$!
	_PIDS+=("$gwp_pid")
	wait_listen "$pp" "$gwp_pid" || {
		sed 's/^/# gwp: /' "$glog" >&2
		fail "$tag: gwproxy did not listen"
	}

	got="$(client "$pp")"

	# The log is written as the event happens, so it is complete by now,
	# but it reaches the file only at a flush: stop the proxy first.
	kill "$gwp_pid" 2>/dev/null
	wait "$gwp_pid" 2>/dev/null

	if [ "$want" = denied ]; then
		[ "$got" = closed ] || fail "$tag: client got '$got', want it hung up on"
		[ ! -s "$rlog" ] || fail "$tag: denied request reached the upstream: $(cat "$rlog")"
		grep -q "ACL denied target" "$glog" || {
			sed 's/^/# gwp: /' "$glog" >&2
			fail "$tag: the denial was not logged"
		}
		return 0
	fi

	[ "$got" = UPSTREAM-TUNNEL ] || {
		sed 's/^/# gwp: /' "$glog" >&2
		fail "$tag: client got '$got', want the tunnel"
	}
	read -ra w <<<"$want"
	seen="$(head -1 "$rlog")"
	i="src=${w[3]:-127.0.0.1} $(want_req "$kind" "${w[1]}" "${w[2]}")"
	[ "$seen" = "$i" ] || fail "$tag: upstream saw '$seen', want '$i'"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	for scheme in socks5h http; do
		kind=socks5
		[ "$scheme" = http ] && kind=http
		rlog="$WORK/up.log"
		: >"$rlog"
		up="$(pick_port)"
		python3 "$SERVERS_DIR/stub_upstream.py" "$kind" "$up" "$rlog" \
			>"$WORK/up.err" 2>&1 &
		up_pid=$!
		_PIDS+=("$up_pid")
		wait_listen "$up" "$up_pid" || fail "stub upstream did not listen"

		for t in "$NAME" "$LIT"; do
			run_case "accept, $t" "$t:80" "-P OUTPUT ACCEPT" "up $t 80"
			run_case "policy reject, $t" "$t:80" "-P OUTPUT REJECT" denied
			run_case "source reject, $t" "$t:80" \
				"-P OUTPUT ACCEPT\n-A OUTPUT -s 127.0.0.0/8 -j REJECT" denied
			run_case "DNAT, $t" "$t:80" \
				"-P OUTPUT ACCEPT\n-A OUTPUT -j DNAT --to 198.51.100.9:99" \
				"up 198.51.100.9 99"
			run_case "BIND, $t" "$t:80" \
				"-P OUTPUT ACCEPT\n-A OUTPUT -j BIND --to-source 127.0.0.77" \
				"up $t 80 127.0.0.77"
		done
		run_case "IPv6 literal" "[2001:db8::1]:80" "-P OUTPUT ACCEPT" \
			"up 2001:db8::1 80"

		# The rest depends neither on the upstream's protocol nor on the
		# event loop: both loops ask the same function for the verdict.
		if [ "$scheme" = http ] || [ "$loop" = io_uring ]; then
			kill "$up_pid" 2>/dev/null
			wait "$up_pid" 2>/dev/null
			continue
		fi

		run_case "--dports reject" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT --dports 80 -j REJECT" denied
		run_case "other --dports" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT --dports 81 -j REJECT" "up $NAME 80"
		run_case "address-only DNAT, name" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -j DNAT --to 198.51.100.9" \
			"up 198.51.100.9 80"

		# What only one form of target can match.
		run_case "-m domain" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -m domain --domain $NAME -j REJECT" denied
		run_case "-m domain, trailing dot" "$NAME.:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -m domain --domain $NAME -j REJECT" denied
		run_case "-m domain, rule with a trailing dot" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -m domain --domain $NAME. -j REJECT" denied
		run_case "-d, no address to match" "$NAME:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -d 0.0.0.0/0 -j REJECT" "up $NAME 80"
		run_case "-d, literal" "$LIT:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -d $LIT/32 -j REJECT" denied
		run_case "-d, IPv6 literal" "[2001:db8::1]:80" \
			"-P OUTPUT ACCEPT\n-A OUTPUT -d 2001:db8::1/128 -j REJECT" denied

		# The built-in rules apply here as well.
		run_case "default ACL, loopback literal" "127.0.0.1:80" - denied
		run_case "default ACL, localhost" "localhost:80" - denied
		run_case "default ACL, other name" "$NAME:80" - "up $NAME 80"

		kill "$up_pid" 2>/dev/null
		wait "$up_pid" 2>/dev/null
	done
done

# What cannot be a destination never gets as far as a connection.
for bad in nocolon "$NAME:0" "$NAME:99999" ":80" "sp ace:80" "a..b:80"; do
	"$GWPROXY" --bind=127.0.0.1:0 --target="$bad" --acl-allow-all \
		--upstream-proxy=socks5h://127.0.0.1:1 --nr-workers=1 \
		>"$WORK/bad.log" 2>&1 &
	bad_pid=$!
	_PIDS+=("$bad_pid")
	for _ in $(seq 1 100); do
		kill -0 "$bad_pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$bad_pid" 2>/dev/null \
		&& fail "--target='$bad' with a remote-DNS upstream was not refused at startup"
	wait "$bad_pid" 2>/dev/null
	[ "$?" != 0 ] || fail "--target='$bad': exit status 0"
	grep -q 'Invalid target address' "$WORK/bad.log" \
		|| fail "--target='$bad': no error logged: $(cat "$WORK/bad.log")"
done

pass

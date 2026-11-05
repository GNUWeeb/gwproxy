#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Which upstream hosts gwproxy takes, for --upstream-proxy and for the
# servers of ACL upstream pools alike. A name with one trailing dot
# ("localhost.") and an IPv4 address in a short form inet_aton() reads
# ("127.1") work, and tunnel to the upstream. A host that is neither a name
# nor an address ("-", "999.999.1.1") is refused without a lookup, and a
# name that does not resolve is refused saying so.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"

rp="$(pick_port)"
# Dual-stack: "localhost." may resolve to ::1 or to 127.0.0.1.
rlog="$WORK/rec.log"
: >"$rlog"
python3 "$SERVERS_DIR/recording_proxy.py" socks5 :: "$rp" "$rlog" \
	>"$WORK/rec.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$rp" "$!" || fail "the recording upstream did not listen"

# through <tag> <args...>: a front started with <args> tunnels through the
# recording upstream.
through()
{
	local tag="$1" fp n

	shift
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 "$@"
	n="$(wc -l <"$rlog")"
	curl -s --max-time 20 --proxy "socks5h://127.0.0.1:$fp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/out.bin" || \
		fail "$tag: the transfer failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"$tag: the payload was corrupted"
	[ "$(wc -l <"$rlog")" -eq $((n + 1)) ] || \
		fail "$tag: the upstream did not carry the tunnel"
	kill "$GWP_PID" 2>/dev/null
}

# refused <tag> <text> <args...>: gwproxy must not start, and say <text>.
refused()
{
	local tag="$1" text="$2" ec=0

	shift 2
	timeout --foreground 60 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
		--as-socks5=1 --acl-allow-all "$@" >"$WORK/refused.log" 2>&1 || \
		ec=$?
	{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
		fail "$tag: gwproxy started (exit $ec)"
	grep -qF -- "$text" "$WORK/refused.log" || {
		sed 's/^/# gwp: /' "$WORK/refused.log" >&2
		fail "$tag: no '$text'"
	}
}

d="$WORK/acl"
mkdir -p "$d"

for host in 127.1 localhost.; do
	through "[cli $host]" --acl-allow-all \
		--upstream-proxy="socks5h://$host:$rp"

	printf -- '%s\n' 'upstream p {' "	server socks5h://$host:$rp;" '}' \
		'-A OUTPUT -j UPSTREAM --to p' >"$d/p.acl"
	through "[pool $host]" --acl-file="$d/p.acl"
done

for host in - 999.999.1.1; do
	refused "[cli $host]" "Invalid --upstream-proxy value 'socks5://$host:1'" \
		--upstream-proxy="socks5://$host:1"
	printf -- '%s\n' 'upstream p {' "	server socks5://$host:1;" '}' \
		>"$d/p.acl"
	refused "[pool $host]" \
		"p.acl: line 2: upstream pool p server 1 (socks5://$host:1): the host is not a valid name or address" \
		--acl-file="$d/p.acl"
done

refused "[cli unresolvable]" \
	"--upstream-proxy host 'no-such-host.invalid' does not resolve" \
	--upstream-proxy="socks5://no-such-host.invalid:1"

pass

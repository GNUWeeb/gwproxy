#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --as-transparent: a connection redirected to the proxy by an iptables
# REDIRECT rule must be forwarded to its original destination, recovered via
# SO_ORIGINAL_DST. To keep the proxy's own re-connection from being redirected
# back into itself (a loop), we mark it with --mark and exclude marked packets
# from the REDIRECT rule ("! --mark"). curl aims straight at the server; the
# only way it can succeed is through the proxy resolving the original dst.
# Needs CAP_NET_ADMIN (SO_MARK) and iptables, so it is skipped without root or
# passwordless sudo.

. "$(dirname "$0")/lib.sh"
require curl
require python3

IPT="$(command -v iptables 2>/dev/null || echo /usr/sbin/iptables)"
[ -x "$IPT" ] || skip "iptables not available"

if [ "$(id -u)" = 0 ]; then
	SUDO=""
elif sudo -n true 2>/dev/null; then
	SUDO="sudo -n"
else
	skip "needs root or passwordless sudo (SO_ORIGINAL_DST + iptables)"
fi

MARK=10538
CMT="gwptest-tproxy-$$"

hp="$(pick_port)"	# real server; also the "original destination" curl aims at
pp="$(pick_port)"	# transparent proxy listener
make_payload "$WORK/payload.bin" 262144
start_httpd "$hp" "$WORK" "1.1"

# Redirect unmarked connections headed for the server to the proxy. The proxy's
# own (marked) reconnection is excluded, so it reaches the server, not a loop.
$SUDO "$IPT" -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark ! --mark "$MARK" \
	-j REDIRECT --to-ports "$pp" -m comment --comment "$CMT" \
	|| skip "cannot add iptables REDIRECT rule (insufficient privilege?)"

cleanup_priv()
{
	$SUDO "$IPT" -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark ! --mark "$MARK" \
		-j REDIRECT --to-ports "$pp" -m comment --comment "$CMT" 2>/dev/null
	$SUDO pkill -f "bind=127.0.0.1:$pp" 2>/dev/null
}
trap 'cleanup_priv; _cleanup' EXIT INT TERM

# Packets matching the REDIRECT rule (conntrack counts the connection's first
# packet). curl's unmarked connection is redirected here; the proxy's marked
# reconnection is excluded, so a bump proves curl went through the proxy.
count_redirect()
{
	$SUDO "$IPT" -t nat -nvxL OUTPUT | awk -v c="$CMT" '$0 ~ c { print $1; f=1 } END { if (!f) print -1 }'
}

$SUDO "$GWPROXY" --as-transparent=1 --mark="$MARK" --bind="127.0.0.1:$pp" \
	--nr-workers=1 --log-level=3 >"$WORK/gwp.log" 2>&1 &
wait_listen "$pp" \
	|| { sed 's/^/# gwp: /' "$WORK/gwp.log" >&2; fail "gwproxy did not listen on $pp"; }

before="$(count_redirect)"

# curl aims at the server; iptables redirects the connection to the proxy,
# which reads SO_ORIGINAL_DST and forwards back to the server.
curl -s --max-time 20 "http://127.0.0.1:$hp/payload.bin" -o "$WORK/out.bin" \
	|| fail "transparent-proxied curl failed"
assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
	"transparent proxy corrupted the payload"

after="$(count_redirect)"
diag "REDIRECT-rule counter: before=$before after=$after"
[ "$after" -gt "$before" ] \
	|| fail "connection was not redirected to the transparent proxy (counter $before -> $after)"

pass

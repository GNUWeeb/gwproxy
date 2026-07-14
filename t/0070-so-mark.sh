#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --mark: outgoing (target) connections must carry the configured SO_MARK
# (fwmark) so policy routing / iptables can match them. We add an iptables
# rule that counts packets leaving with our mark towards the test server, run
# a plain proxy with --mark set, push traffic through it, and assert the
# counter moved. Needs CAP_NET_ADMIN (SO_MARK) and iptables, so it is skipped
# when run without root or passwordless sudo.

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
	skip "needs root or passwordless sudo (SO_MARK + iptables)"
fi

MARK=10537
CMT="gwptest-mark-$$"

hp="$(pick_port)"
pp="$(pick_port)"
make_payload "$WORK/payload.bin" 65536
start_httpd "$hp" "$WORK" "1.1"

# Count packets leaving with our mark, headed for the test server.
$SUDO "$IPT" -A OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark --mark "$MARK" \
	-j ACCEPT -m comment --comment "$CMT" \
	|| skip "cannot add iptables rule (insufficient privilege?)"

cleanup_priv()
{
	$SUDO "$IPT" -D OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark --mark "$MARK" \
		-j ACCEPT -m comment --comment "$CMT" 2>/dev/null
	$SUDO pkill -f "bind=127.0.0.1:$pp" 2>/dev/null
}
trap 'cleanup_priv; _cleanup' EXIT INT TERM

count_rule()
{
	$SUDO "$IPT" -nvxL OUTPUT | awk -v c="$CMT" '$0 ~ c { print $1; f=1 } END { if (!f) print -1 }'
}

before="$(count_rule)"

$SUDO "$GWPROXY" --bind="127.0.0.1:$pp" --target="127.0.0.1:$hp" --mark="$MARK" \
	--nr-workers=1 --log-level=3 >"$WORK/gwp.log" 2>&1 &
wait_listen "$pp" \
	|| { sed 's/^/# gwp: /' "$WORK/gwp.log" >&2; fail "gwproxy did not listen on $pp"; }

curl -s --max-time 15 "http://127.0.0.1:$pp/payload.bin" -o "$WORK/out.bin" \
	|| fail "curl through the marked proxy failed"
assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
	"proxy corrupted the payload"

after="$(count_rule)"
diag "marked-packet counter: before=$before after=$after"
[ "$after" -gt "$before" ] \
	|| fail "SO_MARK not seen on the outgoing connection (counter $before -> $after)"

pass

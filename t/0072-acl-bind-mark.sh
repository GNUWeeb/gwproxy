#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# ACL -j MARK and -j BIND on the outgoing (target) socket. SO_MARK needs
# CAP_NET_ADMIN or CAP_NET_RAW, and the iptables mark match needs root, so the
# whole test is skipped without root or passwordless sudo. It checks, on every event loop:
#   * a per-rule -j MARK --set-mark N tags the outgoing connection (an iptables
#     mark match counts the packets), independent of the global --mark;
#   * -j BIND --to-iface lo binds the connection to a device and still works;
#   * -j BIND to a nonexistent device is strict -- the connection is dropped.

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
	skip "needs root or passwordless sudo (SO_MARK/SO_BINDTODEVICE + iptables)"
fi

MARK=10539
CMT="gwptest-aclmark-$$"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 65536
start_httpd "$hp" "$WORK" "1.1"

# A peer-reporting server for the --to-iface bind (the source stays 127.0.0.1,
# but the connection must still succeed with the device bound).
pa="$(pick_port)"
python3 "$SERVERS_DIR/peer_addr.py" 127.0.0.1 "$pa" >"$WORK/peer.log" 2>&1 &
_PIDS+=("$!")
sleep 0.3

# Count packets leaving with our mark, headed for the test server.
$SUDO "$IPT" -A OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark --mark "$MARK" \
	-j ACCEPT -m comment --comment "$CMT" \
	|| skip "cannot add iptables rule (insufficient privilege?)"

cleanup_priv()
{
	$SUDO "$IPT" -D OUTPUT -p tcp -d 127.0.0.1 --dport "$hp" -m mark --mark "$MARK" \
		-j ACCEPT -m comment --comment "$CMT" 2>/dev/null
	# PRIV_PID is not assigned until start_priv() runs, but this handler is
	# installed before that. Under lib.sh's `set -u` a bare $PRIV_PID would
	# abort the handler on any earlier exit -- leaving the root-installed
	# iptables rule above undeleted on the host.
	[ -n "${PRIV_PID:-}" ] && gwp_kill_priv "$PRIV_PID"
	return 0
}
# _cleanup exits via the EXIT trap in lib.sh; chain ours ahead of it.
trap 'cleanup_priv; _cleanup' EXIT
trap 'exit 143' INT TERM

count_rule()
{
	$SUDO "$IPT" -nvxL OUTPUT | awk -v c="$CMT" '$0 ~ c { print $1; f=1 } END { if (!f) print -1 }'
}

# Start gwproxy under sudo (SO_MARK needs CAP_NET_ADMIN or CAP_NET_RAW) on a
# given loop + acl file. $! is sudo's pid rather than the proxy's, so it is
# recorded as PRIV_PID and handed to gwp_kill_priv(), which finds the proxy
# below it by /proc/<pid>/exe. $1=port $2=target $3=acl $4=loop ; records
# CUR_PORT and PRIV_PID.
start_priv()
{
	CUR_PORT="$1"
	$SUDO "$GWPROXY" --bind="127.0.0.1:$1" --target="$2" \
		--acl-file="$3" --event-loop="$4" --nr-workers=1 \
		--log-level=3 >"$WORK/priv.log" 2>&1 &
	PRIV_PID=$!
	wait_listen "$1" "$PRIV_PID" \
		|| { sed 's/^/# gwp: /' "$WORK/priv.log" >&2; fail "gwproxy did not listen on $1"; }
}

stop_priv()
{
	gwp_kill_priv "${PRIV_PID:-}"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# Per-rule -j MARK: the outgoing connection carries the fwmark and the
	# iptables mark counter moves. No global --mark is set.
	printf -- '%s\n' "-A OUTPUT -p tcp --dports $hp -j MARK --set-mark $MARK" \
		'-P OUTPUT ACCEPT' >"$WORK/mark.acl"
	mpp="$(pick_port)"
	start_priv "$mpp" "127.0.0.1:$hp" "$WORK/mark.acl" "$loop"
	before="$(count_rule)"
	curl -s --max-time 15 "http://127.0.0.1:$mpp/payload.bin" -o "$WORK/m.out" \
		|| fail "[$loop] curl through the -j MARK proxy failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/m.out" \
		"[$loop] -j MARK proxy corrupted the payload"
	after="$(count_rule)"
	diag "[$loop] marked-packet counter: before=$before after=$after"
	[ "$after" -gt "$before" ] \
		|| fail "[$loop] -j MARK not seen on the outgoing connection ($before -> $after)"
	stop_priv

	# The same MARK rule with --accept: it terminates, so the REJECT below
	# it is never reached and the fetch still succeeds -- and the counter
	# still moves, proving the mark was applied on the way out rather than
	# the rule being skipped. Without --accept these rules deny everything.
	printf -- '%s\n' \
		"-A OUTPUT -p tcp --dports $hp -j MARK --set-mark $MARK --accept" \
		'-A OUTPUT -j REJECT' '-P OUTPUT ACCEPT' >"$WORK/markacc.acl"
	app="$(pick_port)"
	start_priv "$app" "127.0.0.1:$hp" "$WORK/markacc.acl" "$loop"
	before="$(count_rule)"
	curl -s --max-time 15 "http://127.0.0.1:$app/payload.bin" -o "$WORK/ma.out" \
		|| fail "[$loop] -j MARK --accept did not terminate before the REJECT"
	assert_files_equal "$WORK/payload.bin" "$WORK/ma.out" \
		"[$loop] -j MARK --accept proxy corrupted the payload"
	after="$(count_rule)"
	diag "[$loop] --accept marked-packet counter: before=$before after=$after"
	[ "$after" -gt "$before" ] \
		|| fail "[$loop] -j MARK --accept did not mark the connection ($before -> $after)"
	stop_priv

	# Control for the case above: drop --accept and the same pair of rules
	# rejects the connection, so the success above is the flag's doing.
	printf -- '%s\n' \
		"-A OUTPUT -p tcp --dports $hp -j MARK --set-mark $MARK" \
		'-A OUTPUT -j REJECT' '-P OUTPUT ACCEPT' >"$WORK/marknoacc.acl"
	npp="$(pick_port)"
	start_priv "$npp" "127.0.0.1:$hp" "$WORK/marknoacc.acl" "$loop"
	if curl -s --max-time 10 "http://127.0.0.1:$npp/payload.bin" \
		-o "$WORK/mn.out" 2>/dev/null; then
		stop_priv
		fail "[$loop] MARK without --accept did not fall through to REJECT"
	fi
	stop_priv

	# -j BIND --to-iface lo: SO_BINDTODEVICE succeeds and traffic flows.
	printf -- '%s\n' '-A OUTPUT -j BIND --to-iface lo' \
		'-P OUTPUT ACCEPT' >"$WORK/bindif.acl"
	bpp="$(pick_port)"
	start_priv "$bpp" "127.0.0.1:$pa" "$WORK/bindif.acl" "$loop"
	src="$(python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(10)
print(s.recv(64).decode().strip())' "$bpp" 2>/dev/null)"
	[ "$src" = 127.0.0.1 ] \
		|| fail "[$loop] BIND --to-iface lo broke the connection (saw '$src')"
	stop_priv

	# -j BIND to a nonexistent device is strict: the connection is dropped.
	printf -- '%s\n' "-A OUTPUT -j BIND --to-iface gwpnodev$$" \
		'-P OUTPUT ACCEPT' >"$WORK/badif.acl"
	xpp="$(pick_port)"
	start_priv "$xpp" "127.0.0.1:$pa" "$WORK/badif.acl" "$loop"
	if python3 -c 'import socket,sys
s=socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(5)
sys.exit(0 if s.recv(64) else 1)' "$xpp" 2>/dev/null; then
		fail "[$loop] BIND to a bad device was not strict (connection served)"
	fi
	stop_priv
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Once a TLS client's UDP association is up, what it sends on the control
# connection is dropped, but what the TLS engine has to say in answer to it
# must still go out: a KeyUpdate that asks for one back, say, when each comes
# in the same read as some data. Kept back, those answers pile up until the
# proxy stops reading the client to wait for them to drain, and as nothing
# drains them, the end of the control connection is never seen and the
# association outlives it. Direct and through a SOCKS5 upstream, on every
# event loop.

. "$(dirname "$0")/lib.sh"
require python3
require_opt --tls-cert
require openssl

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
	-subj '/CN=localhost' >/dev/null 2>&1 \
	|| skip "openssl could not generate a test certificate"

# run <name> <loop> [<proxy option>...]: the udpseg scenario on a TLS proxy.
run()
{
	local name="$1" loop="$2" pp out rc=0
	shift 2

	pp="$(pick_port)"
	# No keepalive: it is not what may end the association.
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --event-loop="$loop" \
		--tls-cert="$WORK/cert.pem" --tls-key="$WORK/key.pem" \
		--nr-workers=1 --target-buf-size=4096 --tcp-keepalive=0 "$@"
	out="$(timeout 120 python3 "$SERVERS_DIR/tls_keyupdate_client.py" \
		udpseg "$pp" "$GWP_PID" 2>&1)" || rc=$?
	[ "$rc" = 77 ] && skip "$out"
	[ "$out" = ok ] || fail "[$name] rc=$rc $out"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	run "$loop direct" "$loop"

	up="$(pick_port)"
	gwp_start "127.0.0.1:$up" --as-socks5=1 --event-loop="$loop"
	{
		echo 'upstream p {'
		echo "	server socks5://127.0.0.1:$up;"
		echo '}'
		echo '-A OUTPUT -s 127.0.0.1 -j UPSTREAM --to p'
		echo '-P OUTPUT ACCEPT'
	} >"$WORK/up.acl"
	chmod 600 "$WORK/up.acl"
	run "$loop upstream" "$loop" --acl-file="$WORK/up.acl"
done

pass

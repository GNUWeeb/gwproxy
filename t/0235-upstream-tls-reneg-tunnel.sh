#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An https:// upstream (TLS 1.2) sends a HelloRequest once the tunnel through
# it is up, and the client then sends more. gwproxy refuses to renegotiate,
# and the OpenSSL upstream takes that as fatal, so the tunnel ends at once.
# Had gwproxy started a renegotiation that the upstream leaves unanswered,
# the client's data could not be sent meanwhile: epoll spun a worker at full
# CPU, and io_uring held the tunnel for as long as the upstream did.
#
# On every event loop: the proxy's CPU stays idle over 2 s, the tunnel ends
# within 10 s (at once, in fact; the upstream would hold it for 30), and the
# upstream got the refusal, never a ClientHello.

. "$(dirname "$0")/lib.sh"
require python3
require openssl
require_opt --upstream-ca-file

ossl()
{
	openssl "$@" >>"$WORK/openssl.log" 2>&1 || {
		sed 's/^/# openssl: /' "$WORK/openssl.log" >&2
		skip "openssl could not make the test certificates"
	}
}
newkey="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
ossl req -x509 $newkey -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 2 \
	-subj "/CN=gwproxy test ca"
ossl req -new $newkey -keyout "$WORK/up.key" -out "$WORK/up.csr" \
	-subj "/CN=localhost"
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' \
	>"$WORK/up.ext"
ossl x509 -req -in "$WORK/up.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
	-set_serial "$RANDOM" -days 2 -extfile "$WORK/up.ext" -out "$WORK/up.pem"

up="$(pick_port)"
python3 "$SERVERS_DIR/tls_reneg_upstream.py" server after "$WORK/up.pem" \
	"$WORK/up.key" "$up" "$WORK/up.log" >"$WORK/up.out" 2>&1 &
_PIDS+=("$!")
wait_listen "$up" "$!" || {
	sed 's/^/# up: /' "$WORK/up.out" >&2
	grep -q 'no usable libssl' "$WORK/up.out" && skip "no usable libssl"
	fail "the upstream did not listen"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	: >"$WORK/up.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --upstream-proxy="https://127.0.0.1:$up" \
		--upstream-ca-file="$WORK/ca.pem"
	glog="$WORK/gwp.$fp.log"

	out="$(timeout 60 python3 "$SERVERS_DIR/tls_reneg_upstream.py" after \
		"$fp" "$GWP_PID" 2>&1)"
	[ "$out" = "no usable libssl" ] && skip "$out"
	diag "[$loop] $out"
	case "$out" in
	cpu=*" end="[0-9]*) ;;
	*)	sed 's/^/# gwp: /' "$glog" >&2
		fail "[$loop] the tunnel did not end in time: $out" ;;
	esac
	cpu="${out#cpu=}"
	cpu="${cpu%% *}"
	[ "$cpu" -le 25 ] ||
		fail "[$loop] the proxy used ${cpu}% CPU after the HelloRequest"
	grep -q '^reneg-refused$' "$WORK/up.log" ||
		fail "[$loop] the upstream did not get a refusal: $(cat "$WORK/up.log")"
	grep -q '^reneg-accepted$' "$WORK/up.log" &&
		fail "[$loop] gwproxy renegotiated"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

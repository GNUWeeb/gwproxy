#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An https:// pool server completes the TLS handshake, reads the CONNECT and
# answers it with a fatal alert. That is the server's own failure, like a
# failed handshake: on every event loop each client is retried on the pool's
# good server and gets its tunnel, the failures are logged as TLS ones with
# OpenSSL's reason and counted, and the broken server is ejected after the
# third.

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

# start_up <mode>: a tls_reneg_upstream.py server; sets UP.
start_up()
{
	local port pid

	port="$(pick_port)"
	: >"$WORK/$1.log"
	python3 "$SERVERS_DIR/tls_reneg_upstream.py" server "$1" \
		"$WORK/up.pem" "$WORK/up.key" "$port" "$WORK/$1.log" \
		>"$WORK/$1.out" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	wait_listen "$port" "$pid" || {
		sed 's/^/# up: /' "$WORK/$1.out" >&2
		grep -q 'no usable libssl' "$WORK/$1.out" &&
			skip "no usable libssl"
		fail "the $1 upstream did not listen"
	}
	UP="$port"
}
start_up alert;	bad="$UP"
start_up good;	good="$UP"

printf '%s\n' 'upstream p {' "	server https://127.0.0.1:$bad;" \
	"	server https://127.0.0.1:$good;" '}' \
	'-A OUTPUT -j UPSTREAM --to p' >"$WORK/p.acl"
chmod 600 "$WORK/p.acl"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	: >"$WORK/alert.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4 --acl-file="$WORK/p.acl" \
		--upstream-ca-file="$WORK/ca.pem"
	glog="$WORK/gwp.$fp.log"

	for i in 1 2 3 4 5 6 7 8 9 10; do
		out="$(timeout 60 python3 "$SERVERS_DIR/tls_reneg_upstream.py" \
			connect "$fp" 2>&1)"
		case "$out" in
		"rep=0x00 "*" echo=ok") ;;
		*)	tail -n 30 "$glog" | sed 's/^/# gwp: /' >&2
			fail "[$loop $i] the client got '$out'" ;;
		esac
	done

	n="$(grep -c '^alert-sent$' "$WORK/alert.log")"
	[ "$n" = 3 ] || fail "[$loop] the broken server failed $n clients, want 3"
	n="$(grep -c "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$bad, end=tls, class=upstream)" "$glog")"
	[ "$n" = 3 ] || {
		grep 'Upstream attempt failed' "$glog" | sed 's/^/# gwp: /' >&2
		fail "[$loop] $n failures noted as the server's TLS ones, want 3"
	}
	n="$(grep -E -i -c "Upstream TLS failed before the CONNECT reply \(class=upstream, .*up=127\.0\.0\.1:$bad\): .*alert bad record mac" "$glog")"
	[ "$n" = 3 ] || {
		grep 'Upstream TLS' "$glog" | sed 's/^/# gwp: /' >&2
		fail "[$loop] $n failures logged with the TLS reason, want 3"
	}
	n="$(grep -c "Upstream pool p server 1 (.*:$bad) ejected for 300 s after 3 failures in 30 s" "$glog")"
	[ "$n" = 1 ] || {
		grep -i 'eject' "$glog" | sed 's/^/# gwp: /' >&2
		fail "[$loop] the broken server was ejected $n times, want 1"
	}
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
done

pass

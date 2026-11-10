#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An https:// upstream (TLS 1.2) reads the CONNECT and, before it replies,
# sends a HelloRequest and waits for the answer. gwproxy's engine refuses
# with a no_renegotiation alert, which has to be sent although nothing else
# is: the OpenSSL upstream takes it as fatal and fails the session. On every
# event loop the client is refused (REP 0x01) within a few seconds, where
# the upstream waits for 30 and --connect-timeout is 10, and the failure is
# noted as the upstream's TLS failure.

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
start_up before;	hr="$UP"

# check <loop> <mode> <port> <want>: a client through a front on the upstream
# at <port> gets <want> ("rep=0x01 secs=*", say) within 5 seconds.
check()
{
	local loop="$1" mode="$2" port="$3" want="$4" out secs

	: >"$WORK/$mode.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=1 --log-level=4 --connect-timeout=10 \
		--upstream-proxy="https://127.0.0.1:$port" \
		--upstream-ca-file="$WORK/ca.pem"
	glog="$WORK/gwp.$fp.log"
	out="$(timeout 60 python3 "$SERVERS_DIR/tls_reneg_upstream.py" \
		connect "$fp" 2>&1)"
	diag "[$loop $mode] $out"
	# shellcheck disable=SC2254
	case "$out" in
	$want) ;;
	*)	tail -n 20 "$glog" | sed 's/^/# gwp: /' >&2
		fail "[$loop $mode] the client got '$out', want '$want'" ;;
	esac
	secs="${out#* secs=}"
	secs="${secs%%[. ]*}"
	[ "$secs" -lt 5 ] ||
		fail "[$loop $mode] the client waited ${out#* secs=} s"
	kill "$GWP_PID" 2>/dev/null
	wait "$GWP_PID" 2>/dev/null
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	check "$loop" before "$hr" "rep=0x01 secs=*"
	grep -q '^reneg-refused$' "$WORK/before.log" ||
		fail "[$loop before] the upstream got no refusal: $(cat "$WORK/before.log")"
	grep -q "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$hr, end=tls, class=upstream)" "$glog" || {
		grep 'Upstream' "$glog" | sed 's/^/# gwp: /' >&2
		fail "[$loop before] the failure was not noted as the upstream's TLS one"
	}
done

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# https:// servers in ACL upstream pools, verified like an https://
# --upstream-proxy: against --upstream-ca-file (one trust store for all),
# with each server's own host sent as SNI and checked. On every available
# event loop:
#
#  - a pool's https server, named by name (SNI) and by address (no SNI),
#    tunnels SOCKS5 and HTTP clients end to end, and the credentials and the
#    CONNECT reach it only inside TLS;
#  - a CA that did not sign its certificate, and a certificate for another
#    name, each fail the connection (SOCKS5 REP 0x01, HTTP 502), logged with
#    the reason and class=upstream, before any CONNECT is sent;
#  - a pool may mix http:// and https:// servers (both resolve remotely);
#  - a reload that adds an https server to a proxy that had none routes
#    through it, and a reload with an https server that cannot be set up is
#    refused and keeps the rules in force;
#  - --upstream-ca-file goes with an --acl-file alone, and is checked at
#    startup there too.
#
# Built without OpenSSL, it checks that an https:// pool server is refused
# at load, saying why, and skips the rest.

. "$(dirname "$0")/lib.sh"
require curl
require python3

if ! "$GWPROXY" --help 2>&1 | grep -q -- --upstream-ca-file; then
	printf -- '%s\n' 'upstream p {' '	server https://127.0.0.1:1;' '}' \
		'-A OUTPUT -j UPSTREAM --to p' >"$WORK/nossl.acl"
	rc=0
	timeout --foreground 10 "$GWPROXY" --as-socks5=1 \
		--bind="127.0.0.1:$(pick_port)" --acl-file="$WORK/nossl.acl" \
		>"$WORK/nossl.log" 2>&1 || rc=$?
	[ "$rc" = 0 ] || [ "$rc" = 124 ] &&
		fail "an https:// pool server loaded without OpenSSL"
	grep -q 'server 1 (https://127.0.0.1:1): https:// needs gwproxy built with OpenSSL' \
		"$WORK/nossl.log" || {
		sed 's/^/# gwp: /' "$WORK/nossl.log" >&2
		fail "the refusal without OpenSSL did not say why"
	}
	skip "gwproxy has no OpenSSL; checked the load error only"
fi

require openssl
require base64

ossl()
{
	openssl "$@" >>"$WORK/openssl.log" 2>&1 || {
		sed 's/^/# openssl: /' "$WORK/openssl.log" >&2
		skip "openssl could not make the test certificates"
	}
}
newkey="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
# Two CAs: ca signs the upstreams' certificates, ca2 signs nothing.
for c in ca ca2; do
	ossl req -x509 $newkey -keyout "$WORK/$c.key" -out "$WORK/$c.pem" \
		-days 2 -subj "/CN=gwproxy test $c"
done
# leaf <name> <subjectAltName>
leaf()
{
	ossl req -new $newkey -keyout "$WORK/$1.key" -out "$WORK/$1.csr" \
		-subj "/CN=$1"
	printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$2" \
		>"$WORK/$1.ext"
	ossl x509 -req -in "$WORK/$1.csr" -CA "$WORK/ca.pem" \
		-CAkey "$WORK/ca.key" -set_serial "$RANDOM" -days 2 \
		-extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
}
leaf good 'DNS:localhost,IP:127.0.0.1'
leaf other 'DNS:other.invalid'

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

creds="up:s3cr3t"
b64="$(printf '%s' "$creds" | base64)"

# start_up <name> <cert>: a TLS CONNECT upstream, demanding $creds. Sets UP.
start_up()
{
	local port pid

	port="$(pick_port)"
	python3 "$SERVERS_DIR/tls_upstream.py" server "$WORK/$2.pem" \
		"$WORK/$2.key" "$port" "$WORK/$1.log" "$creds" \
		>"$WORK/$1.out" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	if ! wait_listen "$port" "$pid"; then
		sed 's/^/# up: /' "$WORK/$1.out" >&2
		fail "the TLS upstream $1 did not start on port $port"
	fi
	UP="$port"
}
start_up good good;	good="$UP"
start_up other other;	other="$UP"

# A cleartext recording HTTP CONNECT upstream.
rh="$(pick_port)"
: >"$WORK/rec.log"
python3 "$SERVERS_DIR/recording_proxy.py" http 127.0.0.1 "$rh" \
	"$WORK/rec.log" >"$WORK/rec.err" 2>&1 &
_PIDS+=("$!")
wait_listen "$rh" "$!" || fail "the http upstream did not listen"

# reset <name>: forget what the upstream <name> has seen.
reset()
{
	: >"$WORK/$1.log"
	: >"$WORK/$1.log.raw"
	: >"$WORK/$1.log.plain"
}

# The upstream <name> saw the credentials and a CONNECT, only decrypted.
check_inside_tls()
{
	local log="$WORK/$1.log"

	grep -q "^connect .* auth=Basic $b64\$" "$log" ||
		fail "[$1] the upstream did not get the credentials"
	grep -q "^CONNECT " "$log.plain" ||
		fail "[$1] the upstream did not get a CONNECT"
	for s in CONNECT Proxy-Authorization "$b64" s3cr3t; do
		grep -aq -- "$s" "$log.raw" &&
			fail "[$1] '$s' went to the upstream outside TLS"
	done
	return 0
}

# acl <file> <server URL>...: one pool "p" of those servers, for everyone.
acl()
{
	local f="$1" u; shift

	{
		echo 'upstream p {'
		for u in "$@"; do
			echo "	server $u;"
		done
		echo '}'
		echo '-A OUTPUT -j UPSTREAM --to p'
	} >"$f.tmp"
	chmod 600 "$f.tmp"
	mv "$f.tmp" "$f"
}

# get <tag> <curl proxy args...>: fetch the payload, which must arrive intact.
get()
{
	local tag="$1"; shift

	rm -f "$WORK/out.bin"
	curl -s --max-time 30 "$@" "http://127.0.0.1:$hp/payload.bin" \
		-o "$WORK/out.bin" || fail "[$tag] curl failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$tag] the payload arrived corrupted"
}

# echo_through <tag> <socks5|http> <port>: 500 kB each way, in parallel.
echo_through()
{
	python3 "$SERVERS_DIR/tls_upstream.py" echo "$2" "$3" 500000 \
		>"$WORK/echo.out" 2>&1 || {
		sed 's/^/# echo: /' "$WORK/echo.out" >&2
		fail "[$1] the $2 tunnel did not echo"
	}
}

# start <loop> <acl file> <ca file>: a SOCKS5 and HTTP front on that set.
start()
{
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$1" --nr-workers=2 --acl-file="$2" \
		--upstream-ca-file="$3"
	glog="$WORK/gwp.$fp.log"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	# By name: SNI, and the certificate's DNS name.
	reset good
	acl "$WORK/p.acl" "https://$creds@localhost:$good"
	start "$loop" "$WORK/p.acl" "$WORK/ca.pem"
	get "$loop/name/socks5" -x "socks5h://127.0.0.1:$fp"
	get "$loop/name/connect" --proxytunnel -x "http://127.0.0.1:$fp"
	get "$loop/name/forward" -x "http://127.0.0.1:$fp"
	echo_through "$loop/name" socks5 "$fp"
	echo_through "$loop/name" http "$fp"
	kill "$GWP_PID" 2>/dev/null
	grep -q '^hs-ok sni=localhost$' "$WORK/good.log" ||
		fail "[$loop/name] the upstream got no SNI for localhost"
	grep -q '^hs-ok sni=-$' "$WORK/good.log" &&
		fail "[$loop/name] a connection went without SNI"
	grep -q "^connect 127.0.0.1:$hp " "$WORK/good.log" ||
		fail "[$loop/name] the upstream was not asked for the origin"
	check_inside_tls good
	grep -q s3cr3t "$glog" && fail "[$loop/name] the password was logged"

	# By address: no SNI, and the certificate's IP address.
	reset good
	acl "$WORK/p.acl" "https://$creds@127.0.0.1:$good"
	start "$loop" "$WORK/p.acl" "$WORK/ca.pem"
	get "$loop/ip/socks5" -x "socks5h://127.0.0.1:$fp"
	get "$loop/ip/connect" --proxytunnel -x "http://127.0.0.1:$fp"
	kill "$GWP_PID" 2>/dev/null
	grep -q '^hs-ok sni=-$' "$WORK/good.log" ||
		fail "[$loop/ip] no connection to the upstream by address"
	grep -q '^hs-ok sni=[^-]' "$WORK/good.log" &&
		fail "[$loop/ip] an address was sent as SNI"
	check_inside_tls good

	# Refused: <server> <CA file> <reason in the log>, matched without
	# case (OpenSSL 1.1.1 says "Hostname mismatch").
	for c in "good ca2 unable to get local issuer certificate" \
		 "other ca hostname mismatch"; do
		set -- $c
		srv="$1" ca="$2"; shift 2
		why="$*"
		tag="$loop/$srv/$ca"

		reset "$srv"
		acl "$WORK/p.acl" "https://$creds@localhost:${!srv}"
		start "$loop" "$WORK/p.acl" "$WORK/$ca.pem"
		rep="$(python3 "$SERVERS_DIR/tls_upstream.py" socks5-rep "$fp" 2>&1)"
		[ "$rep" = "rep=0x01" ] ||
			fail "[$tag] SOCKS5 answered '$rep', want rep=0x01"
		code="$(curl -s --max-time 20 --proxytunnel \
			-x "http://127.0.0.1:$fp" -w '%{http_connect}' \
			"http://127.0.0.1:$hp/payload.bin" -o /dev/null)"
		[ "$code" = 502 ] ||
			fail "[$tag] HTTP CONNECT answered '$code', want 502"
		kill "$GWP_PID" 2>/dev/null
		wait "$GWP_PID" 2>/dev/null

		grep -E -i -q "Upstream TLS handshake failed \(class=upstream, .*host=localhost, .*\): certificate verify failed: $why" "$glog" || {
			sed 's/^/# gwp: /' "$glog" >&2
			fail "[$tag] no log of the refusal with '$why'"
		}
		grep -q '^hs-fail' "$WORK/$srv.log" ||
			fail "[$tag] the upstream saw no failed handshake"
		grep -q '^connect' "$WORK/$srv.log" &&
			fail "[$tag] the upstream got a CONNECT"
		[ -s "$WORK/$srv.log.plain" ] &&
			fail "[$tag] the upstream got application data"
		for s in CONNECT Proxy-Authorization "$b64" s3cr3t; do
			grep -aq -- "$s" "$WORK/$srv.log.raw" &&
				fail "[$tag] '$s' went to the upstream"
		done
	done

	# http:// and https:// in one pool. Every connection goes through one
	# of the two, and arrives; the https one is listed first so it is
	# used whichever way the pool picks.
	reset good
	: >"$WORK/rec.log"
	acl "$WORK/p.acl" "https://$creds@localhost:$good" \
		"http://127.0.0.1:$rh"
	start "$loop" "$WORK/p.acl" "$WORK/ca.pem"
	for i in 1 2 3 4; do
		get "$loop/mixed/$i" -x "socks5h://127.0.0.1:$fp"
	done
	kill "$GWP_PID" 2>/dev/null
	n_tls="$(grep -c '^connect ' "$WORK/good.log")"
	n_web="$(grep -c "^authority=127.0.0.1:$hp" "$WORK/rec.log")"
	[ "$n_tls" -ge 1 ] && [ $((n_tls + n_web)) -eq 4 ] ||
		fail "[$loop/mixed] the https server saw $n_tls and the http one $n_web of 4"

	# A reload adds the first https server to a running proxy: with an
	# --acl-file alone, --upstream-ca-file is taken and used.
	reset good
	: >"$WORK/rec.log"
	acl "$WORK/r.acl" "http://127.0.0.1:$rh"
	start "$loop" "$WORK/r.acl" "$WORK/ca.pem"
	get "$loop/reload/before" -x "socks5h://127.0.0.1:$fp"
	grep -q "^authority=127.0.0.1:$hp" "$WORK/rec.log" ||
		fail "[$loop/reload] the http pool was not used before the reload"
	acl "$WORK/r.acl" "https://$creds@localhost:$good"
	gwp_hup "$GWP_PID" "$glog" 1
	grep -q 'Reloaded ACL file' "$glog" ||
		fail "[$loop/reload] the https pool did not load"
	get "$loop/reload/socks5" -x "socks5h://127.0.0.1:$fp"
	get "$loop/reload/connect" --proxytunnel -x "http://127.0.0.1:$fp"
	grep -q '^hs-ok sni=localhost$' "$WORK/good.log" ||
		fail "[$loop/reload] the added https server was not used"
	check_inside_tls good

	# One that cannot be set up fails the reload; the rules stay.
	n_bad="$(grep -c 'Failed to reload ACL file' "$glog")"
	acl "$WORK/r.acl" "https://$creds@nohost.invalid:$good"
	gwp_hup "$GWP_PID" "$glog" 1
	[ "$(grep -c 'Failed to reload ACL file' "$glog")" -gt "$n_bad" ] ||
		fail "[$loop/reload] a bad https server did not fail the reload"
	grep -q 'upstream pool p server 1 (https://nohost.invalid:[0-9]*): host nohost.invalid does not resolve' \
		"$glog" || fail "[$loop/reload] the bad server was not reported"
	n="$(grep -c '^hs-ok' "$WORK/good.log")"
	get "$loop/reload/kept" -x "socks5h://127.0.0.1:$fp"
	[ "$(grep -c '^hs-ok' "$WORK/good.log")" -gt "$n" ] ||
		fail "[$loop/reload] the failed reload dropped the https pool"
	kill "$GWP_PID" 2>/dev/null
	grep -q s3cr3t "$glog" && fail "[$loop/reload] the password was logged"
done

# Startup: --upstream-ca-file alone is still an error; with an --acl-file it
# is read at startup, like with an https:// --upstream-proxy.
# expect_startup_error <what> <message> <args...>
expect_startup_error()
{
	local what="$1" msg="$2" rc=0
	shift 2

	timeout --foreground 10 "$GWPROXY" --as-socks5=1 \
		--bind="127.0.0.1:$(pick_port)" "$@" >"$WORK/start.log" 2>&1 ||
		rc=$?
	case "$rc" in
	0)	fail "$what: gwproxy exited successfully" ;;
	124)	fail "$what: gwproxy started" ;;
	esac
	grep -q -- "$msg" "$WORK/start.log" || {
		sed 's/^/# gwp: /' "$WORK/start.log" >&2
		fail "$what: no '$msg' in the error"
	}
}

expect_startup_error "--upstream-ca-file alone" \
	"--upstream-ca-file needs an https:// --upstream-proxy or an --acl-file" \
	--upstream-ca-file="$WORK/ca.pem"
expect_startup_error "a CA file that does not exist, with an ACL file" \
	"Cannot read --upstream-ca-file" \
	--acl-file="$WORK/p.acl" --upstream-ca-file="$WORK/nonexistent.pem"
: >"$WORK/empty.pem"
expect_startup_error "an empty CA file, with an ACL file" \
	"No usable CA certificate in --upstream-ca-file" \
	--acl-file="$WORK/p.acl" --upstream-ca-file="$WORK/empty.pem"

pass

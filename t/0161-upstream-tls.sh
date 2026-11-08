#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# An https:// upstream proxy (--upstream-proxy=https://...): HTTP CONNECT over
# TLS to the proxy, whose certificate is verified. On both event loops:
#
#  - SOCKS5 and HTTP clients (CONNECT and forwarding) tunnel through it end to
#    end, with the CA from --upstream-ca-file, naming the proxy by name (sent
#    as SNI) and by IP address (not sent), and so does a TLS client;
#  - the credentials and the CONNECT reach the proxy only inside TLS;
#  - a response the HTTP forwarding filter refuses ends with its 502 and a
#    FIN, not a reset;
#  - a certificate for another name or address, one with the name only as
#    its CN, an untrusted (self-signed) one and an expired one each fail the
#    connection (HTTP 502, SOCKS5 REP 0x01), are logged with the reason and
#    class=upstream, and the proxy never sees a CONNECT or the credentials;
#  - --upstream-ca-file without an https:// upstream, and a CA file that
#    cannot be read or holds no certificate, are startup errors.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require openssl
require cmp
require base64
require_opt --upstream-ca-file

# A test CA, and certificates from it: for localhost and 127.0.0.1, for
# another name only, and one that has expired. Plus a self-signed one.
ossl()
{
	openssl "$@" >>"$WORK/openssl.log" 2>&1 || {
		sed 's/^/# openssl: /' "$WORK/openssl.log" >&2
		skip "openssl could not make the test certificates"
	}
}
newkey="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
ossl req -x509 $newkey -keyout "$WORK/ca.key" -out "$WORK/ca.pem" -days 2 \
	-subj '/CN=gwproxy test CA'
# leaf <name> <subjectAltName> <days>
leaf()
{
	ossl req -new $newkey -keyout "$WORK/$1.key" -out "$WORK/$1.csr" \
		-subj "/CN=$1"
	printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$2" \
		>"$WORK/$1.ext"
	ossl x509 -req -in "$WORK/$1.csr" -CA "$WORK/ca.pem" \
		-CAkey "$WORK/ca.key" -set_serial "$RANDOM" -days "$3" \
		-extfile "$WORK/$1.ext" -out "$WORK/$1.pem"
}
leaf good 'DNS:localhost,IP:127.0.0.1' 2
leaf other 'DNS:other.invalid' 2
leaf expired 'DNS:localhost,IP:127.0.0.1' -1
# The name only as the subject's CN, with no subjectAltName at all.
ossl req -new $newkey -keyout "$WORK/cn.key" -out "$WORK/cn.csr" \
	-subj '/CN=localhost'
printf 'basicConstraints=CA:FALSE\n' >"$WORK/cn.ext"
ossl x509 -req -in "$WORK/cn.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
	-set_serial "$RANDOM" -days 2 -extfile "$WORK/cn.ext" -out "$WORK/cn.pem"
openssl x509 -in "$WORK/expired.pem" -noout -checkend 0 >/dev/null 2>&1 &&
	skip "openssl could not make an expired certificate"
ossl req -x509 $newkey -keyout "$WORK/self.key" -out "$WORK/self.pem" \
	-days 2 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 300000
start_httpd "$hp" "$WORK" "1.1"

creds="up:s3cr3t"
b64="$(printf '%s' "$creds" | base64)"

# start_up <name> <cert>: the TLS CONNECT proxy, demanding $creds. Sets UP.
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
		fail "the TLS upstream proxy did not start on port $port"
	fi
	UP="$port"
}
start_up good good;	good="$UP"
start_up other other;	other="$UP"
start_up self self;	self="$UP"
start_up expired expired; expired="$UP"
start_up cn cn;		cn="$UP"

# The proxy must have seen the credentials and the CONNECT only decrypted.
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

# echo_through <tag> <socks5|http> <port>: 1 MB each way, in parallel.
echo_through()
{
	python3 "$SERVERS_DIR/tls_upstream.py" echo "$2" "$3" 1000000 \
		>"$WORK/echo.out" 2>&1 || {
		sed 's/^/# echo: /' "$WORK/echo.out" >&2
		fail "[$1] the $2 tunnel did not echo"
	}
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	# By name: SNI, and the certificate's DNS name.
	: >"$WORK/good.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 \
		--upstream-proxy="https://$creds@localhost:$good" \
		--upstream-ca-file="$WORK/ca.pem"
	get "$loop/name/socks5" -x "socks5h://127.0.0.1:$fp"
	get "$loop/name/connect" --proxytunnel -x "http://127.0.0.1:$fp"
	get "$loop/name/forward" -x "http://127.0.0.1:$fp"
	echo_through "$loop/name" socks5 "$fp"
	echo_through "$loop/name" http "$fp"
	# A response the forwarding filter refuses ends in its own 502, with a
	# FIN: what the engine still holds of the rest is no cut stream.
	out="$(python3 "$SERVERS_DIR/tls_upstream.py" junk "$fp" 2>&1)" ||
		fail "[$loop/junk] $out"
	[ "$out" = "eof HTTP/1.1 502 Bad Gateway" ] ||
		fail "[$loop/junk] got '$out', want a 502 and a clean end"
	kill "$GWP_PID" 2>/dev/null
	grep -q '^hs-ok sni=localhost$' "$WORK/good.log" ||
		fail "[$loop/name] the upstream got no SNI for localhost"
	grep -q '^hs-ok sni=-$' "$WORK/good.log" &&
		fail "[$loop/name] a connection went without SNI"
	check_inside_tls good

	# By address: no SNI, and the certificate's IP address.
	: >"$WORK/good.log"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 \
		--upstream-proxy="https://$creds@127.0.0.1:$good" \
		--upstream-ca-file="$WORK/ca.pem"
	get "$loop/ip/socks5" -x "socks5h://127.0.0.1:$fp"
	get "$loop/ip/connect" --proxytunnel -x "http://127.0.0.1:$fp"
	echo_through "$loop/ip" socks5 "$fp"
	kill "$GWP_PID" 2>/dev/null
	grep -q '^hs-ok sni=-$' "$WORK/good.log" ||
		fail "[$loop/ip] no connection to the upstream by address"
	grep -q '^hs-ok sni=[^-]' "$WORK/good.log" &&
		fail "[$loop/ip] an address was sent as SNI"
	check_inside_tls good

	# A TLS client through it: an engine on either side of the pair.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 \
		--tls-cert="$WORK/self.pem" --tls-key="$WORK/self.key" \
		--upstream-proxy="https://$creds@localhost:$good" \
		--upstream-ca-file="$WORK/ca.pem"
	get "$loop/tls-client" --proxy-insecure --proxytunnel \
		-x "https://127.0.0.1:$fp"
	get "$loop/tls-client/forward" --proxy-insecure -x "https://127.0.0.1:$fp"
	kill "$GWP_PID" 2>/dev/null

	# Refused certificates: <server> <host> <reason in the log>. The
	# reason is matched without case: OpenSSL 1.1.1 says "Hostname
	# mismatch" where 3.x says "hostname mismatch".
	for c in "other localhost hostname mismatch" \
		 "other 127.0.0.1 IP address mismatch" \
		 "self localhost self.signed certificate" \
		 "expired localhost certificate has expired" \
		 "cn localhost hostname mismatch"; do
		set -- $c
		srv="$1" host="$2"; shift 2
		why="$*"
		port="${!srv}"
		tag="$loop/$srv/$host"

		: >"$WORK/$srv.log"
		: >"$WORK/$srv.log.raw"
		: >"$WORK/$srv.log.plain"
		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
			--event-loop="$loop" --nr-workers=2 \
			--upstream-proxy="https://$creds@$host:$port" \
			--upstream-ca-file="$WORK/ca.pem"
		glog="$WORK/gwp.$fp.log"

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

		grep -E -i -q "Upstream TLS handshake failed \(class=upstream, .*host=$host, .*\): certificate verify failed: $why" "$glog" || {
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
done

# Startup errors. expect_startup_error <what> <message> <args...>
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
	"--upstream-ca-file needs an https://" \
	--upstream-ca-file="$WORK/ca.pem"
expect_startup_error "--upstream-ca-file with http://" \
	"--upstream-ca-file needs an https://" \
	--upstream-proxy="http://localhost:$good" --upstream-ca-file="$WORK/ca.pem"
expect_startup_error "a CA file that does not exist" \
	"Cannot read --upstream-ca-file" \
	--upstream-proxy="https://localhost:$good" \
	--upstream-ca-file="$WORK/nonexistent.pem"
: >"$WORK/empty.pem"
expect_startup_error "an empty CA file" \
	"No usable CA certificate in --upstream-ca-file" \
	--upstream-proxy="https://localhost:$good" \
	--upstream-ca-file="$WORK/empty.pem"
expect_startup_error "a CA file with no certificate in it" \
	"No usable CA certificate in --upstream-ca-file" \
	--upstream-proxy="https://localhost:$good" \
	--upstream-ca-file="$WORK/good.key"
if [ "$(id -u)" != 0 ]; then
	cp "$WORK/ca.pem" "$WORK/noread.pem"
	chmod 000 "$WORK/noread.pem"
	expect_startup_error "an unreadable CA file" \
		"Cannot read --upstream-ca-file" \
		--upstream-proxy="https://localhost:$good" \
		--upstream-ca-file="$WORK/noread.pem"
fi

pass

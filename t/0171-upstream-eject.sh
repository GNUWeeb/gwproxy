#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Passive health of upstream pool servers, on every available event loop.
#
#  - A server that fails in a way that is its own fault (refuses the TCP
#    connection, answers HTTP 407, refuses our SOCKS5 credentials, fails
#    the TLS handshake) costs its clients nothing at first: each one is
#    retried, once, on another server of the pool and gets through. After
#    three such failures in 30 s the server is ejected, logged once, and no
#    longer picked (the --log-level=4 pick lines show it).
#  - A failure that is the destination's (SOCKS5 REP 0x05, HTTP 502 from
#    the upstream) reaches the client as it is, is not retried and never
#    ejects the healthy server that reported it.
#  - A pool of one server keeps using it once ejected: only the log tells.
#    With every server of a pool ejected (one of them by its failures in
#    another pool that lists it: the health is the server's, not the
#    pool's), clients get the usual refusal and the proxy keeps trying the
#    server whose ejection ends soonest.
#  - A SIGHUP reload that rebuilds the pool keeps the ejection; a server
#    taken out of every pool and put back later starts afresh.
#  - A destination that never answers times the CONNECT out: the client
#    hears of it, and the healthy upstream that waited for it is not
#    charged. An https:// upstream that resets the connection before
#    the TLS handshake fails each client with the usual refusal, every
#    time counted (on epoll the reset can beat the first TLS step).
#  - Plain --target forwarding retries too, after a refused connect and
#    after a 407; so does an https:// server whose certificate is not for
#    the name it is reached by (with OpenSSL).
#
# The 5-minute ejection's end is covered by the unit tests
# (src/gwproxy/tests/upstream_lb.c).

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 20000
start_httpd "$hp" "$WORK" "1.1"
url="http://127.0.0.1:$hp/payload.bin"

# rec_start <socks5|http> <name>: a recording upstream; sets REC_PORT.
rec_start()
{
	local port log="$WORK/rec.$2.log"

	port="$(pick_port)"
	: >"$log"
	python3 "$SERVERS_DIR/recording_proxy.py" "$1" 127.0.0.1 "$port" \
		"$log" >"$WORK/rec.$2.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $2 upstream did not listen"
	REC_PORT="$port"
}

# fault_start <socks5|http> <name> <fault>: an upstream that goes wrong
# (upstream_faults.py); sets FAULT_PORT.
fault_start()
{
	local port

	port="$(pick_port)"
	echo "$3" >"$WORK/fault.$2"
	python3 "$SERVERS_DIR/upstream_faults.py" "$1" "$port" \
		"$WORK/fault.$2" >"$WORK/fault.$2.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$port" "$!" || fail "the $2 upstream did not listen"
	FAULT_PORT="$port"
}

rec_start socks5 g1;		g1="$REC_PORT"
rec_start socks5 g2;		g2="$REC_PORT"
rec_start http rh;		rh="$REC_PORT"
fault_start http f407 auth_required;	f407="$FAULT_PORT"
fault_start socks5 fauth auth_fail;	fauth="$FAULT_PORT"
fault_start socks5 frep refuse;		frep="$FAULT_PORT"
fault_start http f502 bad_gateway;	f502="$FAULT_PORT"
closed_port;	dead1="$CLOSED_PORT"
closed_port;	dead2="$CLOSED_PORT"
closed_port;	dead3="$CLOSED_PORT"

# A destination that never answers, behind two more recording upstreams,
# and an upstream that resets every connection as soon as it accepts it.
python3 "$SERVERS_DIR/blackhole_listener.py" 127.0.0.1 >"$WORK/bh" 2>&1 &
_PIDS+=("$!")
for i in $(seq 1 100); do
	bh="$(head -n 1 "$WORK/bh")"
	[ -n "$bh" ] && break
	sleep 0.1
done
[ -n "$bh" ] || fail "the black hole did not start"
rec_start socks5 g3;		g3="$REC_PORT"
rec_start socks5 g4;		g4="$REC_PORT"
fault_start http frst rst_accept;	frst="$FAULT_PORT"
ssl=0
"$GWPROXY" --help 2>&1 | grep -q -- --upstream-ca-file && ssl=1

# With OpenSSL: two TLS upstreams whose certificates the CA signed, one for
# the name it is reached by, one for another name.
tls=0
if "$GWPROXY" --help 2>&1 | grep -q -- --upstream-ca-file &&
   command -v openssl >/dev/null 2>&1; then
	tls=1
	newkey="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
	# shellcheck disable=SC2086
	openssl req -x509 $newkey -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
		-days 2 -subj "/CN=gwproxy test ca" >>"$WORK/openssl.log" 2>&1 ||
		tls=0
	for c in "good DNS:localhost" "other DNS:other.invalid"; do
		set -- $c
		# shellcheck disable=SC2086
		openssl req -new $newkey -keyout "$WORK/$1.key" \
			-out "$WORK/$1.csr" -subj "/CN=$1" \
			>>"$WORK/openssl.log" 2>&1 || tls=0
		printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$2" \
			>"$WORK/$1.ext"
		openssl x509 -req -in "$WORK/$1.csr" -CA "$WORK/ca.pem" \
			-CAkey "$WORK/ca.key" -set_serial "$RANDOM" -days 2 \
			-extfile "$WORK/$1.ext" -out "$WORK/$1.pem" \
			>>"$WORK/openssl.log" 2>&1 || tls=0
	done
fi
if [ "$tls" = 1 ]; then
	for c in good other; do
		port="$(pick_port)"
		python3 "$SERVERS_DIR/tls_upstream.py" server "$WORK/$c.pem" \
			"$WORK/$c.key" "$port" "$WORK/tls.$c.log" \
			>"$WORK/tls.$c.out" 2>&1 &
		_PIDS+=("$!")
		wait_listen "$port" "$!" || fail "the TLS upstream $c did not listen"
		printf -v "tls_$c" '%s' "$port"
	done
fi

printf '%s\n' tcp:p u407:p auth:p dst:p dsth:p one:p all:p >"$WORK/auth"
acl="$WORK/main.acl"

# write_acl <p_tcp servers...>: every pool, with p_tcp's servers as given
# (none: p_tcp holds g1 alone).
write_acl()
{
	local p

	{
		echo 'upstream p_tcp {'
		[ $# -eq 0 ] && set -- "$g1"
		for p in "$@"; do
			echo "	server socks5h://127.0.0.1:$p;"
		done
		echo '}'
		echo 'upstream p_407 {'
		echo "	server http://127.0.0.1:$f407;"
		echo "	server http://127.0.0.1:$rh;"
		echo '}'
		echo 'upstream p_auth {'
		echo "	server socks5h://up:wrong@127.0.0.1:$fauth;"
		echo "	server socks5h://127.0.0.1:$g2;"
		echo '}'
		echo 'upstream p_dst {'
		echo "	server socks5h://127.0.0.1:$frep;"
		echo "	server socks5h://127.0.0.1:$g1;"
		echo '}'
		echo 'upstream p_dsth {'
		echo "	server http://127.0.0.1:$f502;"
		echo "	server http://127.0.0.1:$rh;"
		echo '}'
		echo 'upstream p_one {'
		echo "	server socks5h://127.0.0.1:$dead2;"
		echo '}'
		echo 'upstream p_all {'
		echo "	server socks5h://127.0.0.1:$dead2;"
		echo "	server socks5h://127.0.0.1:$dead3;"
		echo '}'
		for p in tcp:p_tcp u407:p_407 auth:p_auth dst:p_dst \
			 dsth:p_dsth one:p_one all:p_all; do
			echo "-A OUTPUT -m user --user ${p%%:*} -j UPSTREAM --to ${p#*:}"
		done
	} >"$acl.tmp"
	chmod 600 "$acl.tmp"
	mv "$acl.tmp" "$acl"
}

# picks <pool>: the servers <pool> was picked for, in order, as "1 2 1".
picks()
{
	sed -n "s/.*Upstream for idx=[0-9]*: pool $1 server \([0-9]*\), .*/\1/p" \
		"$log" | tr '\n' ' ' | sed 's/ $//'
}

# nretry <pool>: how many pairs of <pool> were retried on another server.
nretry()
{
	grep -c "Upstream retry for idx=[0-9]*: pool $1 server " "$log"
}

# nejected <port>: how many times the server at <port> was ejected.
nejected()
{
	grep -c "Upstream pool [a-z_0-9]* server [0-9]* (127\.0\.0\.1:$1) ejected for 300 s after 3 failures in 30 s" "$log"
}

# nfailed <port> <end> <class>: failures of the server at <port>, so ended
# and classed.
nfailed()
{
	grep -c "Upstream attempt failed (idx=[0-9]*, up=[^,]*:$1, end=$2, class=$3)" "$log"
}

# get <tag> <curl args...>: the payload must arrive intact.
get()
{
	local tag="$1"; shift

	rm -f "$WORK/out.bin"
	curl -s --max-time 20 "$@" "$url" -o "$WORK/out.bin" ||
		fail "[$tag] the transfer failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"[$tag] the payload was corrupted"
}

# rep <user>: the SOCKS5 REP the front answers <user>'s CONNECT with.
rep()
{
	python3 "$SERVERS_DIR/socks5_probe.py" --user "$1" --pass p \
		--atyp domain --dst localhost "$fp" "$hp"
}

# want <tag> <what> <got> <want>
want()
{
	[ "$3" = "$4" ] || {
		tail -n 40 "$log" | sed 's/^/# gwp: /' >&2
		fail "[$1] $2: got '$3', want '$4'"
	}
}

# stop_front <pid>: SIGTERM the front and wait (bounded) for it to exit.
stop_front()
{
	local pid="$1" i

	wait_sigterm_handled "$pid" || fail "front $pid never set up SIGTERM"
	kill -TERM "$pid" 2>/dev/null
	for i in $(seq 1 200); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -0 "$pid" 2>/dev/null && fail "front $pid did not exit on SIGTERM"
	wait "$pid" 2>/dev/null
}

# exit_clean <tag>: the stopped front found every reference given back.
exit_clean()
{
	if grep -q "BUG:" "$log"; then
		grep "BUG:" "$log" | sed 's/^/# gwp: /' >&2
		fail "$1: gwproxy found an accounting bug"
	fi
	grep -q "Upstream pool servers: all connection references dropped" \
		"$log" || {
		tail -n 20 "$log" | sed 's/^/# gwp: /' >&2
		fail "$1: no verdict on the pool servers' references at exit"
	}
}

# plain <tag> <servers...>: plain --target forwarding through a pool of
# those http:// servers: four transfers, all through; sets PLAIN_LOG.
plain()
{
	local tag="$1" s i; shift

	{
		echo 'upstream pp {'
		for s in "$@"; do
			echo "	server http://127.0.0.1:$s;"
		done
		echo '}'
		echo '-A OUTPUT -j UPSTREAM --to pp'
	} >"$WORK/plain.acl"
	chmod 600 "$WORK/plain.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --target="127.0.0.1:$hp" \
		--event-loop="$loop" --nr-workers=2 --log-level=4 \
		--acl-file="$WORK/plain.acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	for i in 1 2 3 4; do
		rm -f "$WORK/out.bin"
		curl -s --max-time 20 "http://127.0.0.1:$fp/payload.bin" \
			-o "$WORK/out.bin" || fail "[$tag $i] the transfer failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$tag $i] the payload was corrupted"
	done
	want "$tag" "picks" "$(picks pp)" "1 2 1 2"
	want "$tag" "retries" "$(nretry pp)" 2
	stop_front "$front"
	exit_clean "[$tag]"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	write_acl "$dead1" "$g1"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 --log-level=4 \
		--auth-file="$WORK/auth" --acl-file="$acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"

	# A server that refuses the TCP connection: every client gets
	# through, the first three by a retry; then it is out.
	for i in 1 2 3 4 5 6 7 8 9 10; do
		get "$loop tcp $i" --proxy "socks5h://tcp:p@127.0.0.1:$fp"
	done
	want "$loop tcp" "picks" "$(picks p_tcp)" "1 2 1 2 1 2 2 2 2 2"
	want "$loop tcp" "retries" "$(nretry p_tcp)" 3
	want "$loop tcp" "ejections" "$(nejected "$dead1")" 1
	want "$loop tcp" "failures" "$(nfailed "$dead1" connect upstream)" 3

	# HTTP 407, through the HTTP front (CONNECT and forwarding).
	for i in 1 2 3 4 5 6; do
		if [ $((i % 2)) = 1 ]; then
			get "$loop 407 $i" --proxytunnel \
				--proxy "http://u407:p@127.0.0.1:$fp"
		else
			get "$loop 407 $i" --proxy "http://u407:p@127.0.0.1:$fp"
		fi
	done
	want "$loop 407" "picks" "$(picks p_407)" "1 2 1 2 1 2"
	want "$loop 407" "retries" "$(nretry p_407)" 3
	want "$loop 407" "ejections" "$(nejected "$f407")" 1
	want "$loop 407" "failures" "$(nfailed "$f407" http-status upstream)" 3
	get "$loop 407 after" --proxy "http://u407:p@127.0.0.1:$fp"
	want "$loop 407 after" "picks" "$(picks p_407)" "1 2 1 2 1 2 2"

	# SOCKS5 credentials refused.
	for i in 1 2 3 4; do
		get "$loop auth $i" --proxy "socks5h://auth:p@127.0.0.1:$fp"
	done
	want "$loop auth" "picks" "$(picks p_auth)" "1 2 1 2"
	want "$loop auth" "retries" "$(nretry p_auth)" 2
	want "$loop auth" "failures" "$(nfailed "$fauth" socks5-auth upstream)" 2
	want "$loop auth" "ejections" "$(nejected "$fauth")" 0
	grep -q wrong "$log" && fail "[$loop auth] a password was logged"

	# The destination refused, behind a healthy server: the client hears
	# it, nothing is retried or ejected, the server stays in turn.
	got=""
	for i in 1 2 3 4 5 6; do
		got="$got $(rep dst)"
	done
	want "$loop dst" "replies" "$got" \
		" REP=0x05 REP=0x00 REP=0x05 REP=0x00 REP=0x05 REP=0x00"
	want "$loop dst" "picks" "$(picks p_dst)" "1 2 1 2 1 2"
	want "$loop dst" "retries" "$(nretry p_dst)" 0
	want "$loop dst" "ejections" "$(nejected "$frep")" 0
	want "$loop dst" "failures" "$(nfailed "$frep" socks5-rep destination)" 3
	got=""
	for i in 1 2 3 4 5 6; do
		got="$got $(curl -s --max-time 20 --proxytunnel \
			--proxy "http://dsth:p@127.0.0.1:$fp" -w '%{http_connect}' \
			"$url" -o /dev/null)"
	done
	want "$loop dsth" "CONNECT replies" "$got" " 502 200 502 200 502 200"
	want "$loop dsth" "retries" "$(nretry p_dsth)" 0
	want "$loop dsth" "ejections" "$(nejected "$f502")" 0

	# A pool of one: ejected, and still used.
	r0="$(rep one)"
	[ "$r0" != REP=0x00 ] || fail "[$loop one] a dead upstream connected"
	for i in 2 3 4; do
		want "$loop one $i" "reply" "$(rep one)" "$r0"
	done
	want "$loop one" "picks" "$(picks p_one)" "1 1 1 1"
	want "$loop one" "ejections" "$(nejected "$dead2")" 1
	want "$loop one" "retries" "$(nretry p_one)" 0

	# Every server of p_all out (dead2 already is, by its failures in
	# p_one): the usual refusal, and the one back soonest, dead2, is the
	# one tried.
	sleep 0.2
	for i in 1 2 3; do
		want "$loop all $i" "reply" "$(rep all)" "$r0"
	done
	want "$loop all" "picks" "$(picks p_all)" "2 2 2"
	want "$loop all" "ejections" "$(nejected "$dead3")" 1
	for i in 4 5 6; do
		want "$loop all $i" "reply" "$(rep all)" "$r0"
	done
	want "$loop all" "picks" "$(picks p_all)" "2 2 2 1 1 1"
	want "$loop all" "retries" "$(nretry p_all)" 0
	[ "$(grep -c "Upstream pool p_all has every server ejected; idx=[0-9]* takes server 1, back soonest" "$log")" = 3 ] ||
		fail "[$loop all] the all-ejected picks were not logged"
	want "$loop all" "dead2's ejections" "$(nejected "$dead2")" 1

	# A reload rebuilds p_tcp, in the other order: dead1 stays out.
	write_acl "$g1" "$dead1"
	gwp_hup "$front" "$log" 2
	grep -q "Failed to reload" "$log" && fail "[$loop] the reload failed"
	for i in 1 2 3 4; do
		get "$loop reload $i" --proxy "socks5h://tcp:p@127.0.0.1:$fp"
	done
	want "$loop reload" "picks" "$(picks p_tcp)" "1 2 1 2 1 2 2 2 2 2 1 1 1 1"
	want "$loop reload" "retries" "$(nretry p_tcp)" 3
	want "$loop reload" "ejections" "$(nejected "$dead1")" 1
	grep -q "back in service" "$log" &&
		fail "[$loop reload] a server came back before its time"

	# Out of every pool, then back: nothing kept its state, so it is
	# picked again, fails, and its client is retried.
	write_acl
	gwp_hup "$front" "$log" 2
	write_acl "$dead1" "$g1"
	gwp_hup "$front" "$log" 2
	get "$loop back" --proxy "socks5h://tcp:p@127.0.0.1:$fp"
	want "$loop back" "picks" "$(picks p_tcp)" "1 2 1 2 1 2 2 2 2 2 1 1 1 1 1"
	want "$loop back" "retries" "$(nretry p_tcp)" 4
	want "$loop back" "failures" "$(nfailed "$dead1" connect upstream)" 4

	stop_front "$front"
	exit_clean "[$loop]"

	# Plain forwarding: a refused connect, and a 407 after it connected.
	plain "$loop plain tcp" "$dead1" "$rh"
	want "$loop plain tcp" "failures" "$(nfailed "$dead1" connect upstream)" 2
	plain "$loop plain 407" "$f407" "$rh"
	want "$loop plain 407" "failures" "$(nfailed "$f407" http-status upstream)" 2

	# A destination that never answers holds the upstream's CONNECT
	# reply up until the connect timeout: the client hears of the
	# timeout (REP 0x06), and the healthy servers are not charged.
	printf '%s\n' 'upstream p_bh {' \
		"	server socks5://127.0.0.1:$g3;" \
		"	server socks5://127.0.0.1:$g4;" '}' \
		'-A OUTPUT -j UPSTREAM --to p_bh' >"$WORK/bh.acl"
	chmod 600 "$WORK/bh.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --log-level=4 --connect-timeout=2 \
		--acl-file="$WORK/bh.acl"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	pids=()
	for i in 1 2 3 4 5 6; do
		python3 "$SERVERS_DIR/socks5_probe.py" --atyp ipv4 \
			--dst 127.0.0.1 "$fp" "$bh" >"$WORK/bh.$loop.$i" 2>&1 &
		pids+=("$!")
	done
	wait "${pids[@]}"
	got="$(cat "$WORK"/bh."$loop".* | sort | uniq -c | tr -s ' ')"
	want "$loop blackhole" "replies" "$got" " 6 REP=0x06"
	want "$loop blackhole" "ejections" \
		"$(($(nejected "$g3") + $(nejected "$g4")))" 0
	want "$loop blackhole" "retries" "$(nretry p_bh)" 0
	want "$loop blackhole" "uncounted timeouts" \
		"$(($(nfailed "$g3" timeout neutral) + $(nfailed "$g4" timeout neutral)))" 6
	stop_front "$front"
	exit_clean "[$loop blackhole]"

	# An https:// upstream that resets the connection before the TLS
	# handshake has begun: every client gets its refusal (REP 0x01), each
	# failure is classified. On epoll the reset can come between the
	# connect's completion and the first TLS step, which then fails at
	# once; it needs many connections at a time to show.
	if [ "$ssl" = 1 ]; then
		printf '%s\n' 'upstream p_rst {' \
			"	server https://127.0.0.1:$frst;" '}' \
			'-A OUTPUT -j UPSTREAM --to p_rst' >"$WORK/rst.acl"
		chmod 600 "$WORK/rst.acl"
		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --log-level=4 --acl-file="$WORK/rst.acl"
		front="$GWP_PID"
		log="$WORK/gwp.$fp.log"
		for b in 1 2 3 4 5 6 7 8; do
			pids=()
			for i in $(seq 1 25); do
				python3 "$SERVERS_DIR/socks5_probe.py" \
					--atyp domain --dst localhost "$fp" 80 \
					>"$WORK/rst.$loop.$b.$i" 2>&1 &
				pids+=("$!")
			done
			wait "${pids[@]}"
		done
		got="$(cat "$WORK"/rst."$loop".* | sort | uniq -c | tr -s ' ')"
		want "$loop rst" "replies" "$got" " 200 REP=0x01"
		want "$loop rst" "classified" \
			"$(grep -c "Upstream attempt failed (idx=[0-9]*, up=127\.0\.0\.1:$frst, end=[a-z]*, class=upstream)" "$log")" 200
		stop_front "$front"
		exit_clean "[$loop rst]"
	fi

	# An https:// server that fails its certificate check.
	[ "$tls" = 1 ] || continue
	printf '%s\n' 'upstream p_tls {' \
		"	server https://localhost:$tls_other;" \
		"	server https://localhost:$tls_good;" '}' \
		'-A OUTPUT -j UPSTREAM --to p_tls' >"$WORK/tls.acl"
	chmod 600 "$WORK/tls.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --as-http=1 \
		--event-loop="$loop" --nr-workers=2 --log-level=4 \
		--acl-file="$WORK/tls.acl" --upstream-ca-file="$WORK/ca.pem"
	front="$GWP_PID"
	log="$WORK/gwp.$fp.log"
	for i in 1 2 3 4; do
		if [ "$i" -le 2 ]; then
			get "$loop tls $i" --proxy "socks5h://127.0.0.1:$fp"
		else
			get "$loop tls $i" --proxytunnel \
				--proxy "http://127.0.0.1:$fp"
		fi
	done
	want "$loop tls" "picks" "$(picks p_tls)" "1 2 1 2"
	want "$loop tls" "retries" "$(nretry p_tls)" 2
	want "$loop tls" "failures" "$(nfailed "$tls_other" tls upstream)" 2
	grep -q '^connect ' "$WORK/tls.other.log" &&
		fail "[$loop tls] the failing server got a CONNECT"
	stop_front "$front"
	exit_clean "[$loop tls]"
done

# The upstreams saw what got through, and no more: g1 the 10 + 4 + 1
# connections of p_tcp and the 3 of p_dst per loop, never the ones they
# were not picked or retried for.
loops=1
have_io_uring && loops=2
want "upstreams" "g1's connections" "$(wc -l <"$WORK/rec.g1.log")" $((loops * 18))
want "upstreams" "g2's connections" "$(wc -l <"$WORK/rec.g2.log")" $((loops * 4))

pass

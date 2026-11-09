#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# -j UPSTREAM routes a connection through the upstream pool an ACL rule
# picks. Two users go through two pools (a socks5:// and an http:// one,
# with their own credentials), a third through the --upstream-proxy
# default, and a fourth DIRECT, past the default. Recording upstreams show
# which connections each saw, with which credentials and destination: the
# socks5:// pool resolves the name here and is sent an address, the http://
# pool and the socks5h:// default are sent the name. The upstream is picked
# before the name is resolved, so -d picks a pool for a target given as an
# address, not for one given by name, and a user keeps a pool even when a
# default-deny set lets targets through by -d alone. Plain --target
# forwarding goes through a pool too. A UDP ASSOCIATE goes to the pool of a
# user the rules send through one, and is granted to one they send DIRECT, past
# --upstream-proxy; it has no target, so a rule that tests one is not taken
# in either polarity, and a pool rule passed over that way refuses it.
# On every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 50000
start_httpd "$hp" "$WORK" "1.1"

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

rec_start socks5 s5
rs="$REC_PORT"
rec_start http web
rh="$REC_PORT"
rec_start socks5 def
rd="$REC_PORT"

# The proxy's own users.
printf '%s\n' alice:pa bob:pb carol:pc dave:pd erin:pe >"$WORK/auth"

d="$WORK/acl"
mkdir -p "$d"
cat >"$d/main.acl" <<EOF
upstream s5 {
	server socks5://a_up:a_pw@127.0.0.1:$rs;
}
upstream web {
	server http://b_up:b_pw@127.0.0.1:$rh;
}
-A OUTPUT -m user --user alice -j UPSTREAM --to s5
-A OUTPUT -m user --user bob -j UPSTREAM --to-proxy web
-A OUTPUT -m user --user dave -j UPSTREAM --to DIRECT
-A OUTPUT -m user --user erin -d 127.0.0.1 -j UPSTREAM --to web
-P OUTPUT ACCEPT
EOF
chmod 600 "$d/main.acl"

cat >"$d/deny.acl" <<EOF
upstream s5 {
	server socks5://a_up:a_pw@127.0.0.1:$rs;
}
-A OUTPUT -m user --user alice -j UPSTREAM --to s5
-A OUTPUT -d 127.0.0.1 -j ACCEPT
-A OUTPUT -d ::1 -j ACCEPT
-P OUTPUT REJECT
EOF
chmod 600 "$d/deny.acl"

# UDP ASSOCIATE has no target: alice's "direct but for one name" is not
# taken, bob's pool for one name may be his, carol's "! -d" is not taken.
cat >"$d/udp.acl" <<EOF
upstream s5 {
	server socks5://127.0.0.1:$rs;
}
-A OUTPUT -m user --user alice -m domain ! --domain secret.example -j UPSTREAM --to DIRECT
-A OUTPUT -m user --user bob -m domain --domain secret.example -j UPSTREAM --to s5
-A OUTPUT -m user --user carol ! -d 10.0.0.0/8 -j UPSTREAM --to DIRECT
EOF
chmod 600 "$d/udp.acl"

# Runs of pool rules long enough for the ACL's index (8), by name and by
# address: a UDP ASSOCIATE has neither, and must still be refused.
for kind in dom net; do
	{
		printf '%s\n' 'upstream s5 {' "	server socks5://127.0.0.1:$rs;" '}'
		for i in 1 2 3 4 5 6 7 8; do
			if [ "$kind" = dom ]; then
				echo "-A OUTPUT -m domain --domain h$i.example -j UPSTREAM --to s5 --accept"
			else
				echo "-A OUTPUT -d 10.0.$i.0/24 -j UPSTREAM --to s5 --accept"
			fi
		done
	} >"$d/udp-$kind.acl"
	chmod 600 "$d/udp-$kind.acl"
done

# udp_rep <tag> <proxy-port> <user:pass> <rep>: a UDP ASSOCIATE gets <rep>.
udp_rep()
{
	local got

	got="$(python3 "$SERVERS_DIR/socks5_udp_assoc.py" "$2" "${3%%:*}" \
		"${3#*:}" 2>&1)"
	[ "$got" = "REP $4" ] || \
		fail "$1 UDP ASSOCIATE for ${3%%:*} got '$got', want REP $4"
}

# lines <name>: how many requests the <name> upstream has seen.
lines()
{
	wc -l <"$WORK/rec.$1.log"
}

# fetch <tag> <proxy-url> <url>: a transfer that must arrive whole.
fetch()
{
	rm -f "$WORK/out.bin"
	curl -s --max-time 20 --proxy "$2" "$3" -o "$WORK/out.bin" || \
		fail "$1: the transfer failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
		"$1: the payload was corrupted"
}

# saw <tag> <name> <line>: the <name> upstream's last request was <line>,
# and it saw one more than it had (in N_<name>).
saw()
{
	local n="N_$2" got

	got="$(tail -n 1 "$WORK/rec.$2.log")"
	[ "$(lines "$2")" -eq $((${!n} + 1)) ] || \
		fail "$1: the $2 upstream saw $(lines "$2") requests, want $((${!n} + 1)); last '$got'"
	case "$got" in
	$3) ;;
	*) fail "$1: the $2 upstream saw '$got', want '$3'" ;;
	esac
}

# count: remember how many requests each upstream has seen.
count()
{
	N_s5="$(lines s5)"
	N_web="$(lines web)"
	N_def="$(lines def)"
}

# unseen <tag>: no upstream saw anything since count().
unseen()
{
	[ "$(lines s5)" -eq "$N_s5" ] && [ "$(lines web)" -eq "$N_web" ] && \
	[ "$(lines def)" -eq "$N_def" ] || \
		fail "$1: an upstream saw a connection that should have gone direct"
}

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --auth-file="$WORK/auth" --log-level=4 \
		--acl-file="$d/main.acl" \
		--upstream-proxy="socks5h://c_up:c_pw@127.0.0.1:$rd"
	log="$WORK/gwp.$fp.log"
	url="http://localhost:$hp/payload.bin"

	count
	fetch "[$loop alice]" "socks5h://alice:pa@127.0.0.1:$fp" "$url"
	saw "[$loop alice]" s5 "atyp=[14] addr=* port=$hp user=a_up pass=a_pw"
	grep -q "atyp=1 addr=127.0.0.1 port=$hp\|atyp=4 addr=::1 port=$hp" \
		"$WORK/rec.s5.log" || fail "[$loop alice] the socks5:// pool was not sent an address"

	count
	fetch "[$loop bob]" "socks5h://bob:pb@127.0.0.1:$fp" "$url"
	saw "[$loop bob]" web "authority=localhost:$hp auth=b_up:b_pw"

	count
	fetch "[$loop carol]" "socks5h://carol:pc@127.0.0.1:$fp" "$url"
	saw "[$loop carol]" def "atyp=3 addr=localhost port=$hp user=c_up pass=c_pw"

	count
	fetch "[$loop dave]" "socks5h://dave:pd@127.0.0.1:$fp" "$url"
	unseen "[$loop dave]"

	# -d sees an address the client gave, never a name.
	count
	fetch "[$loop erin addr]" "socks5h://erin:pe@127.0.0.1:$fp" \
		"http://127.0.0.1:$hp/payload.bin"
	saw "[$loop erin addr]" web "authority=127.0.0.1:$hp auth=b_up:b_pw"
	count
	fetch "[$loop erin name]" "socks5h://erin:pe@127.0.0.1:$fp" "$url"
	saw "[$loop erin name]" def "atyp=3 addr=localhost port=$hp user=c_up pass=c_pw"

	grep -q "pool s5 server 1, 127.0.0.1:$rs" "$log" || \
		fail "[$loop] the pool and server were not logged"
	grep -q "none (DIRECT)" "$log" || fail "[$loop] DIRECT was not logged"
	! grep -q "a_pw\|b_pw\|c_pw" "$log" || \
		fail "[$loop] an upstream password was logged"

	# A pool user's UDP ASSOCIATE goes to the pool's socks5:// server,
	# which turns it down (REP 7, answered REP 1), DIRECT gets the relay
	# past --upstream-proxy, and no choice leaves the default to refuse it.
	udp_rep "[$loop]" "$fp" alice:pa 1
	tail -n 1 "$WORK/rec.s5.log" | grep -q '^cmd=3 ' || \
		fail "[$loop] alice's UDP ASSOCIATE did not reach her pool"
	udp_rep "[$loop]" "$fp" dave:pd 0
	udp_rep "[$loop]" "$fp" carol:pc 7
	kill "$GWP_PID" 2>/dev/null

	# Without --upstream-proxy, no choice gets the relay; a pool still not.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --auth-file="$WORK/auth" \
		--acl-file="$d/main.acl"
	udp_rep "[$loop no default]" "$fp" alice:pa 1
	udp_rep "[$loop no default]" "$fp" dave:pd 0
	udp_rep "[$loop no default]" "$fp" carol:pc 0
	kill "$GWP_PID" 2>/dev/null

	for def in "" "--upstream-proxy=socks5://127.0.0.1:$rd"; do
		tag="[$loop udp${def:+ default}]"
		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --auth-file="$WORK/auth" \
			--acl-file="$d/udp.acl" $def
		udp_rep "$tag" "$fp" alice:pa "$([ -n "$def" ] && echo 7 || echo 0)"
		udp_rep "$tag" "$fp" bob:pb 7
		udp_rep "$tag" "$fp" carol:pc "$([ -n "$def" ] && echo 7 || echo 0)"
		kill "$GWP_PID" 2>/dev/null
	done

	for kind in dom net; do
		fp="$(pick_port)"
		gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --auth-file="$WORK/auth" \
			--acl-file="$d/udp-$kind.acl"
		udp_rep "[$loop udp $kind index]" "$fp" bob:pb 7
		kill "$GWP_PID" 2>/dev/null
	done

	# A default-deny set that lets targets through by -d: the user's pool
	# is kept for a target by name (which no -d rule can match before it
	# resolves) and by address, never left for a direct connection.
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --event-loop="$loop" \
		--nr-workers=2 --auth-file="$WORK/auth" \
		--acl-file="$d/deny.acl"
	count
	fetch "[$loop deny name]" "socks5h://alice:pa@127.0.0.1:$fp" "$url"
	saw "[$loop deny name]" s5 "atyp=[14] addr=* port=$hp user=a_up pass=a_pw"
	count
	fetch "[$loop deny addr]" "socks5h://alice:pa@127.0.0.1:$fp" \
		"http://127.0.0.1:$hp/payload.bin"
	saw "[$loop deny addr]" s5 "atyp=1 addr=127.0.0.1 port=$hp user=a_up pass=a_pw"
	count
	fetch "[$loop deny bob]" "socks5h://bob:pb@127.0.0.1:$fp" "$url"
	unseen "[$loop deny bob]"
	kill "$GWP_PID" 2>/dev/null

	# Plain forwarding to a --target name: through the pool the ACL picks
	# for that name, which resolves it; and through a socks5:// pool, which
	# is sent the address.
	printf -- '%s\n' "upstream web {" "server http://127.0.0.1:$rh;" "}" \
		'-A OUTPUT -m domain --domain localhost -j UPSTREAM --to web' \
		>"$d/plain.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --event-loop="$loop" --nr-workers=2 \
		--target="localhost:$hp" --acl-file="$d/plain.acl"
	count
	fetch "[$loop plain name]" "" "http://127.0.0.1:$fp/payload.bin"
	saw "[$loop plain name]" web "authority=localhost:$hp"
	kill "$GWP_PID" 2>/dev/null

	printf -- '%s\n' "upstream s5 {" "server socks5://127.0.0.1:$rs;" "}" \
		'-A OUTPUT -d 127.0.0.1 -j UPSTREAM --to s5' >"$d/plain.acl"
	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --event-loop="$loop" --nr-workers=2 \
		--target="127.0.0.1:$hp" --acl-file="$d/plain.acl" \
		--upstream-proxy="socks5h://127.0.0.1:$rd"
	count
	fetch "[$loop plain addr]" "" "http://127.0.0.1:$fp/payload.bin"
	saw "[$loop plain addr]" s5 "atyp=1 addr=127.0.0.1 port=$hp"
	kill "$GWP_PID" 2>/dev/null
done

pass

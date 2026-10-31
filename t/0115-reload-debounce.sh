#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# A burst of changes to --auth-file and --acl-file is reloaded once it has
# settled, not once per change, and the reload reads the last version of each
# file. Changes that never pause are still reloaded now and then rather than
# waiting for a pause that never comes. Exercised on every available event
# loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# fetch <proxy-port> <user> <pass>: succeed iff the proxy let the request
# through to the origin.
fetch()
{
	curl -s --max-time 5 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null
}

# wait_fetch <want:0|1> <proxy-port> <user> <pass>: poll until fetch()
# succeeds (want=1) or fails (want=0).
wait_fetch()
{
	local i ok

	for i in $(seq 1 50); do
		ok=0
		fetch "$2" "$3" "$4" && ok=1
		[ "$ok" = "$1" ] && return 0
		sleep 0.1
	done
	return 1
}

# put <file> <contents>: replace <file> by rename, as editors do.
put()
{
	printf '%s' "$2" >"$1.new"
	mv -f "$1.new" "$1"
}

# nr_reloads <log> <auth|ACL>: how many reloads of that file were logged.
nr_reloads()
{
	local what="authentication file"

	[ "$2" = ACL ] && what="ACL file"
	grep -c "Reloaded $what" "$1"
}

allow=$'-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n'
deny="-A OUTPUT -d 127.0.0.1 --dports $hp -j REJECT"$'\n'"$allow"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	put "$WORK/auth" $'u0:pw\n'
	put "$WORK/acl" "$allow"
	pp="$(pick_port)"
	log="$WORK/gwp.$pp.log"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--acl-file="$WORK/acl" --event-loop="$loop" --nr-workers=1
	fetch "$pp" u0 pw || fail "[$loop] initial credentials rejected"

	# A burst: 20 versions of each file, about 10 ms apart, then one more
	# of the ACL. Only the last versions count: version 20 of the ACL
	# denies the origin, the one after it allows it again.
	for i in $(seq 1 20); do
		put "$WORK/auth" "u$i:pw"$'\n'
		if [ "$i" = 20 ]; then
			put "$WORK/acl" "$deny"
		else
			put "$WORK/acl" "# version $i"$'\n'"$allow"
		fi
		sleep 0.01
	done
	put "$WORK/acl" "$allow"
	wait_fetch 1 "$pp" u20 pw \
		|| fail "[$loop] the last version of the auth file was not loaded"
	fetch "$pp" u19 pw \
		&& fail "[$loop] an earlier version of the auth file is in force"
	sleep 1
	a="$(nr_reloads "$log" auth)"
	l="$(nr_reloads "$log" ACL)"
	diag "[$loop] burst of 20: $a auth and $l ACL reloads"
	[ "$a" -le 5 ] || fail "[$loop] a burst of 20 changes gave $a auth reloads"
	[ "$l" -le 5 ] || fail "[$loop] a burst of 21 changes gave $l ACL reloads"

	# A single change after the burst is reloaded on its own.
	put "$WORK/acl" "$deny"
	wait_fetch 0 "$pp" u20 pw \
		|| fail "[$loop] the last version of the ACL file was not loaded"

	put "$WORK/acl" "$allow"
	wait_fetch 1 "$pp" u20 pw \
		|| fail "[$loop] the ACL file put back was not loaded"

	# Changes every 20 ms for 3 s never pause long enough to settle, yet
	# they are reloaded meanwhile, not only once they stop.
	a0="$(nr_reloads "$log" auth)"
	end=$((SECONDS + 3))
	i=100
	while [ "$SECONDS" -lt "$end" ]; do
		i=$((i + 1))
		put "$WORK/auth" "u$i:pw"$'\n'
		sleep 0.02
	done
	a="$(( $(nr_reloads "$log" auth) - a0 ))"
	diag "[$loop] 3 s of constant changes: $a auth reloads meanwhile"
	[ "$a" -ge 1 ] || fail "[$loop] constant changes held back every reload"
	[ "$a" -le 10 ] || fail "[$loop] constant changes gave $a reloads"
	wait_fetch 1 "$pp" "u$i" pw \
		|| fail "[$loop] the last of the constant changes was not loaded"

	kill "$GWP_PID" 2>/dev/null
done

pass

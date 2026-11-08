#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Reload of --auth-file, both watched (--watch-files=1, on every change) and
# on SIGHUP. The file must be re-read from its path: (a) a file replaced by
# rename (write-temp + mv, as editors and install(1) do) takes effect and the
# replaced credentials are revoked; (b) a later in-place rewrite of the
# renamed-in file takes effect too; (c) a file that fails to parse keeps the
# current credentials instead of publishing part of the new file. Exercised
# on every available event loop.

. "$(dirname "$0")/lib.sh"
require curl
require python3

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# fetch <proxy-port> <user> <pass>: succeed iff the proxy let the client in.
fetch()
{
	curl -s --max-time 10 --proxy "socks5h://$2:$3@127.0.0.1:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o /dev/null
}

# wait_login <proxy-port> <user> <pass>: poll until the credentials work.
wait_login()
{
	local i

	for i in $(seq 1 50); do
		fetch "$1" "$2" "$3" && return 0
		sleep 0.1
	done
	return 1
}

# changed: the file was changed; reload it unless the proxy watches it.
changed()
{
	[ "$mode" = watch ] || gwp_hup "$GWP_PID" "$WORK/gwp.$pp.log" 1
}

for loop in epoll io_uring; do
for mode in watch hup; do
	[ "$loop" = io_uring ] && ! have_io_uring && continue

	printf 'alice:pw-a\n' >"$WORK/auth"
	pp="$(pick_port)"
	gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2 \
		--watch-files="$([ "$mode" = watch ] && echo 1 || echo 0)"
	fetch "$pp" alice pw-a || fail "[$loop $mode] initial credentials rejected"

	# (a) Atomic replace by rename.
	printf 'bob:pw-b\n' >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	changed
	wait_login "$pp" bob pw-b \
		|| fail "[$loop $mode] auth file replaced by rename was not reloaded"
	if fetch "$pp" alice pw-a; then
		fail "[$loop $mode] credentials removed by the rename still work"
	fi

	# (b) In-place rewrite of the renamed-in file.
	printf 'carol:pw-c\n' >"$WORK/auth"
	changed
	wait_login "$pp" carol pw-c \
		|| fail "[$loop $mode] in-place rewrite after a rename was not reloaded"

	# (c) A malformed file (a username over 255 bytes) is not applied, not
	# even its valid first line; the proxy says so and keeps the current
	# credentials. A valid file after it is applied.
	{
		printf 'dave:pw-d\n'
		printf '%0300d:x\n' 0
	} >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	changed
	rejected=0
	for _ in $(seq 1 50); do
		if fetch "$pp" dave pw-d; then
			fail "[$loop $mode] a malformed reload was partly applied"
		fi
		if grep -q "Failed to reload authentication file" \
			"$WORK/gwp.$pp.log"; then
			rejected=1
			break
		fi
		sleep 0.1
	done
	[ "$rejected" = 1 ] \
		|| fail "[$loop $mode] a malformed auth file was not reported"
	fetch "$pp" carol pw-c \
		|| fail "[$loop $mode] a malformed reload dropped the current credentials"
	printf 'erin:pw-e\n' >"$WORK/auth.new"
	mv -f "$WORK/auth.new" "$WORK/auth"
	changed
	wait_login "$pp" erin pw-e \
		|| fail "[$loop $mode] reload after a malformed file was not applied"

	kill "$GWP_PID" 2>/dev/null
done
done

pass

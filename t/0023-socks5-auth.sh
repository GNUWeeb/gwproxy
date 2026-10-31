#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 username/password authentication (RFC1929): a proxy started with a
# --auth-file must (a) accept a client that presents the correct
# username/password and relay the payload byte-exact, (b) reject a client
# with a wrong password, and (c) reject a client that presents no
# credentials at all. Exercised on every available event loop. The
# credential file takes comment lines, and refuses a line that is not
# "user:password" instead of reading it as a user with no password.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# RFC1929 credential store: one "username:password" line.
printf 'testuser:s3cr3t\n' >"$WORK/auth"

for loop in epoll io_uring; do
	[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

	pp="$(pick_port)"
	gwp_start "[::1]:$pp" --as-socks5=1 --auth-file="$WORK/auth" \
		--event-loop="$loop" --nr-workers=2

	# (a) Correct credentials: the transfer succeeds and the bytes are intact.
	curl -s --max-time 20 \
		--proxy "socks5h://testuser:s3cr3t@[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/ok.bin" \
		|| fail "[$loop] curl with correct SOCKS5 credentials failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/ok.bin" \
		"[$loop] authenticated SOCKS5 proxy corrupted the payload"

	# (b) Wrong password: curl must fail and must not receive the payload.
	rm -f "$WORK/bad.bin"
	if curl -s --max-time 20 \
		--proxy "socks5h://testuser:wrong@[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/bad.bin"; then
		fail "[$loop] curl with wrong SOCKS5 password unexpectedly succeeded"
	fi
	if cmp -s "$WORK/payload.bin" "$WORK/bad.bin"; then
		fail "[$loop] wrong-password client received the correct payload"
	fi

	# (c) No credentials at all: curl must fail and must not receive the payload.
	rm -f "$WORK/none.bin"
	if curl -s --max-time 20 \
		--proxy "socks5h://[::1]:$pp" \
		"http://127.0.0.1:$hp/payload.bin" -o "$WORK/none.bin"; then
		fail "[$loop] curl with no SOCKS5 credentials unexpectedly succeeded"
	fi
	if cmp -s "$WORK/payload.bin" "$WORK/none.bin"; then
		fail "[$loop] anonymous client received the correct payload"
	fi

	kill "$GWP_PID" 2>/dev/null
done

# (d) Comment lines are not users. A line with no ':' used to become a user
#     with an empty password, comments included, so "# admins" with no
#     password logged in.
printf '# admins\n\ntestuser:s3cr3t\n' >"$WORK/auth.comment"
pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth.comment"
rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --user '# admins' --pass '' \
	"$pp" "$hp")"
[ "$rep" = AUTHFAIL ] || fail "a comment line logged in with no password ($rep)"
rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --user testuser --pass s3cr3t \
	"$pp" "$hp")"
[ "$rep" = REP=0x00 ] || fail "the user after a comment line was refused ($rep)"
kill "$GWP_PID" 2>/dev/null

# (e) A line that is not "user:password" refuses the whole file, rather than
#     creating a user with an empty password.
printf 'testuser:s3cr3t\nnopass\n' >"$WORK/auth.bad"
pp="$(pick_port)"
"$GWPROXY" --bind="127.0.0.1:$pp" --as-socks5=1 --auth-file="$WORK/auth.bad" \
	--acl-allow-all >"$WORK/bad.log" 2>&1 &
bad_pid=$!
_PIDS+=("$bad_pid")
for _ in $(seq 1 50); do
	kill -0 "$bad_pid" 2>/dev/null || break
	sleep 0.1
done
kill -0 "$bad_pid" 2>/dev/null && fail "gwproxy started with a malformed auth file"
grep -q 'line 2' "$WORK/bad.log" \
	|| fail "the malformed auth file line was not reported: $(cat "$WORK/bad.log")"

pass

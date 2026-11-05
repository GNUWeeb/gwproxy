#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream pools ("upstream NAME { server URL; }") and -j UPSTREAM rules in
# the ACL file, as files to load (t/0163 checks where they route): a set with
# pools, spread over an include, loads and reloads and proxying goes on; a
# bad pool is refused at startup, and on reload the rules in force stay; a
# file holding upstream credentials that others can read is warned about,
# and no message shows a password.

. "$(dirname "$0")/lib.sh"
require curl

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

acl_ok="Reloaded ACL file"
acl_bad="Failed to reload ACL file"
pass_word="pw-s3cret"

# code <proxy-port> <target-port>: the HTTP status of a forwarded GET.
code()
{
	curl -s --max-time 20 -x "http://127.0.0.1:$1" \
		"http://127.0.0.1:$2/payload.bin" -o /dev/null -w '%{http_code}'
}

# wait_code <proxy-port> <target-port> <status>: poll until code() says so.
wait_code()
{
	local i c=""

	for i in $(seq 1 150); do
		c="$(code "$1" "$2")"
		[ "$c" = "$3" ] && return 0
		sleep 0.1
	done
	echo "# last status $c" >&2
	return 1
}

# wait_lines <log> <text> <count>: poll until <text> is logged <count> times.
wait_lines()
{
	local i

	for i in $(seq 1 300); do
		[ "$(grep -c "$2" "$1")" -ge "$3" ] && return 0
		sleep 0.1
	done
	return 1
}

# no_password <log>: the password must not appear in <log>.
no_password()
{
	! grep -q "$pass_word" "$1" || fail "a password was logged in $1"
}

# start_bad <name> <acl>: gwproxy must refuse to start with <acl>.
start_bad()
{
	local ec=0

	timeout --foreground 10 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
		--as-http=1 --acl-file="$2" >"$WORK/$1.log" 2>&1 || ec=$?
	{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
		fail "$1: gwproxy accepted the ACL (exit $ec)"
	no_password "$WORK/$1.log"
}

d="$WORK/acl"
mkdir -p "$d"

# Refused at startup, with the file and line at fault.
printf -- '%s\n' '-A OUTPUT -j UPSTREAM --to nowhere' '-P OUTPUT ACCEPT' \
	>"$d/undef.acl"
chmod 600 "$d/undef.acl"
start_bad undef "$d/undef.acl"
grep -q 'undef.acl: line 1: upstream pool nowhere is not defined' \
	"$WORK/undef.log" || fail "an undefined pool was not reported"

printf -- '%s\n' 'upstream mixed {' '	server socks5h://127.0.0.1:1;' \
	"	server socks5://u:$pass_word@127.0.0.1:2;" '}' >"$d/mixed.acl"
chmod 600 "$d/mixed.acl"
start_bad mixed "$d/mixed.acl"
grep -q 'mixed.acl: line 3: upstream pool mixed server 2 (socks5://127.0.0.1:2)' \
	"$WORK/mixed.log" || fail "a pool mixing DNS modes was not reported"

# A good set: a pool in an included file, used from the top file before
# it is defined, a pool in the top file, and DIRECT. The last match wins,
# so the request goes straight to the target.
printf -- '%s\n' 'upstream pool_b {' \
	"	server http://user:$pass_word@127.0.0.1:3128;" \
	'	least_conn;' '}' >"$d/pools.acl"
printf -- '%s\n' '-A OUTPUT -j UPSTREAM --to pool_a' \
	'include pools.acl;' \
	"-A OUTPUT --dports $hp -j UPSTREAM --to-proxy pool_b" \
	'-A OUTPUT --dports 9 -j UPSTREAM --to DIRECT --accept' \
	'-A OUTPUT --dports 9 -j REJECT' \
	"-A OUTPUT --dports $hp -j UPSTREAM --to DIRECT" \
	'upstream pool_a {' '	server socks5h://127.0.0.1:1080;' '}' \
	'-P OUTPUT ACCEPT' >"$d/main.acl"
chmod 600 "$d/main.acl" "$d/pools.acl"

pp="$(pick_port)"
log="$WORK/gwp.$pp.log"
gwp_start "127.0.0.1:$pp" --as-http=1 --nr-workers=1 --acl-file="$d/main.acl"
c="$(code "$pp" "$hp")"
[ "$c" = 200 ] || fail "a request matching -j UPSTREAM got $c"
grep -q 'readable by group or others' "$log" && \
	fail "a private file was warned about"

# Edit the included file: the set reloads, and a pool may change.
n_ok="$(grep -c "$acl_ok" "$log")"
printf -- '%s\n' 'upstream pool_b {' \
	"	server http://user:$pass_word@127.0.0.1:3129;" '}' \
	"-A OUTPUT --dports $hp -j REJECT" >"$d/pools.acl"
gwp_hup "$GWP_PID" "$log" 1
wait_code "$pp" "$hp" 403 || fail "an edit of the pool file was not reloaded"
wait_lines "$log" "$acl_ok" $((n_ok + 1)) || fail "the reload was not logged"

# Others may read it now: warned, once per load, without the password.
n_ok="$(grep -c "$acl_ok" "$log")"
chmod 644 "$d/pools.acl"
printf -- '%s\n' "-A OUTPUT --dports $hp -j ACCEPT" '-P OUTPUT REJECT' \
	'upstream pool_a {' '	server socks5h://127.0.0.1:1080;' '}' \
	'include pools.acl;' >"$d/main.acl"
gwp_hup "$GWP_PID" "$log" 1
wait_code "$pp" "$hp" 200 || fail "an edit of the top file was not reloaded"
wait_lines "$log" "$acl_ok" $((n_ok + 1)) || fail "the reload was not logged"
grep -q 'pools.acl: warning: holds upstream credentials but is readable by group or others' \
	"$log" || fail "a readable file with credentials was not warned about"
grep -q 'main.acl: warning' "$log" && \
	fail "a file without credentials was warned about"

# A bad pool on reload: refused, the rules in force stay.
n_bad="$(grep -c "$acl_bad" "$log")"
printf -- '%s\n' 'upstream pool_b {' \
	"	server https://user:$pass_word@127.0.0.1:3129;" '}' >"$d/pools.acl"
gwp_hup "$GWP_PID" "$log" 1
wait_lines "$log" "$acl_bad" $((n_bad + 1)) || \
	fail "a pool with an https server did not fail the reload"
grep -q 'pools.acl: line 2: upstream pool pool_b server 1 (https://127.0.0.1:3129): https:// is not supported in a pool yet' \
	"$log" || fail "the https server was not reported"
c="$(code "$pp" "$hp")"
[ "$c" = 200 ] || fail "a failed reload dropped the rules ($c)"
c="$(code "$pp" 9)"
[ "$c" = 403 ] || fail "a failed reload dropped the policy ($c)"

n_bad="$(grep -c "$acl_bad" "$log")"
printf -- '%s\n' 'upstream pool_b {' '	server http://127.0.0.1:3129;' \
	>"$d/pools.acl"
gwp_hup "$GWP_PID" "$log" 1
wait_lines "$log" "$acl_bad" $((n_bad + 1)) || \
	fail "an unclosed pool did not fail the reload"
grep -q 'pools.acl: line 1: upstream pool pool_b is not closed' "$log" || \
	fail "the unclosed pool was not reported"
c="$(code "$pp" "$hp")"
[ "$c" = 200 ] || fail "a failed reload dropped the rules ($c)"

no_password "$log"
pass

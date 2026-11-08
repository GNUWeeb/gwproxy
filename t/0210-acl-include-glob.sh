#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Patterns in "include": every file a pattern matches is included, in the
# byte-wise order of the paths, whatever order the directories list them in,
# with wildcards at several levels; a SIGHUP reload matches the pattern
# again. A pattern that matches nothing, or a match that is not a regular
# file, refuses the set at startup, naming the file, line and pattern.

. "$(dirname "$0")/lib.sh"
require curl

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 1000
start_httpd "$hp" "$WORK" "1.1"

# code <proxy-port> <target-port>: the HTTP status of a forwarded GET.
code()
{
	curl -s --max-time 20 -x "http://127.0.0.1:$1" \
		"http://127.0.0.1:$2/payload.bin" -o /dev/null -w '%{http_code}'
}

# refused <name> <what>: gwproxy must refuse $WORK/<name>/main.acl at
# startup; its output is left in $WORK/<name>.log.
refused()
{
	local ec=0

	timeout --foreground 10 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
		--as-http=1 --acl-file="$WORK/$1/main.acl" >"$WORK/$1.log" 2>&1 ||
		ec=$?
	{ [ "$ec" -ne 0 ] && [ "$ec" -ne 124 ]; } || \
		fail "gwproxy accepted $2 (exit $ec)"
}

d="$WORK/set"
mkdir -p "$d/rules.d/20-b/x" "$d/rules.d/10-a/x" "$d/rules.d/.h/x"
# The later one first: the order must come from the names.
printf -- '%s\n' "-A OUTPUT --dports $hp -j ACCEPT" >"$d/rules.d/20-b/x/r.acl"
printf -- '%s\n' "-A OUTPUT --dports $hp -j REJECT" >"$d/rules.d/10-a/x/r.acl"
printf -- '%s\n' '-A OUTPUT -j BOGUS' >"$d/rules.d/.h/x/r.acl"
printf -- '%s\n' '-A OUTPUT -j BOGUS' >"$d/rules.d/10-a/x/r.txt"
printf -- '%s\n' 'include rules.d/*/?/*.acl;' '-P OUTPUT ACCEPT' \
	>"$d/main.acl"

pp="$(pick_port)"
log="$WORK/gwp.$pp.log"
gwp_start "127.0.0.1:$pp" --as-http=1 --nr-workers=1 --acl-file="$d/main.acl"
c="$(code "$pp" "$hp")"
[ "$c" = 403 ] || fail "10-a's rule did not come first ($c)"

# Renamed past 20-b, the same rule comes second, after its ACCEPT.
mv "$d/rules.d/10-a" "$d/rules.d/30-a"
gwp_hup "$GWP_PID" "$log" 1
grep -q 'Reloaded ACL file' "$log" || fail "the reload failed"
c="$(code "$pp" "$hp")"
[ "$c" = 200 ] || fail "the reload did not follow the new order ($c)"

# A pattern that matches nothing fails the reload and keeps the rules.
printf -- '%s\n' 'include rules.d/*/?/*.acl;' 'include none.d/*.acl;' \
	'-P OUTPUT REJECT' >"$d/main.acl"
gwp_hup "$GWP_PID" "$log" 1
grep -q "main.acl: line 2: include none.d/\*.acl: no file matches" "$log" || \
	fail "the empty pattern was not reported with its file and line"
c="$(code "$pp" "$hp")"
[ "$c" = 200 ] || fail "a failed reload dropped the rules ($c)"

# At startup, the same refuses the set.
mkdir -p "$WORK/none"
printf -- '%s\n' '-P OUTPUT ACCEPT' '' 'include conf.d/*.acl;' \
	>"$WORK/none/main.acl"
refused none "an include pattern that matches nothing"
grep -q "main.acl: line 3: include conf.d/\*.acl: no file matches" \
	"$WORK/none.log" || fail "the startup error did not name the pattern"

# A directory among the matches refuses the set.
mkdir -p "$WORK/dir/conf.d/b.acl"
printf -- '%s\n' '-A OUTPUT -j ACCEPT' >"$WORK/dir/conf.d/a.acl"
printf -- '%s\n' 'include conf.d/*.acl;' >"$WORK/dir/main.acl"
refused dir "an include pattern that matches a directory"
grep -q 'conf.d/b.acl: not a regular file' "$WORK/dir.log" || \
	fail "the directory match was not reported"

pass

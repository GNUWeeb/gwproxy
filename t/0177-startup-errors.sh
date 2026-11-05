#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Startup checks and their exit status.
#
#  - --bind-source takes a port of decimal digits only, 0 to 65535. Trailing
#    characters, an empty port or one out of range are refused with EINVAL
#    (22) and a message naming the option; so are a sign and leading blanks,
#    which strtoul() took: "+80" and " 80" passed for 80, and a "-" value
#    wrapped around, "-18446744073709551535" giving port 81.

. "$(dirname "$0")/lib.sh"

closed_port
tp="$CLOSED_PORT"

# start_bad <what> <exit-status> <message> <args...>: gwproxy must refuse to
# start with <args>, exit with <exit-status> and log <message> (fixed string).
start_bad()
{
	local what="$1" want="$2" msg="$3" pp ec out
	shift 3

	pp="$(pick_port)"
	out="$WORK/bad.$pp.log"
	timeout 20 "$GWPROXY" --bind="127.0.0.1:$pp" --target="127.0.0.1:$tp" \
		--acl-allow-all --log-level=3 "$@" >"$out" 2>&1
	ec=$?
	[ "$ec" = "$want" ] || {
		sed 's/^/# gwp: /' "$out" >&2
		fail "$what: exit status $ec, want $want"
	}
	grep -qF -- "$msg" "$out" || {
		sed 's/^/# gwp: /' "$out" >&2
		fail "$what: no '$msg' in the log"
	}
}

for v in '127.0.0.1:80x' '127.0.0.1:65536' '127.0.0.1:' '127.0.0.1:+80' \
	 '127.0.0.1: 80' '[::1]:-18446744073709551535' '[::1]:+0' \
	 '[::1]:99999999999999999999'; do
	start_bad "--bind-source=$v" 22 "Invalid --bind-source value '$v'" \
		--bind-source="$v"
done

# A good one still starts.
pp="$(pick_port)"
gwp_start "127.0.0.1:$pp" --target="127.0.0.1:$tp" --bind-source=127.0.0.1:0
grep -q 'bind to source 127.0.0.1' "$WORK/gwp.$pp.log" \
	|| fail "--bind-source=127.0.0.1:0 was not taken"
kill "$GWP_PID"

pass

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --pid-file and --log-file must not be redirected through a symlink: run as
# root with the file in a directory someone else can write to, fopen() let
# that someone have the proxy truncate (PID file) or append to (log file)
# any file at all. A symlinked PID file is left alone and the proxy runs
# on; a symlinked log file stops it from starting. A real PID file holds
# our PID, is locked so a second instance pointed at it leaves it alone,
# and is removed when the proxy exits.

. "$(dirname "$0")/lib.sh"

printf 'keep\n' >"$WORK/victim"

# (1) A symlinked PID file: the link target is not touched.
ln -s "$WORK/victim" "$WORK/pid.lnk"
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --pid-file="$WORK/pid.lnk"
[ "$(cat "$WORK/victim")" = keep ] \
	|| fail "the PID file's symlink target was overwritten: $(cat "$WORK/victim")"
kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null

# (2) A symlinked log file: no start, and the target is not touched.
ln -s "$WORK/victim" "$WORK/log.lnk"
p="$(pick_port)"
"$GWPROXY" --bind="127.0.0.1:$p" --as-socks5=1 --acl-allow-all \
	--log-file="$WORK/log.lnk" >"$WORK/lnk.out" 2>&1 &
lp=$!
_PIDS+=("$lp")
for _ in $(seq 1 50); do
	kill -0 "$lp" 2>/dev/null || break
	sleep 0.1
done
kill -0 "$lp" 2>/dev/null && fail "gwproxy started with a symlinked log file"
[ "$(cat "$WORK/victim")" = keep ] \
	|| fail "the log file's symlink target was written to: $(cat "$WORK/victim")"

# (3) A real PID file: our PID, kept from a second instance, gone at exit.
p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --pid-file="$WORK/gwp.pid"
first="$GWP_PID"
[ "$(cat "$WORK/gwp.pid")" = "$first" ] \
	|| fail "PID file holds '$(cat "$WORK/gwp.pid")', want $first"

p2="$(pick_port)"
gwp_start "127.0.0.1:$p2" --as-socks5=1 --pid-file="$WORK/gwp.pid"
[ "$(cat "$WORK/gwp.pid")" = "$first" ] \
	|| fail "a second instance overwrote the PID file: $(cat "$WORK/gwp.pid")"
kill "$GWP_PID" 2>/dev/null
wait "$GWP_PID" 2>/dev/null

kill "$first" 2>/dev/null
wait "$first" 2>/dev/null
[ ! -e "$WORK/gwp.pid" ] || fail "the PID file was left behind at exit"

pass

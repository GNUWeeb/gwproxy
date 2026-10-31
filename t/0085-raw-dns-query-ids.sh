#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# --raw-dns queries must be hard to answer for anyone but the server
# (RFC 5452): every query goes out with a random transaction ID from a
# random source port. Transaction IDs used to be the resolver's slot
# numbers, handed out from 0, and every query of a worker left from the
# same long-lived socket, so an off-path attacker had next to nothing to
# guess. Make several lookups through a DNS server that logs what it sees.
#
# epoll only: gwproxy refuses --raw-dns together with --event-loop=io_uring.

. "$(dirname "$0")/lib.sh"
require python3
grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null || \
	skip "gwproxy built without the raw DNS resolver (--use-new-dns-resolver)"

hp="$(pick_port)"
make_payload "$WORK/payload.bin" 100
start_httpd "$hp" "$WORK" "1.1"

dp="$(pick_port)"
qlog="$WORK/queries.log"
: >"$qlog"
python3 "$SERVERS_DIR/dns_malformed.py" good "$dp" "$WORK/nr_queries" \
	"$qlog" 2>/dev/null &
_PIDS+=("$!")
sleep 0.4

p="$(pick_port)"
gwp_start "127.0.0.1:$p" --as-socks5=1 --raw-dns=1 \
	--dns-server="127.0.0.1:$dp" --nr-workers=1

n=8
for i in $(seq 1 "$n"); do
	rep="$(python3 "$SERVERS_DIR/socks5_probe.py" --host 127.0.0.1 \
		--atyp domain --dst "q$i.example" "$p" "$hp")"
	[ "$rep" = "REP=0x00" ] || fail "lookup $i did not resolve (got '$rep')"
done

[ "$(wc -l <"$qlog")" -eq "$n" ] \
	|| fail "the server saw $(wc -l <"$qlog") queries (want $n)"

ports="$(awk '{print $2}' "$qlog" | sort -u | wc -l)"
[ "$ports" -ge $((n / 2)) ] \
	|| fail "$n queries came from only $ports source port(s): $(cat "$qlog")"

# Random 16-bit IDs: all 8 below 1024 has odds of 2^-48. Slot numbers
# never get there with one lookup at a time.
awk '$1 >= 1024 { big = 1 } END { exit !big }' "$qlog" \
	|| fail "transaction IDs look sequential: $(cat "$qlog")"
[ "$(awk '{print $1}' "$qlog" | sort -u | wc -l)" -eq "$n" ] \
	|| fail "transaction IDs repeat: $(cat "$qlog")"

pass

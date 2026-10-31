#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Upstream SOCKS5 chaining (--upstream-proxy): a front SOCKS5 proxy routes
# every outgoing connection through a second (upstream) SOCKS5 proxy. Verify a
# payload survives the whole chain byte-for-byte for both URL schemes --
# socks5:// (the front resolves the target) and socks5h:// (the upstream
# resolves it) -- across every available front-end event loop.
#
# The destination must be a NAME for the two schemes to differ at all: with an
# IP literal there is nothing to resolve, both schemes emit the same ATYP=1
# request, and the socks5h path is never exercised. A recording upstream then
# pins the actual distinction, since both schemes otherwise produce an equally
# working transfer.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require_opt "--upstream-proxy"

hp="$(pick_port)"
up="$(pick_port)"
make_payload "$WORK/payload.bin" 200000
start_httpd "$hp" "$WORK" "1.1"

# A single upstream SOCKS5 proxy shared by every front-end below. Killed
# automatically on exit; GWP_PID is reassigned to each front-end as it starts.
gwp_start "[::1]:$up" --as-socks5=1 --event-loop=epoll --nr-workers=2

for scheme in socks5 socks5h; do
	for loop in epoll io_uring; do
		[ "$loop" = io_uring ] && ! grep -q CONFIG_IO_URING "$ROOT/config.h" 2>/dev/null && continue

		fp="$(pick_port)"
		gwp_start "[::1]:$fp" --as-socks5=1 --event-loop="$loop" \
			--nr-workers=2 --upstream-proxy="$scheme://[::1]:$up"
		curl -s --max-time 20 --proxy "socks5h://[::1]:$fp" \
			"http://localhost:$hp/payload.bin" -o "$WORK/out.bin" \
			|| fail "[$scheme/$loop] curl through SOCKS5 chain failed"
		assert_files_equal "$WORK/payload.bin" "$WORK/out.bin" \
			"[$scheme/$loop] SOCKS5 chain corrupted the payload"
		kill "$GWP_PID" 2>/dev/null
	done
done

# What actually went upstream. socks5:// must resolve the name locally and send
# an address (ATYP 1 or 4); socks5h:// must forward the name itself (ATYP 3).
# Without this the two schemes are indistinguishable: both transfer correctly
# whichever ATYP is emitted.
for scheme in socks5 socks5h; do
	rp="$(pick_port)"
	rlog="$WORK/rec.$scheme.log"
	: >"$rlog"
	python3 "$SERVERS_DIR/recording_proxy.py" socks5 127.0.0.1 "$rp" "$rlog" \
		>"$WORK/rec.$scheme.err" 2>&1 &
	_PIDS+=("$!")
	wait_listen "$rp" "$!" || fail "recording upstream did not listen"

	fp="$(pick_port)"
	gwp_start "127.0.0.1:$fp" --as-socks5=1 --nr-workers=2 \
		--upstream-proxy="$scheme://127.0.0.1:$rp"
	curl -s --max-time 20 --proxy "socks5h://127.0.0.1:$fp" \
		"http://localhost:$hp/payload.bin" -o "$WORK/rec.out" \
		|| fail "[$scheme] curl through the recording upstream failed"
	assert_files_equal "$WORK/payload.bin" "$WORK/rec.out" \
		"[$scheme] recording upstream chain corrupted the payload"
	kill "$GWP_PID" 2>/dev/null

	got="$(head -1 "$rlog")"
	case "$scheme" in
	socks5)
		case "$got" in
		"atyp=1 "*|"atyp=4 "*) ;;
		*) fail "socks5:// should resolve locally, upstream saw '$got'" ;;
		esac ;;
	socks5h)
		[ "$got" = "atyp=3 addr=localhost port=$hp" ] \
			|| fail "socks5h:// should forward the name, upstream saw '$got'" ;;
	esac
done

# The port of an upstream is optional (1080 for socks5://), also for a
# bracketed IPv6 literal. gwproxy validates the URL at startup, so a rejected
# one never gets as far as listening. Nothing is dialled here: port 1080 is
# not ours to use.
fp="$(pick_port)"
gwp_start "127.0.0.1:$fp" --as-socks5=1 --upstream-proxy="socks5://[::1]"
kill "$GWP_PID" 2>/dev/null

pass

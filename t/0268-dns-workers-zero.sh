#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# -W/--nr-dns-workers=0 where the system resolver is needed.
#
# SOCKS5 and HTTP look hostnames up on resolver threads, and -W 0 leaves none
# to run a lookup on. The option took 0 all the same, and the proxy then
# failed to start with only "Failed to initialize DNS context: Invalid
# argument". It is now refused while the options are read, with a message
# naming -W. Where no resolver thread is started -- plain forwarding, and
# --raw-dns -- 0 is still taken and the proxy starts.

. "$(dirname "$0")/lib.sh"

EINVAL=22

# run_opt <args...>: run a proxy with <args> for at most 3 s; RC gets its exit
# status (124: it started and kept running) and $WORK/opt.log its output.
run_opt()
{
	RC=0
	timeout --foreground 3 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" \
		--nr-workers=1 "$@" >"$WORK/opt.log" 2>&1 || RC=$?
}

# bad <args...>: refused with EINVAL and a message naming -W.
bad()
{
	run_opt "$@"
	[ "$RC" = "$EINVAL" ] || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "$*: exit status $RC, want $EINVAL"
	}
	grep -qF -- "Error: -W/--nr-dns-workers must be at least 1" \
		"$WORK/opt.log" || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "$*: no message naming -W"
	}
}

# good <args...>: the proxy starts and keeps running with <args>.
good()
{
	run_opt "$@"
	[ "$RC" = 124 ] || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "$*: exit status $RC, want it to start"
	}
}

bad --as-socks5=1 --nr-dns-workers=0
bad --as-http=1 -W 0
bad --as-socks5=1 --as-http=1 --nr-dns-workers=0

good --as-socks5=1 --nr-dns-workers=1
good --target=127.0.0.1:9 --nr-dns-workers=0

if grep -q 'CONFIG_NEW_DNS_RESOLVER' "$ROOT/config.h" 2>/dev/null; then
	good --as-socks5=1 --raw-dns=1 --dns-server=127.0.0.1:53 \
		--nr-dns-workers=0
else
	diag "built without the raw DNS resolver: --raw-dns -W 0 not checked"
fi

pass

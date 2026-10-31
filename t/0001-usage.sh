#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Basic CLI behaviour: --help, unknown options, and required-argument checks.

. "$(dirname "$0")/lib.sh"

# Exit status for a rejected configuration (-EINVAL out of parse_opts()).
EINVAL=22

# expect_reject <what> <args...>: gwproxy must refuse this configuration and
# exit EINVAL. Testing merely for "non-zero" is not enough -- `timeout` reports
# 124 while the process is still alive, so a configuration that was ACCEPTED
# and is happily serving traffic scores exactly like a rejected one, and so
# would a crash. Both are called out separately here.
expect_reject()
{
	local what="$1"; shift
	local rc=0

	timeout 5 "$GWPROXY" "$@" >/dev/null 2>&1 || rc=$?
	case "$rc" in
	"$EINVAL")
		return 0 ;;
	124)
		fail "$what: gwproxy started and kept running (input accepted)" ;;
	0)
		fail "$what: gwproxy exited successfully (input accepted)" ;;
	esac
	fail "$what: gwproxy exited $rc, want $EINVAL (crash or wrong error?)"
}

# --help succeeds and prints a usage line.
out="$("$GWPROXY" --help 2>&1)" || fail "--help exited non-zero"
printf '%s\n' "$out" | grep -q '^Usage:' || fail "--help did not print a Usage line"

# An unknown option must be rejected. The remaining arguments form a valid,
# runnable configuration so the unknown option is the only reason to fail --
# otherwise this check would also pass on the missing-target guard below and
# would never isolate unknown-option handling at all.
expect_reject "unknown option" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
	--definitely-not-an-option

# Without --target and without a proxy mode there is nothing to do; reject it.
expect_reject "missing --target and proxy mode" --bind="127.0.0.1:$(pick_port)"

# Numeric arguments are parsed whole and range-checked. atoi() used to take
# "2x" for 2, "yes" for 0 and wrap out-of-range values, so a typo started a
# proxy with settings nobody asked for. The rest of each command line is a
# valid, runnable configuration, so the bad number is the only reason to fail.
for bad in --nr-workers=2x --nr-workers=1025 --nr-dns-workers=-1 \
	   --protocol-timeout=99999999999 --connect-timeout= \
	   --tcp-nodelay=yes --idle-timeout=10s --mark=-1 \
	   --mark=0x100000000 --client-buf-size=64k \
	   --max-conns-per-ip=-1 --max-conns-per-ip=3x; do
	expect_reject "bad numeric argument $bad" --as-socks5=1 \
		--bind="127.0.0.1:$(pick_port)" --nr-workers=1 "$bad"
done

# Without CAP_NET_ADMIN the --mark probe fails at startup, and the error must
# name the mark as given: one above INT_MAX used to be printed as negative.
if [ "$(id -u)" != 0 ]; then
	out="$(timeout 5 "$GWPROXY" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
		--nr-workers=1 --mark=0xffffffff 2>&1)" && \
		fail "--mark without CAP_NET_ADMIN: gwproxy exited successfully"
	printf '%s\n' "$out" | grep -q -- '--mark=4294967295 ' || \
		fail "--mark error does not show 4294967295: $out"
fi

# A malformed --upstream-proxy URL must be rejected at startup. Use URLs that
# are structurally wrong (unsupported scheme, no scheme at all) rather than one
# whose host merely fails to resolve: on a host with a wildcard search domain
# any name resolves, which would quietly turn such a check into a no-op.
if "$GWPROXY" --help 2>&1 | grep -q -- "--upstream-proxy"; then
	expect_reject "--upstream-proxy with an unsupported scheme" \
		--as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
		--upstream-proxy="ftp://127.0.0.1:1080"
	expect_reject "--upstream-proxy with no scheme" \
		--as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
		--upstream-proxy="not-a-url"
fi

pass

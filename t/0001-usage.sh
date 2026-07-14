#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Basic CLI behaviour: --help, unknown options, and required-argument checks.

. "$(dirname "$0")/lib.sh"

# --help succeeds and prints a usage line.
out="$("$GWPROXY" --help 2>&1)" || fail "--help exited non-zero"
printf '%s\n' "$out" | grep -q '^Usage:' || fail "--help did not print a Usage line"

# An unknown option must be rejected.
if timeout 5 "$GWPROXY" --definitely-not-an-option >/dev/null 2>&1; then
	fail "an unknown option was accepted"
fi

# Without --target and without a proxy mode there is nothing to do; reject it.
if timeout 5 "$GWPROXY" --bind="127.0.0.1:$(pick_port)" >/dev/null 2>&1; then
	fail "missing --target / proxy mode was accepted"
fi

# A malformed --upstream-socks5 URL must be rejected at startup.
if require_opt "--upstream-socks5" 2>/dev/null; then :; fi
if "$GWPROXY" --help 2>&1 | grep -q -- "--upstream-socks5"; then
	if timeout 5 "$GWPROXY" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
			--upstream-socks5="http://nope:1080" >/dev/null 2>&1; then
		fail "malformed --upstream-socks5 URL was accepted"
	fi
fi

pass

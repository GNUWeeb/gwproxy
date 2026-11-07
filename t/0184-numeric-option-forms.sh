#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The forms a numeric command line option takes.
#
#  - A number is decimal digits, after a "-" where the option takes negative
#    values. strtoll() also took a "+" and leading blanks: "--nr-workers=+4"
#    and "--nr-workers= 4" ran four workers. Each such value is refused with
#    EINVAL (22) and a message naming the option and the value.
#  - --mark alone also takes 0x hexadecimal. It was read in base 0, so
#    "--mark=010" set the mark 8; a decimal mark with a leading 0 is now
#    refused, and other options keep reading a leading 0 as decimal.

. "$(dirname "$0")/lib.sh"

EINVAL=22

# run_opt <args...>: run a proxy that would otherwise start with <args> for at
# most 3 s; RC gets its exit status (124: it started and kept running) and
# $WORK/opt.log its output.
run_opt()
{
	RC=0
	timeout --foreground 3 "$GWPROXY" --as-socks5=1 \
		--bind="127.0.0.1:$(pick_port)" --nr-workers=1 "$@" \
		>"$WORK/opt.log" 2>&1 || RC=$?
}

# bad <option> <value> [<extra message>]: --<option>=<value> is refused with
# EINVAL and a message naming the option and the value as given.
bad()
{
	local opt="$1" val="$2" extra="${3:-}"

	run_opt "--$opt=$val"
	[ "$RC" = "$EINVAL" ] || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "--$opt='$val': exit status $RC, want $EINVAL"
	}
	grep -qF -- "Error: --$opt: '$val' is not a" "$WORK/opt.log" || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "--$opt='$val': no message naming the option and value"
	}
	[ -z "$extra" ] || grep -qF -- "$extra" "$WORK/opt.log" || {
		sed 's/^/# gwp: /' "$WORK/opt.log" >&2
		fail "--$opt='$val': no '$extra' in the message"
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

tab="$(printf '\t')"

# A sign or blanks around a decimal value, on unsigned and signed options and
# on a boolean one.
for v in +4 " 4" "4 " "$tab"4 "+0" "0x4" "4x"; do
	bad nr-workers "$v"
done
bad nr-dns-workers +0
for v in +5 " -1" "--1" "- 1" "-" "-0x1" "0x10"; do
	bad connect-timeout "$v"
done
bad idle-timeout "+60"
bad tcp-nodelay "+1"
bad tcp-nodelay " 1"
bad max-conns-per-ip "+3"
bad nr-workers -1

# --mark: decimal without a leading 0, or 0x hexadecimal; nothing else.
for v in 010 00 0777 08; do
	bad mark "$v" "no leading 0: it once meant octal"
done
for v in +1 " 1" -0 0x 0x+1 0x-1 "0x 1" 0x0x1 0b1 0o7 0xg 1a 0x100000000 \
	 4294967296 18446744073709551616; do
	bad mark "$v"
done

# The short option goes through the same parser.
run_opt -w +4
[ "$RC" = "$EINVAL" ] && grep -qF -- "Error: --nr-workers: '+4'" "$WORK/opt.log" \
	|| fail "-w +4: exit status $RC, want $EINVAL with a message"

# What is taken: negative values where the option allows them, and a leading 0
# in a decimal-only option, which never meant octal there.
good --connect-timeout=-1
good --connect-timeout=-0
good --idle-timeout=-2147483648
good --nr-workers=01
good --dns-cache-secs=007
good --tcp-nodelay=01
good --mark=0

# Without CAP_NET_ADMIN the --mark probe fails at startup and names the mark as
# read: 0x10 and 0X10 are 16, and 16 stays 16. As root the probe succeeds and
# the value cannot be seen this way, so only that it starts is checked.
for v in 0x10 0X10 0x00000010 16; do
	if [ "$(id -u)" = 0 ]; then
		good --mark="$v"
	else
		run_opt --mark="$v"
		grep -qF -- "--mark=16 " "$WORK/opt.log" || {
			sed 's/^/# gwp: /' "$WORK/opt.log" >&2
			fail "--mark=$v was not read as 16 (exit $RC)"
		}
	fi
done

pass

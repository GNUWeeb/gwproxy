#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# The upstream proxy password must not leak to other users of the host:
#
#   (1) an --upstream-proxy URL that fails to parse is named in the error
#       message, but with its password masked;
#   (2) --upstream-proxy-auth-file supplies the credentials from a file
#       instead of the URL (and so argv): the right ones relay through an
#       upstream SOCKS5 proxy that demands them, a password holding '@' and
#       ':' included, the wrong ones do not; a URL with credentials of its
#       own, a missing file, a malformed file, and the option without
#       --upstream-proxy are all refused at startup;
#   (3) credentials given in the URL still work, but the password is
#       overwritten in /proc/<pid>/cmdline once gwproxy has started.

. "$(dirname "$0")/lib.sh"
require curl
require python3
require cmp
require_opt "--upstream-proxy"
require_opt "--upstream-proxy-auth-file"

# Exit statuses for a rejected configuration and a missing file.
EINVAL=22
ENOENT=2

SECRET="s3cr3t-Upstream-Pw"

# (1) A URL with credentials but an unresolvable host (the space makes it
# invalid on any resolver) is rejected at startup; the message names the user
# and the host, and must not carry the password.
out="$(timeout 5 "$GWPROXY" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
	--upstream-proxy="http://opuser:$SECRET@bad host:1" 2>&1)"
case $? in
0) fail "a malformed --upstream-proxy URL was accepted" ;;
124) fail "a malformed --upstream-proxy URL went to the resolver and timed out" ;;
esac
printf '%s\n' "$out" | grep -q "Invalid --upstream-proxy value 'http://opuser:\*\*\*@bad host:1'" || \
	fail "no masked upstream URL in the error: $out"
printf '%s\n' "$out" | grep -qF "$SECRET" && \
	fail "the upstream password was logged: $out"

# (2) Credentials from a file. The upstream SOCKS5 proxy requires them.
hp="$(pick_port)"
up="$(pick_port)"
make_payload "$WORK/payload.bin" 100000
start_httpd "$hp" "$WORK" "1.1"
printf 'up:%s\n' "p@ss:$SECRET" >"$WORK/upauth"
gwp_start "[::1]:$up" --as-socks5=1 --auth-file="$WORK/upauth" \
	--event-loop=epoll --nr-workers=1

# fetch <front port> <out file>: one GET through the front proxy.
fetch()
{
	curl -s --max-time 20 --proxy "socks5h://[::1]:$1" \
		"http://127.0.0.1:$hp/payload.bin" -o "$2"
}

printf 'up:%s\r\n' "p@ss:$SECRET" >"$WORK/good"
chmod 600 "$WORK/good"
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=1 \
	--upstream-proxy="socks5://[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/good"
fetch "$fp" "$WORK/ok.bin" || fail "fetch with credentials from a file failed"
assert_files_equal "$WORK/payload.bin" "$WORK/ok.bin" \
	"the chain with file credentials corrupted the payload"
kill "$GWP_PID" 2>/dev/null

printf 'up:wrong\n' >"$WORK/bad"
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=1 \
	--upstream-proxy="socks5://[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/bad"
rm -f "$WORK/bad.bin"
fetch "$fp" "$WORK/bad.bin" && \
	fail "fetch with a wrong password from a file succeeded"
cmp -s "$WORK/payload.bin" "$WORK/bad.bin" && \
	fail "the wrong file credentials still got the payload"
kill "$GWP_PID" 2>/dev/null

# (3) Credentials in the URL: the chain works, and the password, which
# contains '@' and ':' here, no longer shows in the process's command line.
fp="$(pick_port)"
gwp_start "[::1]:$fp" --as-socks5=1 --event-loop=epoll --nr-workers=1 \
	--upstream-proxy="socks5://up:p@ss:$SECRET@[::1]:$up"
tr '\0' ' ' <"/proc/$GWP_PID/cmdline" >"$WORK/cmdline"
grep -qF "$SECRET" "$WORK/cmdline" && \
	fail "the upstream password is visible in /proc/<pid>/cmdline: $(cat "$WORK/cmdline")"
grep -qF -- "--upstream-proxy=socks5://up:***@[::1]:$up" "$WORK/cmdline" || \
	fail "the masked upstream URL is missing from the command line: $(cat "$WORK/cmdline")"
fetch "$fp" "$WORK/url.bin" || fail "fetch with credentials in the URL failed"
assert_files_equal "$WORK/payload.bin" "$WORK/url.bin" \
	"the chain with URL credentials corrupted the payload"
kill "$GWP_PID" 2>/dev/null

# expect_reject <what> <errno> <args...>: gwproxy refuses to start, exiting
# with <errno> (not 124, which is timeout's for a proxy that kept running),
# and without printing the password.
expect_reject()
{
	local what="$1" want="$2"; shift 2
	local rc=0

	timeout 5 "$GWPROXY" --as-socks5=1 --bind="127.0.0.1:$(pick_port)" \
		--nr-workers=1 "$@" >"$WORK/reject.out" 2>&1 || rc=$?
	[ "$rc" = "$want" ] || {
		sed 's/^/# /' "$WORK/reject.out" >&2
		fail "$what: exit status $rc, want $want"
	}
	grep -qF "$SECRET" "$WORK/reject.out" && \
		fail "$what: the password was printed"
	return 0
}

expect_reject "credentials in both the URL and the file" "$EINVAL" \
	--upstream-proxy="socks5://up:x@[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/good"
expect_reject "a missing credentials file" "$ENOENT" \
	--upstream-proxy="socks5://[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/does-not-exist"
: >"$WORK/empty"
expect_reject "an empty credentials file" "$EINVAL" \
	--upstream-proxy="socks5://[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/empty"
python3 -c 'print("u:" + "p" * 256)' >"$WORK/long"
expect_reject "a password over 255 bytes" "$EINVAL" \
	--upstream-proxy="socks5://[::1]:$up" \
	--upstream-proxy-auth-file="$WORK/long"
expect_reject "the credentials file without --upstream-proxy" "$EINVAL" \
	--upstream-proxy-auth-file="$WORK/good"

pass

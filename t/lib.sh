# SPDX-License-Identifier: GPL-2.0-only
#
# Common helpers for gwproxy integration tests.
#
# This file is meant to be sourced by t/*.sh, not executed directly. Each
# test script exits 0 on success, 77 to skip (e.g. a feature is not compiled
# in or a tool is missing), or any other code on failure. All background
# processes and temporary files are cleaned up automatically on exit.

set -u

T_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$T_DIR/.." && pwd)"
GWPROXY="${GWPROXY:-$ROOT/gwproxy}"
SERVERS_DIR="$T_DIR/servers"

SKIP_CODE=77

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gwptest.XXXXXX")"
declare -a _PIDS=()

_cleanup()
{
	local pid
	for pid in "${_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
	for pid in "${_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
	done
	rm -rf "$WORK"
}
trap _cleanup EXIT INT TERM

diag() { echo "# $*" >&2; }
skip() { echo "SKIP: $*"; exit "$SKIP_CODE"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS${1:+: $1}"; exit 0; }

# require <tool>: skip the test if the tool is missing.
require()
{
	command -v "$1" >/dev/null 2>&1 || skip "missing tool: $1"
}

# Skip unless gwproxy was built with io_uring support.
require_io_uring()
{
	grep -q 'CONFIG_IO_URING' "$ROOT/config.h" 2>/dev/null || \
		skip "gwproxy built without io_uring"
}

# Skip unless gwproxy advertises a given long option in --help.
require_opt()
{
	"$GWPROXY" --help 2>&1 | grep -q -- "$1" || \
		skip "gwproxy has no $1 option"
}

# Print a free TCP port that is bindable on the IPv4/IPv6 dual stack, so it is
# also free for a plain 127.0.0.1 or [::1] bind.
pick_port()
{
	python3 - <<-'PY'
	import socket
	s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
	s.bind(("", 0))
	print(s.getsockname()[1])
	s.close()
	PY
}

# wait_listen <port> [pid]: wait until something is listening on <port>, or
# until <pid> (if given) exits. Returns 0 on success, 1 on timeout/exit.
wait_listen()
{
	local port="$1" pid="${2:-}" i
	for i in $(seq 1 100); do
		if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
			return 1
		fi
		if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

# gwp_start <bind> [args...]: start gwproxy bound to <bind> (e.g. "[::1]:1080"
# or "127.0.0.1:1080") and wait until it is listening. Sets GWP_PID. The log
# is captured under $WORK and dumped on failure.
gwp_start()
{
	local bind="$1"; shift
	local port="${bind##*:}"
	local log="$WORK/gwp.$port.log"

	"$GWPROXY" --bind="$bind" --log-level=3 "$@" >"$log" 2>&1 &
	local pid=$!
	_PIDS+=("$pid")
	if ! wait_listen "$port" "$pid"; then
		sed 's/^/# gwp: /' "$log" >&2
		fail "gwproxy did not listen on $bind (args: $*)"
	fi
	GWP_PID="$pid"
}

# start_httpd <port> <docroot> [http_version]: start the dual-stack test HTTP
# server serving <docroot>. It is reachable via 127.0.0.1, [::1] or localhost.
# http_version is "1.0" (closes after each response) or "1.1" (keep-alive).
# Default "1.1".
start_httpd()
{
	local port="$1" root="$2" ver="${3:-1.1}"
	python3 "$SERVERS_DIR/httpd.py" "$port" "$root" "$ver" \
		>"$WORK/httpd.$port.log" 2>&1 &
	local pid=$!
	_PIDS+=("$pid")
	if ! wait_listen "$port" "$pid"; then
		sed 's/^/# httpd: /' "$WORK/httpd.$port.log" >&2
		fail "test HTTP server did not start on port $port"
	fi
}

# make_payload <path> <size>: create a deterministic <size>-byte file.
make_payload()
{
	head -c "$2" /dev/urandom >"$1"
}

# assert_files_equal <a> <b>: fail unless the two files are byte-identical.
assert_files_equal()
{
	if ! cmp -s "$1" "$2"; then
		diag "files differ: $1 ($(wc -c <"$1") bytes) vs $2 ($(wc -c <"$2") bytes)"
		fail "${3:-file mismatch}"
	fi
}

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

. "$T_DIR/sweep.sh"

_cleanup()
{
	local pid
	for pid in "${_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null
	done
	for pid in "${_PIDS[@]:-}"; do
		[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
	done
	# Catch any proxy this test started outside gwp_start (or whose pid we
	# lost); the runner sweeps again in case we are killed before this runs.
	gwp_sweep -q
	_release_ports
	rm -rf "$WORK"
}
# The signal handler must exit rather than fall through: a handler that only
# cleans up lets bash resume the script at the next statement, so the test runs
# on with its work dir deleted and its servers dead, burying the real failure
# under bogus errors -- and run.sh's `timeout` stops bounding anything.
# Exiting from here fires the EXIT trap, so _cleanup still runs exactly once.
trap _cleanup EXIT
trap 'exit 143' INT TERM

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

# Skip unless gwproxy was built with PCRE2 support (--use-pcre), needed by the
# ACL --domain-regexp / --user-regexp matches.
require_pcre()
{
	grep -q 'CONFIG_PCRE' "$ROOT/config.h" 2>/dev/null || \
		skip "gwproxy built without PCRE (--use-pcre)"
}

# Skip unless gwproxy advertises a given long option in --help.
require_opt()
{
	"$GWPROXY" --help 2>&1 | grep -q -- "$1" || \
		skip "gwproxy has no $1 option"
}

# wait_listen() drives gwp_start() and start_httpd(), so every test depends on
# ss(8). Without it each test would instead fail after a 10s poll with a
# misleading "gwproxy did not listen"; say so up front.
require ss

# ns_drop_setup: prepare to enter a user namespace, setting NS_DROP to a
# command prefix to run "unshare -r..." under ("" when already unprivileged).
#
# "unshare -r" maps exactly ONE uid into the new namespace: the caller's. Run
# the ordinary way the caller owns this tree, so uid_map reads "0 <uid> 1" and
# the sources stay readable inside. Run under "sudo make test" the caller is
# root, uid_map reads "0 0 1", and the uid owning the tree is left unmapped --
# it reads back as "nobody", and an 0700 home directory anywhere above the
# checkout then refuses even the inner root.
#
# No capability fixes that: capabilities inside a user namespace apply only to
# inodes whose owner is mapped into it, so CAP_DAC_OVERRIDE has no authority
# over a file owned by an unmapped uid. (Skipping the user namespace needs
# CAP_SYS_ADMIN, which the containers these run in do not have.)
#
# None of the namespace tests need privilege, so when handed root they give it
# back: run as the uid owning the tree, reproducing the unprivileged mapping.
ns_drop_setup()
{
	local uid gid

	NS_DROP=""
	[ "$(id -u)" = 0 ] || return 0

	uid="${SUDO_UID:-$(stat -c %u "$ROOT")}"
	gid="${SUDO_GID:-$(stat -c %g "$ROOT")}"
	[ "$uid" != 0 ] || return 0

	require setpriv
	NS_DROP="setpriv --reuid=$uid --regid=$gid --clear-groups"
	# $WORK is mktemp'd 0700 as root; the namespace body writes there.
	chown -R "$uid:$gid" "$WORK" || fail "cannot chown $WORK to $uid:$gid"
}

# ns_inner_work <dir>: adopt the outer half's work directory, <dir>.
#
# A test that re-execs itself into a namespace sources this file again on the
# way in, so the inner half has already been given a work directory of its own
# by the mktemp above -- and it is about to stop using it, in favour of the one
# the outer half passed down. It also replaces the EXIT trap, so lib.sh's
# _cleanup never runs there to remove it. Left alone that orphans one empty
# directory per run, on the host's real /tmp: neither "unshare -rn" nor the
# "unshare -rm" that bind-mounts only /etc/hosts hides it.
ns_inner_work()
{
	rm -rf "$WORK"
	WORK="$1"
}

# Port reservations, shared by every test running on this host. pick_port()
# only knows that a port was free when it looked; under `make -jN` (or with
# several checkouts testing at once) two tests can be handed the same number.
# gwproxy binds its listener with SO_REUSEPORT, so two tests' proxies can then
# both bind it and the kernel spreads one test's connections across both --
# the client talks to the other test's proxy and sees a wrong or "corrupted"
# payload, while wait_listen() is satisfied by either. Reserving the number
# with an atomic mkdir closes that: a number is handed to one test at a time.
#
# The directory is shared like /tmp (mode 1777) because the privileged tests
# run the same helpers as root. Each reservation records the test's PID; a
# test releases its own on exit, and one left by a killed test is reclaimed
# once that PID is gone.
_PORT_DIR="${TMPDIR:-/tmp}/gwptest-ports"

# Drop reservations whose test is gone: one killed before its EXIT trap ran,
# or a half that cleaned up some other way. Without this they would only go
# away when the same number happened to be probed again.
_reap_stale_ports()
{
	local d owner

	for d in "$_PORT_DIR"/*/; do
		owner="$(cat "${d}owner" 2>/dev/null)"
		# No owner yet: being created right now, leave it alone.
		[ -n "$owner" ] || continue
		[ -d "/proc/$owner" ] || rm -rf "${d:?}" 2>/dev/null
	done
	return 0
}

# Print a free TCP port that is bindable on the IPv4/IPv6 dual stack, so it is
# also free for a plain 127.0.0.1 or [::1] bind, and reserve it for this test.
#
# The number is drawn from outside the kernel's ephemeral port range
# (net.ipv4.ip_local_port_range), never from bind(0). A reservation only
# keeps other pick_port() callers off the number: the port itself stays
# unbound until its test binds it. Everything that lets the kernel choose a
# port -- the helpers that bind port 0 (start_udp_echo, closed_port, many of
# t/servers/) and every outgoing connection -- gets one from the ephemeral
# range, unaware of the reservations. Were the reserved number from that
# range too, such a socket could take it before its test binds it, and the
# test would fail to bind its server or end up talking to the other socket.
# Outside that range the kernel never hands the number out on its own.
pick_port()
{
	local port owner i

	if [ ! -d "$_PORT_DIR" ]; then
		mkdir -p "$_PORT_DIR" 2>/dev/null && chmod 1777 "$_PORT_DIR" 2>/dev/null
	fi
	_reap_stale_ports

	for i in $(seq 1 100); do
		port="$(python3 - <<-'PY'
		import random, socket
		lo, hi = 32768, 60999
		try:
		    with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
		        lo, hi = map(int, f.read().split())
		except (OSError, ValueError):
		    pass
		# Below the ephemeral range, clear of the low ports services
		# tend to use, else above it; with no room on either side, let
		# the kernel choose, racy as that is.
		if lo - 10000 >= 1000:
		    port = random.randint(10000, lo - 1)
		elif 65535 - hi >= 1000:
		    port = random.randint(hi + 1, 65535)
		else:
		    port = 0
		s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
		try:
		    s.bind(("", port))
		except OSError:
		    raise SystemExit	# taken: print nothing, try another
		print(s.getsockname()[1])
		s.close()
		PY
		)"
		[ -n "$port" ] || continue
		# No usable reservation directory: fall back to the bare probe.
		if [ ! -w "$_PORT_DIR" ]; then
			echo "$port"
			return 0
		fi
		if mkdir "$_PORT_DIR/$port" 2>/dev/null; then
			echo "$$" >"$_PORT_DIR/$port/owner"
			echo "$port"
			return 0
		fi
		# Reserved already. Reclaim it if its test is gone, then pick
		# again either way; the probe hands out a fresh port next time.
		owner="$(cat "$_PORT_DIR/$port/owner" 2>/dev/null)"
		if [ -n "$owner" ] && [ ! -d "/proc/$owner" ]; then
			rm -rf "${_PORT_DIR:?}/${port:?}" 2>/dev/null
		fi
	done
	fail "pick_port: could not reserve a free port"
}

# Release every port this test reserved. pick_port() runs in a command
# substitution, so the reservations are found by owner, not kept in a list.
_release_ports()
{
	local d

	for d in "$_PORT_DIR"/*/; do
		[ -f "${d}owner" ] || continue
		[ "$(cat "${d}owner" 2>/dev/null)" = "$$" ] && rm -rf "${d:?}" 2>/dev/null
	done
	return 0
}

# _pid_tree <pid>: print <pid> and all its descendants, one per line.
_pid_tree()
{
	local c

	echo "$1"
	for c in $(ps -o pid= --ppid "$1" 2>/dev/null); do
		_pid_tree "$c"
	done
}

# wait_listen <port> <pid>: wait until <pid>, or a process below it (a server
# started through a shell function or a wrapper), listens on TCP <port>.
# Returns 0 once it does, 1 when <pid> exits or after 10s.
#
# Something listening on <port> is not enough: if the server failed to bind
# because another socket holds the port, that socket would satisfy the wait
# and the test would go on to talk to it. So the listener has to be <pid>'s,
# as ss -p reports it. ss can name the owner only of our own processes (or
# of any, as root); for one we cannot see into -- a server started through
# "sudo -n" -- any listener is taken, as before.
wait_listen()
{
	local port="$1" pid="${2:-}" i p owned users

	[ -n "$pid" ] || fail "wait_listen: no pid given for port $port"
	for i in $(seq 1 100); do
		# Not kill -0 alone: where sudo runs the command with the real
		# uid set to root, it fails with EPERM while the server runs.
		kill -0 "$pid" 2>/dev/null || [ -e "/proc/$pid" ] || return 1
		# Asked each time: right after "sudo ... &" the pid is still our
		# own forked shell, until it execs sudo and becomes root's.
		owned=1
		[ "$(id -u)" = 0 ] || [ -O "/proc/$pid" ] || owned=0
		if [ "$owned" = 0 ]; then
			ss -ltnH "sport = :$port" 2>/dev/null | grep -q . && return 0
		else
			users="$(ss -ltnpH "sport = :$port" 2>/dev/null)"
			for p in $(_pid_tree "$pid"); do
				case "$users" in *"pid=$p,"*) return 0 ;; esac
			done
		fi
		sleep 0.1
	done
	return 1
}

# gwp_start <bind> [args...]: start gwproxy bound to <bind> (e.g. "[::1]:1080"
# or "127.0.0.1:1080") and wait until it is listening. Sets GWP_PID. The log
# is captured under $WORK and dumped on failure.
#
# gwproxy applies a built-in default ACL (blocking loopback/private targets)
# when no --acl-file is given. The test servers live on loopback, so unless a
# test opts into the ACL (its own --acl-file) or already disables it, inject
# --acl-allow-all so proxying to loopback works -- restoring the pre-default
# "no ACL" behaviour these tests were written against.
gwp_start()
{
	local bind="$1"; shift
	local port="${bind##*:}"
	local log="$WORK/gwp.$port.log"

	case " $* " in
	*" --acl-file"*|*" --acl-allow-all "*) ;;
	*) set -- "$@" --acl-allow-all ;;
	esac

	"$GWPROXY" --bind="$bind" --log-level=3 "$@" >"$log" 2>&1 &
	local pid=$!
	_PIDS+=("$pid")
	if ! wait_listen "$port" "$pid"; then
		sed 's/^/# gwp: /' "$log" >&2
		fail "gwproxy did not listen on $bind (args: $*)"
	fi
	GWP_PID="$pid"
}

# start_udp_echo <addr>: start the UDP echo server on <addr> (an IPv4 or IPv6
# literal, "::" for dual-stack) and set UDP_ECHO_PORT to its port.
#
# The kernel picks the port (bind to 0) and the server reports it, so there is
# no window between choosing a number and binding it. pick_port() cannot be
# used here: it only finds a port free for TCP, and under `make -jN` another
# test's UDP socket may already hold that number. A readiness check asking ss
# whether *some* socket has the port is no better, because it is satisfied by
# that other socket even when this server failed to bind.
start_udp_echo()
{
	local addr="$1" log pid port i

	_UDP_ECHO_N=$((${_UDP_ECHO_N:-0} + 1))
	log="$WORK/udp_echo.$_UDP_ECHO_N.log"
	python3 "$SERVERS_DIR/udp_echo.py" "$addr" 0 >"$log" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	for i in $(seq 1 100); do
		port="$(sed -n 's/^READY \([0-9][0-9]*\)$/\1/p' "$log")"
		if [ -n "$port" ]; then
			UDP_ECHO_PORT="$port"
			return 0
		fi
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	sed 's/^/# udp_echo: /' "$log" >&2
	fail "UDP echo server on $addr did not start"
}

# closed_port: set CLOSED_PORT to a TCP port on 127.0.0.1 that refuses
# connections for the rest of the test. A port that was free when probed is
# not enough: under `make -jN` another test can be handed the same number
# and listen on it, and the "refused" connect then succeeds. So keep it
# bound, never listening and without SO_REUSEADDR, in a helper process: no
# one else can bind it, and a connect to it is refused. Not $(closed_port):
# the helper must be recorded in _PIDS of this shell to be stopped.
closed_port()
{
	local log pid port i

	_CLOSED_N=$((${_CLOSED_N:-0} + 1))
	log="$WORK/closed_port.$_CLOSED_N"
	python3 -c '
import socket, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1], flush=True)
time.sleep(3600)' >"$log" 2>&1 &
	pid=$!
	_PIDS+=("$pid")
	for i in $(seq 1 100); do
		port="$(head -n 1 "$log" 2>/dev/null)"
		case "$port" in
		""|*[!0-9]*) ;;
		*) CLOSED_PORT="$port"; return 0 ;;
		esac
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	fail "could not reserve a closed port"
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

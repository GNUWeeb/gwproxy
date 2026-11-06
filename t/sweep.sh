# SPDX-License-Identifier: GPL-2.0-only
#
# Shared "leave no gwproxy behind" sweep, sourced by t/lib.sh (so a test cleans
# up after itself) and t/run-one.sh (so the runner cleans up after a test that
# could not clean up after itself -- a SIGKILLed test never runs its EXIT trap,
# and its proxies are reparented to init and linger forever).
#
# MATCHING RULE: a process is only ever killed when /proc/<pid>/exe resolves to
# the gwproxy binary itself. Never match on the process name or command line:
# editors, shells, agent sessions and this very script routinely carry the
# string "gwproxy" in their argv, and killing those would be destructive. A
# binary that has been rebuilt since the process started shows up as
# "<path> (deleted)", so that spelling is matched too.
#
# SCOPE: by default only processes in OUR OWN process group are killed, because
# `make -jN` runs tests concurrently and a global kill would shoot down the
# proxies of every other test in flight. run-one.sh puts each test in its own
# process group (setsid), and a process keeps its process group even after it
# is orphaned and reparented to init -- which is exactly the case this sweep
# exists for. Pass --all to ignore the group and sweep everything, for cleaning
# up by hand after an interrupted session.

# _gwp_pgid_of <pid>: print the process group id of <pid>, or nothing.
# Parses /proc/<pid>/stat after the comm field, which may itself contain spaces
# and parentheses, so split on the last ')'.
_gwp_pgid_of()
{
	local st
	st="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
	st="${st##*) }"
	set -- $st
	printf '%s' "$3"
}

# gwp_sweep [-q] [--all]: kill the gwproxy processes this test left behind.
gwp_sweep()
{
	local quiet=0 all=0 arg
	for arg in "$@"; do
		case "$arg" in
		-q)	quiet=1 ;;
		--all)	all=1 ;;
		esac
	done

	local bin="${GWPROXY:-}"
	[ -n "$bin" ] || return 0
	bin="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
	[ -n "$bin" ] || return 0

	local mypg=""
	if [ "$all" = 0 ]; then
		mypg="$(_gwp_pgid_of $$)"
		[ -n "$mypg" ] || return 0
	fi

	# The group is checked first, with builtins only: a readlink, or any
	# other fork, for each of the thousands of processes on a busy host
	# took tens of seconds of every test's time limit. Only this test's
	# few processes get as far as the readlink.
	local pass d pid st f exe n=0
	for pass in TERM KILL; do
		for d in /proc/[0-9]*; do
			pid="${d#/proc/}"
			if [ -n "$mypg" ]; then
				{ read -r st <"$d/stat"; } 2>/dev/null || continue
				st="${st##*) }"
				f=($st)
				# Another test's process, or none of ours.
				[ "${f[2]:-}" = "$mypg" ] || continue
			fi
			exe="$(readlink "$d/exe" 2>/dev/null)" || continue
			case "$exe" in
			"$bin"|"$bin (deleted)") ;;
			*) continue ;;
			esac
			kill "-$pass" "$pid" 2>/dev/null || continue
			[ "$pass" = TERM ] && n=$((n + 1))
		done
		[ "$n" -gt 0 ] || break
		[ "$pass" = TERM ] && sleep 0.2
	done

	[ "$n" -gt 0 ] && [ "$quiet" = 0 ] && \
		echo "swept $n stray gwproxy process(es)" >&2
	return 0
}

# gwp_kill_priv <pid>: stop a gwproxy that was started as `$SUDO gwproxy ... &`,
# where <pid> is the $! recorded at that point.
#
# The privileged tests cannot use gwp_sweep() for this. The proxy runs as root,
# so an unprivileged /proc/<pid>/exe readlink returns nothing at all and the
# process is invisible to the very matching rule above -- the scan has to run as
# root, which is what this wrapper adds.
#
# <pid> is sudo's, not necessarily the proxy's, and which of the two it is
# depends on configuration: with `Defaults use_pty` sudo stays resident and runs
# the proxy as its child in a process group of its own, and without it sudo
# execs the proxy in place, so the proxy IS <pid>. Killing <pid> alone therefore
# reaches the proxy only in the second case, which is why this walks the process
# tree and stops every gwproxy that is <pid> or descends from it.
#
# That ancestry test is also what scopes the kill to THIS test, the job the
# process group does in gwp_sweep(). The group is unusable here precisely
# because sudo may have moved the proxy into one of its own, so under `make -jN`
# a group- or name-based kill could take out a concurrent test's proxy.
gwp_kill_priv()
{
	local pid="$1" bin="${GWPROXY:-}"

	[ -n "$pid" ] || return 0
	[ -n "$bin" ] || return 0
	bin="$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")"
	[ -n "$bin" ] || return 0

	${SUDO:-} env GWP_KP_BIN="$bin" GWP_KP_ROOT="$pid" bash -c '
		bin=$GWP_KP_BIN
		root=$GWP_KP_ROOT

		# descends <pid>: true when <pid> is $root or is reached from it
		# by walking up. Builtins only, as in gwp_sweep(): this runs for
		# every process on the host, and a fork for each of them took
		# seconds on a busy one. The bound stops a pid-reuse cycle from
		# spinning forever.
		descends() {
			local p="$1" n=0 st f
			while [ -n "$p" ] && [ "$p" != 0 ] && [ "$p" != 1 ] \
			      && [ "$n" -lt 64 ]; do
				[ "$p" = "$root" ] && return 0
				{ read -r st <"/proc/$p/stat"; } 2>/dev/null || return 1
				st=${st##*) }
				f=($st)
				p=${f[1]:-}
				n=$((n + 1))
			done
			return 1
		}

		# The ancestry is checked first: only the few processes under
		# <pid> get as far as the readlink.
		for pass in TERM KILL; do
			hit=0
			for d in /proc/[0-9]*; do
				p=${d#/proc/}
				descends "$p" || continue
				exe=$(readlink "$d/exe" 2>/dev/null) || continue
				case "$exe" in
				"$bin"|"$bin (deleted)") ;;
				*) continue ;;
				esac
				kill "-$pass" "$p" 2>/dev/null && hit=1
			done
			[ "$hit" = 1 ] || break
			[ "$pass" = TERM ] && sleep 0.2
		done
	' 2>/dev/null

	return 0
}

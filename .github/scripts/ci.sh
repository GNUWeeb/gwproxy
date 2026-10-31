#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-2.0-only
#
# CI driver for .github/workflows/ci.yml.
#
# WHY THIS FILE EXISTS
# ====================
# The workflow does not test just the pushed tip, it tests every commit in
# the pushed range: the get_commit_list job expands the range into a matrix
# axis and every job then runs "git checkout <commit>" before building.
#
# GitHub Actions, however, always reads the workflow YAML from the newest
# commit. Any build command written directly into the YAML is therefore
# applied to older commits that were never written for it -- a new configure
# flag, a new dependency, a new compiler pin -- and CI breaks retroactively
# on commits that were perfectly fine when they were written.
#
# Keeping the commands here fixes that: this script is checked out together
# with the commit under test, so every commit is built with exactly the
# commands it shipped with. Only the matrix stays in the YAML, and its values
# are handed to this script as arguments.
#
# CONSEQUENCE FOR EDITORS OF THIS FILE
# ====================================
# Older commits run their own older copy of this file. Never assume the
# caller and the script agree: validate every argument, and fail loudly
# rather than silently skipping a build.
#
# Adding a build variant should mean editing this file only.
#

set -euo pipefail

PROG="${0##*/}"

# Repository root, derived from the script location so the script can be
# invoked from anywhere.
TOPDIR="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"

# apt.llvm.org release installed when a matrix row asks for the "clang"
# package. Bumping this here (not in the YAML) keeps older commits pinned to
# the clang they were tested with.
#
# It is tied to the runner's distribution, which is pinned in the YAML rather
# than here: apt.llvm.org does not carry the same releases for every codename,
# and 23 is one of the ones it publishes for noble and not for jammy. So
# changing runs-on can invalidate this line without touching it. Check
# https://apt.llvm.org/<codename>/dists/ when moving either.
CLANG_VERSION="23"

# Extra Debian packages needed by the --use-openssl and --use-pcre variants.
# Only installed for native x86_64; the other rows are cross-compiled and
# have no target libssl/libpcre2 available.
DEB_EXTRA_PACKAGES="libssl-dev libpcre2-dev"

# Alpine/musl build dependencies, followed by what the test suite needs:
# bash for t/*.sh, python3 for the helper servers in t/servers, curl as the
# HTTP client the integration tests drive, the openssl CLI to mint the test
# certificates, and coreutils/util-linux/iproute2 for timeout(1), setsid(1)
# and ss(8), whose busybox applets do not take the options the tests use.
# The caller still has to install bash itself before it can run this script.
APK_PACKAGES="build-base musl-dev linux-headers git openssl-dev pcre2-dev
	bash python3 curl openssl coreutils util-linux iproute2"

# Parallelism for make. Overridable for local runs.
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 1)}"

# Set to 1 to print every command without running it. Used to audit the exact
# set of configure invocations a matrix row expands to.
DRY_RUN="${DRY_RUN:-0}"

# Command currently being executed, for error messages.
CMD=""

usage()
{
	cat <<EOF
Usage: ${PROG} <command> [options]

Runs the gwproxy CI steps. The workflow passes its matrix values in as
options; everything else (build variants, configure flags, package lists)
lives in this script so that it travels with the commit under test.

Commands:
  deps             Install the toolchain for one Ubuntu build matrix row.
                   Requires --arch, --cc, --cc-pkg.
  build            Run every build variant for one Ubuntu build matrix row.
                   Requires --arch, --cc, --sanitize.
  alpine-deps      Install the Alpine/musl build dependencies (needs root).
  alpine-build     Run every build variant for the Alpine/musl job.
  codespell-deps   Install codespell.
  codespell        Run codespell over man/.

Options:
  --arch=ARCH      Target architecture of the row, e.g. x86_64, mips.
                   Tests are only run when this is x86_64; every other row
                   is cross-compiled and its binaries cannot be executed.
  --cc=CC          C compiler to build with, e.g. mips-linux-gnu-gcc.
  --cc-pkg=PKG     Debian package providing --cc, or the literal "clang"
                   to install clang-${CLANG_VERSION} from apt.llvm.org.
  --sanitize=0|1   Whether this row is the AddressSanitizer/UBSan row.
  -h, --help       Print this message.

Environment:
  JOBS=N           Parallelism for make (default: nproc).
  DRY_RUN=1        Print the commands instead of running them.
EOF
}

die()
{
	printf '%s: error: %s\n' "${PROG}" "$*" >&2
	printf "Try '%s --help' for more information.\n" "${PROG}" >&2
	exit 1
}

# need <value> <option>: a missing matrix value must fail the job, never
# quietly turn into an empty string that skips a build.
need()
{
	if [ -z "$1" ]; then
		die "command '${CMD}' requires $2"
	fi
}

group_begin()
{
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		printf '::group::%s\n' "$1"
	fi
	printf '===== %s =====\n' "$1"
}

group_end()
{
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		printf '::endgroup::\n'
	fi
}

# run <cmd...>: echo the command, then run it.
run()
{
	printf '+ %s\n' "$*"
	if [ "${DRY_RUN}" = "1" ]; then
		return 0
	fi
	"$@"
}

# sudo_run <cmd...>: like run(), but escalate when not already root. The
# Ubuntu runners need sudo; the Alpine chroot steps already run as root.
sudo_run()
{
	if [ "$(id -u)" -eq 0 ]; then
		run "$@"
	else
		run sudo "$@"
	fi
}

# enter_topdir: everything below builds the working tree, so make sure we
# really are in it.
enter_topdir()
{
	cd "${TOPDIR}"
	if [ ! -x ./configure ] || [ ! -f ./Makefile ]; then
		die "'${TOPDIR}' does not look like a gwproxy tree"
	fi
}

#
# build_variant <name> <wipe_config> <run_tests> [configure args...]
#
# <wipe_config> mirrors the "rm -vf config.h config.log config.make" that
# some -- not all -- of the old workflow steps ran before "make clean". It
# matters: "make clean" reads config.make, and with CONFIG_IO_URING=y it
# also descends into src/liburing. Removing the config first is therefore
# not cosmetic, so it is kept per variant exactly where it used to be.
#
# <run_tests> is passed in rather than computed here so that each caller
# states its own test policy explicitly.
#
build_variant()
{
	local name="$1" wipe_config="$2" run_tests="$3"

	shift 3

	group_begin "build: ${name}"
	if [ "${wipe_config}" = "1" ]; then
		run rm -vf config.h config.log config.make
	fi
	run make clean
	run env CFLAGS=-Werror ./configure "$@"
	run make -j"${JOBS}"
	if [ "${run_tests}" = "1" ]; then
		run make -j"${JOBS}" test
	else
		printf -- '-- not running "make test" for this variant\n'
	fi
	group_end
}

cmd_deps()
{
	need "${arch}" '--arch=ARCH'
	need "${cc}" '--cc=CC'
	need "${cc_pkg}" '--cc-pkg=PKG'

	if [ "${cc_pkg}" = "clang" ]; then
		run wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
		sudo_run bash /tmp/llvm.sh "${CLANG_VERSION}"
		sudo_run update-alternatives --install /usr/bin/clang++ \
			clang++ "/usr/bin/clang++-${CLANG_VERSION}" 400
		sudo_run update-alternatives --install /usr/bin/clang \
			clang "/usr/bin/clang-${CLANG_VERSION}" 400
	else
		sudo_run apt-get update -y
		# shellcheck disable=SC2086 # deliberate word splitting
		sudo_run apt-get install -y ${cc_pkg}
	fi

	# OpenSSL headers for the HTTPS (--use-openssl) build and PCRE2 headers
	# for the ACL regexp (--use-pcre) build.
	if [ "${arch}" = "x86_64" ]; then
		# shellcheck disable=SC2086 # deliberate word splitting
		sudo_run apt-get install -y ${DEB_EXTRA_PACKAGES}
	fi

	run "${cc}" --version
}

cmd_build()
{
	local run_tests=0
	local san=()

	need "${arch}" '--arch=ARCH'
	need "${cc}" '--cc=CC'
	need "${sanitize}" '--sanitize=0|1'
	case "${sanitize}" in
	0|1)
		;;
	*)
		die "--sanitize must be 0 or 1, got '${sanitize}'"
		;;
	esac

	enter_topdir

	# The workflow used to export CC for the whole job; the io_uring
	# variants below rely on it instead of passing --cc=. Set it here so
	# the script is self-contained.
	export CC="${cc}"

	# Only the native rows can execute what they built.
	if [ "${arch}" = "x86_64" ]; then
		run_tests=1
	else
		printf 'NOTE: arch=%s is cross-compiled, "make test" is skipped\n' \
			"${arch}"
	fi

	if [ "${sanitize}" = "1" ]; then
		san=(--sanitize)
		build_variant "default + sanitizers" 0 "${run_tests}" \
			"--cc=${cc}" --sanitize
	else
		build_variant "default" 0 "${run_tests}" \
			"--cc=${cc}"
		build_variant "debug" 0 "${run_tests}" \
			"--cc=${cc}" --debug
	fi

	# NOTE: no --cc= here, on purpose. These two take the compiler from the
	# exported CC, which is what the workflow has always done.
	build_variant "io_uring" 1 "${run_tests}" \
		--use-io-uring
	build_variant "io_uring + debug" 1 "${run_tests}" \
		--use-io-uring --debug

	# libssl/libpcre2 are only installed for the native x86_64 rows (see
	# cmd_deps), so the TLS and regexp variants are x86_64 only. They are
	# also the variants whose "make test" actually exercises ssl.t, t/0034
	# and the ACL regexp cases, under the sanitizer when this row asks for
	# it.
	if [ "${arch}" != "x86_64" ]; then
		return 0
	fi

	# The raw DNS resolver. It needs no extra library, so the only reason
	# it sits below the x86_64 guard rather than beside the io_uring rows
	# is that this is where "make test" runs, and t/0027 -- the only thing
	# that exercises the response parser -- has to execute to be worth
	# anything. Widening it to the cross rows would add the endianness
	# coverage that a packet parser wants; nobody has checked it builds
	# there yet, and a matrix row that cannot compile is worse than one
	# that is missing.
	build_variant "new-dns-resolver" 1 "${run_tests}" \
		"--cc=${cc}" --use-new-dns-resolver \
		${san[@]+"${san[@]}"}

	build_variant "openssl" 1 "${run_tests}" \
		"--cc=${cc}" --use-openssl \
		${san[@]+"${san[@]}"}
	build_variant "openssl + io_uring" 1 "${run_tests}" \
		"--cc=${cc}" --use-openssl --use-io-uring \
		${san[@]+"${san[@]}"}
	build_variant "openssl + io_uring + pcre" 1 "${run_tests}" \
		"--cc=${cc}" --use-openssl --use-io-uring --use-pcre \
		${san[@]+"${san[@]}"}
}

cmd_alpine_deps()
{
	# The workflow runs this step as root ("alpine.sh --root"), and the
	# Alpine image has no sudo to fall back on, so call apk directly: a
	# non-root invocation should fail with apk's own permission error
	# rather than a confusing "sudo: not found".
	# shellcheck disable=SC2086 # deliberate word splitting
	run apk add --no-cache ${APK_PACKAGES}
}

cmd_alpine_build()
{
	#
	# Alpine runs on the native x86_64 runner, so unlike the cross-compiled
	# rows of the build job it can execute what it builds. Run the tests.
	#
	local run_tests=1

	enter_topdir

	build_variant "default" 0 "${run_tests}" \
		--cc=gcc
	build_variant "debug" 0 "${run_tests}" \
		--cc=gcc --debug
	build_variant "io_uring" 1 "${run_tests}" \
		--cc=gcc --use-io-uring
	build_variant "io_uring + debug" 1 "${run_tests}" \
		--cc=gcc --use-io-uring --debug
	# Exercise the TLS module (ssl.c) against musl.
	build_variant "openssl" 1 "${run_tests}" \
		--cc=gcc --use-openssl
	# Exercise the ACL PCRE2 path against musl.
	build_variant "pcre" 1 "${run_tests}" \
		--cc=gcc --use-io-uring --use-pcre
}

cmd_codespell_deps()
{
	sudo_run apt-get update -y
	sudo_run apt-get install -y codespell
	run codespell --version
}

cmd_codespell()
{
	enter_topdir
	run codespell --ignore-words=.github/actions/codespell/stopwords man/
}

arch=""
cc=""
cc_pkg=""
sanitize=""

if [ "$#" -eq 0 ]; then
	usage >&2
	die "no command given"
fi

CMD="$1"
shift

for opt in "$@"; do
	case "${opt}" in
	--arch=*)
		arch="${opt#*=}"
		;;
	--cc=*)
		cc="${opt#*=}"
		;;
	--cc-pkg=*)
		cc_pkg="${opt#*=}"
		;;
	--sanitize=*)
		sanitize="${opt#*=}"
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		die "unknown option '${opt}' for command '${CMD}'"
		;;
	esac
done

case "${CMD}" in
-h|--help)
	usage
	exit 0
	;;
deps)
	cmd_deps
	;;
build)
	cmd_build
	;;
alpine-deps)
	cmd_alpine_deps
	;;
alpine-build)
	cmd_alpine_build
	;;
codespell-deps)
	cmd_codespell_deps
	;;
codespell)
	cmd_codespell
	;;
*)
	die "unknown command '${CMD}'"
	;;
esac

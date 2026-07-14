#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run every gwproxy integration test (t/[0-9]*.sh) and print a summary.
# Exit status is non-zero if any test fails. Skipped tests (exit 77) do not
# count as failures.

set -u

T_DIR="$(cd "$(dirname "$0")" && pwd)"
export GWPROXY="${GWPROXY:-$T_DIR/../gwproxy}"

if [ ! -x "$GWPROXY" ]; then
	echo "gwproxy binary not found at $GWPROXY (run 'make' first)" >&2
	exit 1
fi

shopt -s nullglob
tests=("$T_DIR"/[0-9]*.sh)
shopt -u nullglob
IFS=$'\n' tests=($(printf '%s\n' "${tests[@]}" | sort)); unset IFS

if [ ${#tests[@]} -eq 0 ]; then
	echo "no integration tests found in $T_DIR"
	exit 0
fi

npass=0
nfail=0
nskip=0
failed=()

for t in "${tests[@]}"; do
	name="$(basename "$t")"
	out="$(timeout 120 bash "$t" 2>&1)"
	rc=$?
	case "$rc" in
	0)
		echo "ok    $name"
		npass=$((npass + 1))
		;;
	77)
		reason="$(printf '%s\n' "$out" | sed -n 's/^SKIP: //p' | head -1)"
		echo "skip  $name${reason:+ - $reason}"
		nskip=$((nskip + 1))
		;;
	*)
		echo "FAIL  $name (rc=$rc)"
		printf '%s\n' "$out" | sed 's/^/      /'
		nfail=$((nfail + 1))
		failed+=("$name")
		;;
	esac
done

echo "------------------------------------------------------------"
echo "integration: passed=$npass failed=$nfail skipped=$nskip"

if [ $nfail -ne 0 ]; then
	echo "FAILED: ${failed[*]}"
	exit 1
fi
exit 0

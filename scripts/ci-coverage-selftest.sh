#!/bin/sh
# ci-coverage-selftest.sh validates the coverage profiles produced by the CI
# lanes BEFORE they are merged. A profile that is missing, empty, lacks the
# `mode:` header, or records implausibly few blocks must fail the pipeline
# here with a message naming the file, instead of surfacing later as a
# confusing merge-coverage error or silently understated coverage.
#
# Usage: ci-coverage-selftest.sh PROFILE...
#
# Environment:
#   KC_MIN_COVERAGE_BLOCKS   minimum coverage blocks per profile (default: 1000)
set -eu

MIN_BLOCKS="${KC_MIN_COVERAGE_BLOCKS:-1000}"
[ "$#" -ge 1 ] || {
	echo "ci-coverage-selftest: usage: ci-coverage-selftest.sh PROFILE..." >&2
	exit 1
}

case "$MIN_BLOCKS" in
*[!0-9]* | '')
	echo "ci-coverage-selftest: KC_MIN_COVERAGE_BLOCKS must be a non-negative integer (got '$MIN_BLOCKS')" >&2
	exit 1
	;;
esac

status=0
for profile in "$@"; do
	if [ ! -f "$profile" ]; then
		echo "ci-coverage-selftest: $profile does not exist; the producing lane did not write a profile (expected go test -coverprofile=$profile ...)" >&2
		status=1
		continue
	fi
	if [ ! -s "$profile" ]; then
		echo "ci-coverage-selftest: $profile is empty; the producing lane wrote no coverage data" >&2
		status=1
		continue
	fi
	first="$(head -n 1 "$profile")"
	case "$first" in
	mode:*)
		mode="${first#mode: }"
		[ -n "$mode" ] || {
			echo "ci-coverage-selftest: $profile has an empty mode header ($first)" >&2
			status=1
			continue
		}
		;;
	*)
		echo "ci-coverage-selftest: $profile has no 'mode:' header (first line: $first)" >&2
		status=1
		continue
		;;
	esac
	blocks="$(awk 'NR > 1 && NF == 3 && $3 ~ /^[0-9]+$/ { n++ } END { print n + 0 }' "$profile")"
	if [ "$blocks" -lt "$MIN_BLOCKS" ]; then
		echo "ci-coverage-selftest: $profile records $blocks coverage blocks, below the required $MIN_BLOCKS (truncated or semantically empty profile)" >&2
		status=1
		continue
	fi
	echo "ci-coverage-selftest: $profile ok ($blocks blocks, mode $mode)"
done
exit "$status"

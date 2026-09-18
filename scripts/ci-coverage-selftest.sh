#!/bin/sh
# ci-coverage-selftest.sh validates the coverage profiles produced by the CI
# lanes BEFORE they are merged. A profile that is missing, empty, lacks the
# `mode:` header, or records implausibly few blocks must fail the pipeline
# here with a message naming the file, instead of surfacing later as a
# confusing merge-coverage error or silently understated coverage.
#
# Cross-package assertion: the integration lane runs with `-coverpkg=./...`,
# so its profile must record coverage blocks for production packages the
# integration tests reach indirectly through the tested packages (for example
# internal/pipeline, internal/safefs and internal/forge). Dropping or
# narrowing -coverpkg silently shrinks the profile to the directly tested
# packages while a plain block-count check still passes, so the profile whose
# basename matches KC_INTEGRATION_PROFILE is additionally required to contain
# at least one block for every fragment in KC_CROSSPKG_PATHS. Those paths are
# absent from the profile when the integration lane loses -coverpkg=./...
#
# Usage: ci-coverage-selftest.sh PROFILE...
#
# Environment:
#   KC_MIN_COVERAGE_BLOCKS  minimum coverage blocks per profile (default: 1000)
#   KC_INTEGRATION_PROFILE  basename of the integration profile checked for
#                           cross-package instrumentation
#                           (default: integration-coverage.out)
#   KC_CROSSPKG_PATHS       space-separated path fragments that must appear in
#                           that profile; set it empty to disable the check
#                           (default: internal/pipeline internal/safefs internal/forge)
set -eu

MIN_BLOCKS="${KC_MIN_COVERAGE_BLOCKS:-1000}"
INTEGRATION_PROFILE="${KC_INTEGRATION_PROFILE:-integration-coverage.out}"
CROSSPKG_PATHS="${KC_CROSSPKG_PATHS-internal/pipeline internal/safefs internal/forge}"
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
	ok=1
	if [ "${profile##*/}" = "$INTEGRATION_PROFILE" ]; then
		for fragment in $CROSSPKG_PATHS; do
			if ! grep -Fq "/$fragment/" "$profile"; then
				echo "ci-coverage-selftest: $profile records no coverage blocks for $fragment: the integration lane must run with -coverpkg=./... so cross-package production paths are instrumented" >&2
				ok=0
			fi
		done
	fi
	if [ "$ok" -eq 0 ]; then
		status=1
		continue
	fi
	echo "ci-coverage-selftest: $profile ok ($blocks blocks, mode $mode)"
done
exit "$status"

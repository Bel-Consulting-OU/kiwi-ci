#!/bin/sh
# coverage-floor.sh enforces a minimum total statement coverage.
#
# Usage:
#   coverage-floor.sh [profile]        (default: coverage.out)
#
# Environment:
#   KC_MIN_COVERAGE   minimum total percentage (default: 60)
#
# The profile is produced by the coverage lane:
#   go test -coverprofile=coverage.out ./...
#
# A missing profile, an unparsable total, or a total below the floor all fail
# with a non-zero exit status so the CI step fails closed.
set -eu

PROFILE="${1:-coverage.out}"
FLOOR="${KC_MIN_COVERAGE:-60}"

if [ ! -f "$PROFILE" ]; then
	echo "coverage-floor: profile $PROFILE not found; run go test -coverprofile=$PROFILE ./..." >&2
	exit 1
fi

TOTAL="$(go tool cover -func="$PROFILE" | awk '$1 == "total:" { gsub(/%/, "", $NF); print $NF }')"
if [ -z "$TOTAL" ]; then
	echo "coverage-floor: could not parse a total from $PROFILE" >&2
	exit 1
fi

awk -v total="$TOTAL" -v floor="$FLOOR" 'BEGIN {
	if (total + 0 != total || floor + 0 != floor) {
		printf("coverage-floor: non-numeric total (%s) or floor (%s)\n", total, floor) > "/dev/stderr"
		exit 1
	}
	if (total + 0 < floor + 0) {
		printf("coverage-floor: total %.1f%% is below the %.1f%% floor\n", total, floor) > "/dev/stderr"
		exit 1
	}
	printf("coverage-floor: total %.1f%% >= %.1f%% floor\n", total, floor)
}'

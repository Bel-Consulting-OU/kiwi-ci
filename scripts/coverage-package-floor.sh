#!/bin/sh
# coverage-package-floor.sh enforces a minimum STATEMENT coverage for every
# package in a Go coverage profile. The total floor (coverage-floor.sh) can
# be met while a single package sits at 0%; this gate names every package
# below its floor and fails closed.
#
# Usage:
#   coverage-package-floor.sh [profile]        (default: coverage.out)
#   coverage-package-floor.sh --selftest       (fixture-driven proof of the
#                                               failure and override paths)
#
# Environment:
#   KC_MIN_PACKAGE_COVERAGE    minimum per-package percentage (default: 80)
#   KC_PACKAGE_FLOOR_BASELINE  baseline file of justified exceptions
#                              (default: coverage-package-baseline.txt next
#                              to this script). Format, one entry per line:
#                                  pkg<TAB>floor<TAB>reason
#                              Blank lines and '#' comments are ignored. An
#                              explicitly set path that does not exist is an
#                              error; the default file may be absent.
#
# A missing/empty/malformed profile, a malformed baseline, a non-numeric
# floor or any package below its effective floor exits non-zero.
set -eu

SELF=$0
case $SELF in
/*) ;;
*) SELF=$(pwd)/$SELF ;;
esac
SCRIPT_DIR=$(CDPATH='' cd "$(dirname "$SELF")" && pwd)
DEFAULT_BASELINE="$SCRIPT_DIR/coverage-package-baseline.txt"
DEFAULT_FLOOR=80

usage() {
	echo "usage: $0 [profile]" >&2
	echo "       $0 --selftest" >&2
}

selftest() {
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	cat >"$tmp/below.out" <<'EOF'
mode: atomic
github.com/Bel-Consulting-OU/kiwi-ci/internal/low/low.go:1.1,3.2 8 0
github.com/Bel-Consulting-OU/kiwi-ci/internal/low/rest.go:1.1,3.2 2 2
EOF
	cat >"$tmp/at-floor.out" <<'EOF'
mode: atomic
github.com/Bel-Consulting-OU/kiwi-ci/internal/ok/ok.go:1.1,3.2 8 1
github.com/Bel-Consulting-OU/kiwi-ci/internal/ok/more.go:1.1,3.2 2 0
EOF
	cat >"$tmp/above.out" <<'EOF'
mode: atomic
github.com/Bel-Consulting-OU/kiwi-ci/internal/ok/ok.go:1.1,3.2 10 1
EOF
	cat >"$tmp/tiny.out" <<'EOF'
mode: atomic
github.com/Bel-Consulting-OU/kiwi-ci/internal/low/low.go:1.1,3.2 10 0
EOF
	cat >"$tmp/baseline.txt" <<'EOF'
# selftest fixture
internal/low	10	selftest fixture: grandfathering a package pending real tests
EOF
	cat >"$tmp/bad-baseline.txt" <<'EOF'
internal/low not-a-tab-separated-entry
EOF
	cat >"$tmp/empty-baseline.txt" <<'EOF'
EOF
	printf 'mode: atomic\nthis is not a coverage line\n' >"$tmp/malformed.out"

	status=0
	check_case() {
		_case=$1
		_want=$2
		_msg=$3
		shift 3
		_out=$("$@" 2>&1) && _got=0 || _got=$?
		_ok=1
		if [ "$_got" -ne "$_want" ]; then
			echo "coverage-package-floor: selftest FAIL: $_case exited $_got, want $_want" >&2
			_ok=0
		fi
		case $_out in
		*"$_msg"*) ;;
		*)
			echo "coverage-package-floor: selftest FAIL: $_case output does not mention '$_msg'" >&2
			_ok=0
			;;
		esac
		if [ "$_ok" -eq 0 ]; then
			echo "$_out" >&2
			status=1
		else
			echo "coverage-package-floor: selftest ok: $_case (exit $_got)"
		fi
	}

	check_case "below-floor profile fails" 1 "internal/low" \
		env KC_PACKAGE_FLOOR_BASELINE="$tmp/empty-baseline.txt" sh "$SELF" "$tmp/below.out"
	check_case "at-floor profile passes" 0 "at/above floor" \
		env sh "$SELF" "$tmp/at-floor.out"
	check_case "above-floor profile passes" 0 "at/above floor" \
		env sh "$SELF" "$tmp/above.out"
	check_case "baseline override passes" 0 "at/above floor" \
		env KC_PACKAGE_FLOOR_BASELINE="$tmp/baseline.txt" sh "$SELF" "$tmp/below.out"
	check_case "baseline override below the baseline floor fails" 1 "internal/low" \
		env KC_PACKAGE_FLOOR_BASELINE="$tmp/baseline.txt" sh "$SELF" "$tmp/tiny.out"
	check_case "raised default floor fails" 1 "internal/ok" \
		env KC_MIN_PACKAGE_COVERAGE=90 sh "$SELF" "$tmp/at-floor.out"
	check_case "malformed profile fails" 1 "malformed" \
		env sh "$SELF" "$tmp/malformed.out"
	check_case "missing profile fails" 1 "not found" \
		env sh "$SELF" "$tmp/does-not-exist.out"
	check_case "malformed baseline fails" 1 "baseline" \
		env KC_PACKAGE_FLOOR_BASELINE="$tmp/bad-baseline.txt" sh "$SELF" "$tmp/at-floor.out"
	check_case "explicit missing baseline fails" 1 "baseline" \
		env KC_PACKAGE_FLOOR_BASELINE="$tmp/no-baseline-here.txt" sh "$SELF" "$tmp/at-floor.out"
	check_case "non-numeric floor fails" 1 "KC_MIN_PACKAGE_COVERAGE" \
		env KC_MIN_PACKAGE_COVERAGE=eighty sh "$SELF" "$tmp/at-floor.out"

	if [ "$status" -ne 0 ]; then
		echo "coverage-package-floor: selftest FAILED" >&2
		exit 1
	fi
	echo "coverage-package-floor: selftest OK"
}

case "${1:-}" in
--selftest)
	selftest
	exit 0
	;;
--help | -h)
	usage
	exit 0
	;;
esac

PROFILE="${1:-coverage.out}"
FLOOR="${KC_MIN_PACKAGE_COVERAGE:-$DEFAULT_FLOOR}"
BASELINE_SET=0
if [ "${KC_PACKAGE_FLOOR_BASELINE+x}" = x ] && [ -n "$KC_PACKAGE_FLOOR_BASELINE" ]; then
	BASELINE_SET=1
	BASELINE="$KC_PACKAGE_FLOOR_BASELINE"
else
	BASELINE="$DEFAULT_BASELINE"
fi

awk -v floor="$FLOOR" 'BEGIN {
	if (floor + 0 != floor || floor + 0 < 0 || floor + 0 > 100) {
		printf("coverage-package-floor: KC_MIN_PACKAGE_COVERAGE must be a percentage in [0,100] (got %s)\n", floor) > "/dev/stderr"
		exit 1
	}
}' || exit 1

if [ ! -f "$PROFILE" ]; then
	echo "coverage-package-floor: profile $PROFILE not found; run go test -coverprofile=$PROFILE ./..." >&2
	exit 1
fi
if [ ! -s "$PROFILE" ]; then
	echo "coverage-package-floor: profile $PROFILE is empty" >&2
	exit 1
fi

if [ -f "$BASELINE" ]; then
	awk -F'\t' '
	BEGIN { bad = 0 }
	/^[ \t]*$/ { next }
	/^[ \t]*#/ { next }
	{
		if (NF != 3) {
			printf("coverage-package-floor: %s:%d: expected pkg<TAB>floor<TAB>reason, got %d field(s)\n", FILENAME, FNR, NF) > "/dev/stderr"
			bad = 1
			next
		}
		if ($2 !~ /^[0-9]+([.][0-9]+)?$/ || $2 + 0 < 0 || $2 + 0 > 100) {
			printf("coverage-package-floor: %s:%d: floor %s is not a percentage in [0,100]\n", FILENAME, FNR, $2) > "/dev/stderr"
			bad = 1
			next
		}
		if ($3 ~ /^[ \t]*$/) {
			printf("coverage-package-floor: %s:%d: baseline entry for %s has no reason\n", FILENAME, FNR, $1) > "/dev/stderr"
			bad = 1
			next
		}
		if ($1 in seen) {
			printf("coverage-package-floor: %s:%d: duplicate baseline entry for %s\n", FILENAME, FNR, $1) > "/dev/stderr"
			bad = 1
			next
		}
		seen[$1] = 1
	}
	END { exit bad }' "$BASELINE" || exit 1
elif [ "$BASELINE_SET" -eq 1 ]; then
	echo "coverage-package-floor: baseline $BASELINE not found (explicit KC_PACKAGE_FLOOR_BASELINE must exist)" >&2
	exit 1
fi

# Per-package statement aggregation: same profile technique as
# coverage-report.sh, plus strict line validation so a truncated or
# hand-edited profile fails instead of silently under-reporting packages.
STATS=$(awk -F'[: ,]' '
NR == 1 {
	if ($0 !~ /^mode: [a-z]+$/) {
		printf("coverage-package-floor: malformed profile header: %s\n", $0) > "/dev/stderr"
		bad = 1
	}
	next
}
NF == 0 { next }
{
	if (NF < 5 || $1 !~ /\.go$/ || $(NF - 1) !~ /^[0-9]+$/ || $NF !~ /^[0-9]+$/) {
		printf("coverage-package-floor: malformed profile line %d: %s\n", NR, $0) > "/dev/stderr"
		bad = 1
		next
	}
	file = $1
	stmts = $(NF - 1) + 0
	count = $NF + 0
	sub(/^github.com\/Bel-Consulting-OU\/kiwi-ci\//, "", file)
	n = split(file, a, "/")
	dir = ""
	for (i = 1; i < n; i++) dir = dir (i > 1 ? "/" : "") a[i]
	if (dir == "") dir = "."
	total[dir] += stmts
	if (count > 0) covered[dir] += stmts
}
END {
	if (bad) exit 1
	for (p in total) printf "%s\t%d\t%d\t%.2f\n", p, total[p], covered[p], 100 * covered[p] / total[p]
}' "$PROFILE") || {
	echo "coverage-package-floor: refusing $PROFILE: profile is malformed" >&2
	exit 1
}

baseline_field() { # pkg field(2 or 3)
	[ -f "$BASELINE" ] || return 0
	awk -F'\t' -v pkg="$1" -v field="$2" '
	/^[ \t]*$/ { next }
	/^[ \t]*#/ { next }
	$1 == pkg { print $field; exit }' "$BASELINE"
}

below=0
checked=0
while IFS="	" read -r pkg stmts covered pct; do
	[ -n "$pkg" ] || continue
	checked=$((checked + 1))
	floor="$FLOOR"
	reason=""
	override_floor=$(baseline_field "$pkg" 2)
	if [ -n "$override_floor" ]; then
		floor="$override_floor"
		reason=$(baseline_field "$pkg" 3)
	fi
	if awk -v pct="$pct" -v floor="$floor" 'BEGIN { exit !(pct + 0 < floor + 0) }'; then
		below=$((below + 1))
		if [ -n "$reason" ]; then
			echo "coverage-package-floor: $pkg ${pct}% < ${floor}% baseline floor - reason: $reason [$covered/$stmts stmts]" >&2
		else
			echo "coverage-package-floor: $pkg ${pct}% < ${floor}% floor [$covered/$stmts stmts]" >&2
		fi
	fi
done <<EOF
$STATS
EOF

if [ "$checked" -eq 0 ]; then
	echo "coverage-package-floor: no packages parsed from $PROFILE" >&2
	exit 1
fi
if [ "$below" -gt 0 ]; then
	echo "coverage-package-floor: FAIL: $below of $checked package(s) below their floor (default ${FLOOR}%; baseline $BASELINE)" >&2
	exit 1
fi
echo "coverage-package-floor: $checked package(s) at/above floor (default ${FLOOR}%; baseline $BASELINE)"

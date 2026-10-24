#!/bin/sh
# perf-compare.sh runs the release performance contract (./perf) and fails
# on regressions against the checked-in baseline in bench/.
#
# Noise contract (read this before tightening the budget):
#   Wall-clock ns/op on a shared machine is not reproducible to a few
#   percent. This gate therefore
#     * samples each benchmark PERF_COUNT times (default 7) and compares
#       the median (stable to one lucky/unlucky sample),
#     * allows PERF_THRESHOLD_PCT regression (default 100 = 2x — catches
#       order-of-magnitude breaks, not 10% drift),
#     * enforces an absolute ceiling per benchmark as a backstop that
#       does not depend on baseline freshness,
#     * runs first in release-gate so the machine is quiet.
#   Tight budgets (10-25%) need a dedicated idle host. Do not pretend a
#   laptop is that host.
#
# Usage:
#   scripts/perf-compare.sh            # compare against bench/baseline.txt
#   scripts/perf-compare.sh --update   # rewrite the baseline (quiet machine!)
#
# Environment:
#   PERF_THRESHOLD_PCT   max median regression vs baseline (default 100)
#   PERF_COUNT           samples per benchmark (default 7, odd preferred)
set -eu

die() {
	echo "perf-compare: $*" >&2
	exit 1
}

UPDATE=0
if [ "${1:-}" = "--update" ]; then
	UPDATE=1
fi

THRESHOLD="${PERF_THRESHOLD_PCT:-100}"
case "$THRESHOLD" in
"" | *[!0-9]*) die "PERF_THRESHOLD_PCT must be a non-negative integer, got '$THRESHOLD'" ;;
esac

COUNT="${PERF_COUNT:-7}"
case "$COUNT" in
"" | *[!0-9]*) die "PERF_COUNT must be a positive integer, got '$COUNT'" ;;
esac
[ "$COUNT" -ge 1 ] || die "PERF_COUNT must be >= 1"

CONTRACT=2
BASELINE="bench/baseline.txt"
OUT="$(mktemp)"
CEILINGS="bench/ceilings.txt"
trap 'rm -f "$OUT" "$OUT.ns"' EXIT INT TERM

echo "perf-compare: running ./perf benchmarks (count=$COUNT, median-of-N, threshold=${THRESHOLD}%)"
# Two passes: micro benchmarks get the full sample count; e2e/scale
# benchmarks (which spin up real control planes) run a bounded wave so a
# loaded machine cannot pin a worker for minutes per sample.
{
	go test -run '^$' -bench 'Pipeline|Acceptance|SeededQueue' -benchmem -benchtime=150ms -count="$COUNT" ./perf/
	PERF_QUEUE_WAVE="${PERF_QUEUE_WAVE:-200}" go test -run '^$' -bench 'E2E|Scale' -benchmem -benchtime=1x -count="${PERF_HEAVY_COUNT:-3}" ./perf/
} | tee "$OUT"

# Median-of-N per benchmark. Output: name ns/op (float).
parse_median() {
	awk '/^Benchmark/ {
		name=$1; sub(/-[0-9]+$/, "", name);
		ns=""
		for (i=2; i<=NF; i++) if ($i=="ns/op") { ns=$(i-1); break }
		if (ns == "") next
		n[name]++
		samples[name, n[name]] = ns+0
	}
	END {
		for (name in n) {
			cnt = n[name]
			for (i = 1; i <= cnt; i++) {
				for (j = i+1; j <= cnt; j++) {
					if (samples[name, j] < samples[name, i]) {
						tmp = samples[name, i]
						samples[name, i] = samples[name, j]
						samples[name, j] = tmp
					}
				}
			}
			mid = int((cnt+1)/2)
			printf "%s %.6f\n", name, samples[name, mid]
		}
	}'
}

CUR="$OUT.ns"
parse_median <"$OUT" | sort >"$CUR"
[ -s "$CUR" ] || die "no benchmarks produced ns/op results"

if [ "$UPDATE" = "1" ]; then
	mkdir -p bench
	{
		echo "# perf baseline contract=$CONTRACT count=$COUNT threshold=$THRESHOLD"
		echo "# regenerate with: scripts/perf-compare.sh --update (on a quiet machine)"
		cat "$CUR"
	} >"$BASELINE"
	# Ceilings are absolute SLOs: 3x the observed median. They backstop a
	# stale baseline on a machine that is generally slower.
	awk '{ printf "%s %.0f\n", $1, $2*3 }' "$CUR" >"$CEILINGS"
	echo "perf-compare: baseline updated at $BASELINE"
	echo "perf-compare: ceilings updated at $CEILINGS"
	exit 0
fi

[ -f "$BASELINE" ] || die "missing $BASELINE (run scripts/perf-compare.sh --update to create it)"

BASE_CONTRACT="$(awk -F= '/^# perf baseline contract=/{print $2; exit}' "$BASELINE" | awk '{print $1}')"
if [ -n "$BASE_CONTRACT" ] && [ "$BASE_CONTRACT" != "$CONTRACT" ]; then
	die "baseline contract=$BASE_CONTRACT != current $CONTRACT (regenerate with --update)"
fi

FAIL=0
MISSING="$(awk '
	NR==FNR {
		if ($0 ~ /^#/) next
		if (NF>=2) { base[$1]=$2 }
		next
	}
	{
		name=$1; cur=$2
		if (!(name in base)) { print "NEW", name, cur; next }
		limit = base[name] * (1 + t/100.0)
		if (cur > limit) { print "REG", name, cur, base[name], limit }
		seen[name]=1
	}
	END {
		for (n in base) if (!(n in seen)) print "GONE", n
	}
' t="$THRESHOLD" "$BASELINE" "$CUR")"

if [ -n "$MISSING" ]; then
	printf '%s\n' "$MISSING" | while read -r kind name rest; do
		case "$kind" in
		NEW) echo "perf-compare: FAIL $name is new and has no baseline budget (run --update)" >&2 ;;
		GONE) echo "perf-compare: FAIL $name missing from current run (contract shrank)" >&2 ;;
		REG) echo "perf-compare: FAIL $name median ns/op $rest" >&2 ;;
		esac
	done
	FAIL=1
else
	awk '
		NR==FNR { if ($0 !~ /^#/ && NF>=2) base[$1]=$2; next }
		{ printf "perf-compare: ok   %s median %s ns/op (baseline %s, budget %s)\n", $1, $2, base[$1], base[$1]*(1+t/100.0) }
	' t="$THRESHOLD" "$BASELINE" "$CUR"
fi

# Absolute ceilings: do not depend on baseline freshness.
if [ -f "$CEILINGS" ]; then
	while read -r name ceil; do
		case "$name" in \#*|"") continue ;; esac
		cur="$(awk -v n="$name" '$1==n{print $2; exit}' "$CUR")"
		[ -n "$cur" ] || continue
		over="$(awk -v c="$cur" -v l="$ceil" 'BEGIN{print (c>l)?1:0}')"
		if [ "$over" = "1" ]; then
			echo "perf-compare: FAIL $name median $cur ns/op exceeds absolute ceiling $ceil" >&2
			FAIL=1
		fi
	done <"$CEILINGS"
fi

if [ "$FAIL" != "0" ]; then
	die "performance regression against $BASELINE"
fi
echo "perf-compare: all benchmarks within ${THRESHOLD}% of $BASELINE (median-of-$COUNT) and under absolute ceilings"

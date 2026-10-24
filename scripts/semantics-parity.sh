#!/bin/sh
# semantics-parity.sh — differential oracle between local execution and
# `kiwi explain --why` for the same change set.
#
# For each fixture pipeline + changed-file set:
#   1. kiwi explain --why JOB --changed-files …  → parse "path matched"
#   2. kiwi run --job JOB --changed-files …       → parse job status
#   3. Assert agreement: explained match ⇒ run is success/skipped-not-path,
#      explained no-match with known set ⇒ run is skipped (path filter).
#
# Unknown-diff is out of scope here (explain prints indeterminate; run runs
# conservatively) — that class is covered by unit tests.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
KIWI="${KIWI:-$ROOT/dist/kiwi}"
if [ ! -x "$KIWI" ]; then
	KIWI="$(command -v kiwi || true)"
fi
if [ -z "$KIWI" ] || [ ! -x "$KIWI" ]; then
	echo "semantics-parity: build kiwi first (go build -o dist/kiwi ./cmd/kiwi)" >&2
	exit 1
fi
KIWI="$(cd "$(dirname "$KIWI")" && pwd)/$(basename "$KIWI")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fixture: path-gated job
cat >"$WORK/p.yaml" <<'EOF'
version: 1
jobs:
  gated:
    paths: [src/**]
    steps:
      - run: "true"
  always:
    steps:
      - run: "true"
EOF

fail=0

check_pair() {
	job="$1"
	files="$2"
	want_path="$3" # yes|no
	explain_out="$WORK/explain.out"
	run_out="$WORK/run.out"
	(
		cd "$WORK"
		"$KIWI" explain -f p.yaml --why "$job" --event push --changed-files "$files" \
			>"$explain_out" 2>/dev/null
	)
	matched=$(grep -E 'path matched:' "$explain_out" | awk '{print $3}' || true)
	if [ "$matched" != "$want_path" ]; then
		echo "FAIL explain $job files=$files path matched=$matched want=$want_path" >&2
		fail=1
		return
	fi
	set +e
	(
		cd "$WORK"
		"$KIWI" run -f p.yaml --job "$job" --changed-files "$files" >"$run_out" 2>&1
	)
	rc=$?
	set -e
	if [ "$want_path" = "yes" ]; then
		# Must run (success)
		if [ "$rc" -ne 0 ]; then
			echo "FAIL run $job files=$files expected success, rc=$rc" >&2
			sed -n '1,20p' "$run_out" >&2
			fail=1
			return
		fi
		if ! grep -q 'success' "$run_out"; then
			echo "FAIL run $job files=$files no success in output" >&2
			fail=1
			return
		fi
	else
		# Path filter should skip → overall success (job skipped)
		if [ "$rc" -ne 0 ]; then
			echo "FAIL run $job files=$files expected skip-as-success, rc=$rc" >&2
			sed -n '1,20p' "$run_out" >&2
			fail=1
			return
		fi
		if ! grep -q 'skipped' "$run_out"; then
			echo "FAIL run $job files=$files expected skipped status" >&2
			fail=1
			return
		fi
	fi
	echo "ok explain+run $job files=$files path=$want_path"
}

check_pair gated "src/x.go" yes
check_pair gated "docs/readme.md" no
check_pair always "docs/readme.md" yes # no path filter → always match (run)

if [ "$fail" -ne 0 ]; then
	echo "semantics-parity: FAILED" >&2
	exit 1
fi
echo "semantics-parity: OK"

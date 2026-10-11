#!/usr/bin/env bash
# dogfood-run.sh runs one dogfood suite filter and FAILS CLOSED when the
# filter matches no tests. A Makefile target that silently runs nothing is
# worse than a red suite: it claims coverage it does not have.
#
# Usage: scripts/dogfood-run.sh <timeout> <go-test -run regexp> [package...]
# Default package: ./internal/dogfood/...
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <timeout> <run-regexp> [package...]" >&2
  exit 2
fi
timeout="$1"
shift
run_re="$1"
shift
if [[ $# -gt 0 ]]; then
  packages=("$@")
else
  packages=(./internal/dogfood/...)
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

set +e
go test "${packages[@]}" -run "$run_re" -count=1 -timeout="$timeout" -v >"$out" 2>&1
status=$?
set -e

# Executed top-level tests only (subtests are === RUN   TestFoo/bar).
ran=0
while IFS= read -r line; do
  case "$line" in
    '=== RUN   Test'*/*) ;;
    '=== RUN   Test'*) ran=$((ran + 1)) ;;
  esac
done <"$out"

if [[ "$ran" -eq 0 ]]; then
  echo "dogfood-run: filter '$run_re' matched ZERO tests — refusing vacuous green" >&2
  echo "----- go test output -----" >&2
  cat "$out" >&2
  exit 1
fi

cat "$out"
if [[ "$status" -ne 0 ]]; then
  echo "dogfood-run: suite failed (filter '$run_re', $ran tests)" >&2
  exit "$status"
fi
echo "dogfood-run: ok ($ran tests, filter '$run_re')"

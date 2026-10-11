#!/usr/bin/env bash
# dogfood-run.sh runs one dogfood suite and FAILS CLOSED unless every
# REQUIRED test in the suite actually executed.
#
# The earlier "filter matched at least one test" check was too weak: a suite
# named TestDFUPGRADE|TestOther stayed green if TestDFUPGRADE vanished as
# long as TestOther still matched. A dogfood suite is a release contract, so
# each suite lists the tests it OWNS; missing any of them is a red suite.
#
# Usage:
#   scripts/dogfood-run.sh <timeout> --run <regexp> --require <TestName> [--require ...] \
#       [-- package...]
#
#   --run       go test -run regexp (what to execute)
#   --require   top-level test function name that MUST appear in the run
#               (repeatable). Matched as an exact `=== RUN   TestName` line
#               or as a prefix of one (so TestDFEVID001 requires every
#               TestDFEVID001* that ran, and is satisfied by at least one).
#   --          optional package list (default ./internal/dogfood/...)
#
# Exit codes: 0 all required tests ran and the suite passed; 1 suite failed
# or a required test was missing; 2 usage error.
set -euo pipefail

usage() {
  echo "usage: $0 <timeout> --run <regexp> --require <TestName> [--require ...] [-- package...]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
timeout="$1"
shift

run_re=""
required=()
packages=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      [[ $# -ge 2 ]] || usage
      run_re="$2"
      shift 2
      ;;
    --require)
      [[ $# -ge 2 ]] || usage
      required+=("$2")
      shift 2
      ;;
    --)
      shift
      packages=("$@")
      break
      ;;
    *)
      usage
      ;;
  esac
done

[[ -n "$run_re" ]] || usage
[[ ${#required[@]} -gt 0 ]] || usage
if [[ ${#packages[@]} -eq 0 ]]; then
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

# Collect executed top-level test names (=== RUN   TestFoo, not TestFoo/bar).
executed=()
while IFS= read -r line; do
  case "$line" in
    '=== RUN   Test'*/*) ;;
    '=== RUN   Test'*)
      name="${line#=== RUN   }"
      name="${name%%$'\t'*}"
      name="${name%% *}"
      executed+=("$name")
      ;;
  esac
done <"$out"

if [[ ${#executed[@]} -eq 0 ]]; then
  echo "dogfood-run: filter '$run_re' executed ZERO tests — refusing vacuous green" >&2
  echo "----- go test output -----" >&2
  cat "$out" >&2
  exit 1
fi

# Every required test must have executed AND not skipped. A prefix match
# counts (TestDFEVID001 is satisfied by TestDFEVID001GenerationAndVerify).
# A required test that only t.Skip'd is MISSING: "required present" means the
# body ran, not that Go emitted === RUN before skipping.
skipped=()
for req in "${required[@]}"; do
  # If every matching === RUN is followed by --- SKIP for that name, treat as missing.
  if grep -q "^--- SKIP: ${req}" "$out" && ! grep -q "^--- PASS: ${req}" "$out" && ! grep -q "^--- FAIL: ${req}" "$out"; then
    skipped+=("$req")
  fi
done

missing=()
for req in "${required[@]}"; do
  found=0
  for name in "${executed[@]}"; do
    if [[ "$name" == "$req" || "$name" == "$req"* ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    missing+=("$req")
  fi
done
for req in ${skipped[@]+"${skipped[@]}"}; do
  missing+=("$req")
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "dogfood-run: suite is NOT green — required test(s) did not execute (or skipped):" >&2
  for m in "${missing[@]}"; do
    echo "  MISSING  $m" >&2
  done
  echo "executed ${#executed[@]} top-level test(s) under filter '$run_re':" >&2
  for name in "${executed[@]}"; do
    echo "  ran      $name" >&2
  done
  echo "----- go test output -----" >&2
  cat "$out" >&2
  exit 1
fi

cat "$out"
if [[ "$status" -ne 0 ]]; then
  echo "dogfood-run: suite failed (filter '$run_re', ${#executed[@]} tests, ${#required[@]} required ok)" >&2
  exit "$status"
fi
echo "dogfood-run: ok (${#executed[@]} tests, ${#required[@]}/${#required[@]} required present, filter '$run_re')"

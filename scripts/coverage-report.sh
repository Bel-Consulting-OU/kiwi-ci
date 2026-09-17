#!/bin/sh
# coverage-report.sh prints per-package STATEMENT coverage from a Go
# coverage profile, plus the total. Usage: coverage-report.sh [profile]
set -eu
PROFILE="${1:-coverage.out}"
[ -f "$PROFILE" ] || { echo "coverage-report: $PROFILE not found (run: go test -coverprofile=$PROFILE ./...)" >&2; exit 1; }
awk -F'[: ,]' '
NR == 1 { next }
{
  file = $1
  stmts = $(NF - 1)
  count = $NF
  sub(/^github.com\/Bel-Consulting-OU\/kiwi-ci\//, "", file)
  n = split(file, a, "/")
  dir = ""
  for (i = 1; i < n; i++) dir = dir (i > 1 ? "/" : "") a[i]
  total[dir] += stmts
  if (count + 0 > 0) covered[dir] += stmts
  gtotal += stmts
  if (count + 0 > 0) gcovered += stmts
}
END {
  for (p in total) printf "%6.1f%%  %6d stmts  %s\n", 100*covered[p]/total[p], total[p], p
  printf "%6.1f%%  %6d stmts  TOTAL\n", 100*gcovered/gtotal, gtotal
}' "$PROFILE" | sort -n

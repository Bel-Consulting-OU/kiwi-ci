#!/bin/sh
# crash-matrix.sh — crash/reclaim lifecycle oracles as one entry point.
# Each case is a Go model test (deterministic, CI-safe). A future extension
# SIGKILLs a real runner; the model tests already cover the ledger contracts
# that made hand audits find orphaned native PIDs.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "crash-matrix: freeze authority"
go test ./internal/lifecycle -count=1 -timeout 60s

echo "crash-matrix: native mid-start / onStart rollback"
go test ./internal/executor -run 'TestLifecycleNative' -count=1 -timeout 60s

echo "crash-matrix: ledger reclaim"
go test ./internal/runner -run 'TestLifecycleCrashNativeReclaim' -count=1 -timeout 60s

echo "crash-matrix: OK"

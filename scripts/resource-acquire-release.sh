#!/bin/sh
# resource-acquire-release.sh — static tripwire for "acquire host resource
# without a release path" (the bug class behind transactional native
# startup). Coarse on purpose: proof lives in state-machine tests.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

require() {
	if ! grep -q "$1" "$2"; then
		echo "FAIL $2 missing /$1/" >&2
		fail=1
	fi
}

require 'releaseNativePort' internal/executor/services_native.go
require 'once.Do' internal/executor/services_native.go
require 'ledgerRemove' internal/runner/runtime_ledger.go
require 'ledgerSetNativeServices' internal/runner/runner.go

# Heuristic: functions that *call* claimNativePort (not define it) must
# also mention release/cleanup in the same body.
awk '
	/^func / { fn=$0; body=$0; grab=1; next }
	grab { body = body "\n" $0 }
	/^}/ {
		if (body ~ /claimNativePort\(/ && body !~ /func claimNativePort/ &&
		    body !~ /releaseNativePort|cleanup|once\.Do/) {
			print "claim without release in " fn
			bad = 1
		}
		grab=0; fn=""
	}
	END { exit bad+0 }
' internal/executor/services_native.go >"$ROOT/.kiwi-acquire.tmp" || true
if [ -s "$ROOT/.kiwi-acquire.tmp" ]; then
	while read -r line; do
		echo "FAIL $line" >&2
		fail=1
	done <"$ROOT/.kiwi-acquire.tmp"
fi
rm -f "$ROOT/.kiwi-acquire.tmp"

if [ "$fail" -ne 0 ]; then
	echo "resource-acquire-release: FAILED" >&2
	exit 1
fi
echo "resource-acquire-release: OK"

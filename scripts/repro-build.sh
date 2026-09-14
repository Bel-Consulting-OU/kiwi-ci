#!/bin/sh
# repro-build.sh verifies reproducible builds: two consecutive builds with
# fixed ldflags must produce byte-identical binaries.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
COMMIT="repro"
DATE="2026-01-01T00:00:00Z"
LDFLAGS="-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=0.1.0-repro \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=$COMMIT \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=$DATE \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=false"
go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /tmp/kiwi-repro-a ./cmd/kiwi
go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /tmp/kiwi-repro-b ./cmd/kiwi
if cmp -s /tmp/kiwi-repro-a /tmp/kiwi-repro-b; then
	echo "repro-build: identical binaries"
	rm -f /tmp/kiwi-repro-a /tmp/kiwi-repro-b
else
	echo "repro-build: binaries differ" >&2
	exit 1
fi

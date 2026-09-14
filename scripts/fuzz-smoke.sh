#!/bin/sh
# fuzz-smoke.sh runs every registered Go fuzz target for a bounded time and
# fails the build on any crash. Usage: fuzz-smoke.sh [duration] (default 10s).
set -eu
DURATION="${1:-10s}"
TARGETS="
internal/pipeline:FuzzYAML
internal/pipeline:FuzzConditionParser
internal/pipeline:FuzzPathGlob
internal/pipeline:FuzzPipelineValidation
internal/executor:FuzzOutputParser
internal/safefs:FuzzArtifactExtract
internal/safefs:FuzzCacheExtract
internal/testintel:FuzzJUnit
internal/server:FuzzWebhookGitHub
internal/server:FuzzWebhookGitLab
internal/server:FuzzWebhookForgejo
internal/forge:FuzzCanonicalRepository
internal/forge:FuzzCacheManifest
internal/forge:FuzzSnapshotManifest
internal/forge:FuzzProvenanceEnvelope
"
for entry in $TARGETS; do
	pkg="${entry%%:*}"
	target="${entry##*:}"
	echo "== fuzz $pkg/$target ($DURATION)"
	go test -run '^$' -fuzz "$target" -fuzztime "$DURATION" "./$pkg"
done
echo "fuzz smoke: all targets clean"

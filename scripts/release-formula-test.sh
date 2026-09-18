#!/bin/sh
# release-formula-test.sh proves Formula/kiwi.rb is rendered deterministically
# from Formula/kiwi.rb.tmpl across sequential releases. It renders v1.2.3 and
# then v2.0.0 over the same output file and checks each time that the version,
# both release URLs, and both SHA256 digests are exactly the new values, with
# no unsubstituted tokens and no leftovers from the previous rendering.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM
OUT="$TMP/kiwi.rb"

fail() {
	echo "release-formula-test: $*" >&2
	exit 1
}

check_render() {
	version="$1"
	arm64="$2"
	amd64="$3"
	sh "$ROOT/scripts/release.sh" --render-formula "$version" "$arm64" "$amd64" "$OUT" >/dev/null
	grep -q "version \"$version\"" "$OUT" || fail "version $version not set"
	grep -q "releases/download/v$version/kiwi-darwin-arm64" "$OUT" || fail "v$version arm64 url missing"
	grep -q "releases/download/v$version/kiwi-darwin-amd64" "$OUT" || fail "v$version amd64 url missing"
	grep -q "sha256 \"$arm64\"" "$OUT" || fail "v$version arm64 digest missing"
	grep -q "sha256 \"$amd64\"" "$OUT" || fail "v$version amd64 digest missing"
	if grep -q '__[A-Z][A-Z0-9_]*__' "$OUT"; then
		fail "v$version rendering left an unsubstituted token"
	fi
}

ARM64_V1=1111111111111111111111111111111111111111111111111111111111111111
AMD64_V1=2222222222222222222222222222222222222222222222222222222222222222
ARM64_V2=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
AMD64_V2=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

# First release.
check_render 1.2.3 "$ARM64_V1" "$AMD64_V1"

# Second release rendered over the already-rendered formula: no reliance on
# placeholders surviving in the output.
check_render 2.0.0 "$ARM64_V2" "$AMD64_V2"

if grep -q '1\.2\.3' "$OUT"; then
	fail "stale v1.2.3 text survived the v2.0.0 rendering"
fi
if grep -q "$ARM64_V1" "$OUT" || grep -q "$AMD64_V1" "$OUT"; then
	fail "stale v1 digests survived the v2.0.0 rendering"
fi

# A bad digest must fail closed rather than render an unverifiable formula.
if sh "$ROOT/scripts/release.sh" --render-formula 3.0.0 not-a-sha256 "$AMD64_V2" "$OUT" >/dev/null 2>&1; then
	fail "renderer accepted a non-SHA256 digest"
fi

echo "release-formula-test: v1.2.3 then v2.0.0 rendered correctly"

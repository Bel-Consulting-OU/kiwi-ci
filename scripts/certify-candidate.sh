#!/bin/sh
# certify-candidate.sh is the one release-certification chain:
#
#   commit C → build immutable candidate B → hash/sign B
#            → test B everywhere (dogfood + adversarial + N-1 + self-host)
#            → tag C → publish B unchanged
#
# There is no permitted path "test source tree → tag → later build binaries"
# and no path "test candidate A → publish rebuilt candidate B". Artifact
# identity is part of the proposition under verification.
#
# Usage:
#   scripts/certify-candidate.sh vX.Y.Z
#
# Env:
#   KIWI_N_MINUS_ONE_BIN / KIWI_N_MINUS_ONE_SHA256 / KIWI_N_MINUS_ONE_SUMS
#       published predecessor (see fetch-n-minus-one.sh)
#   KIWI_RELEASE_SIGNING_KEY   signs the candidate provenance
#   CANDIDATE_DIR              default dist/candidate
set -eu

die() {
	echo "certify-candidate: $*" >&2
	exit 1
}

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: certify-candidate.sh vX.Y.Z"
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "version must be vX.Y.Z, got '$VERSION'"

CANDIDATE_DIR="${CANDIDATE_DIR:-dist/candidate}"
export KIWI_CANDIDATE_DIR="$CANDIDATE_DIR"

echo "certify-candidate: 1/5 freeze candidate bytes"
rm -rf "$CANDIDATE_DIR"
./scripts/release.sh --candidate "$VERSION" ${KIWI_RELEASE_SIGNING_KEY:+--require-signing} ${KIWI_ALLOW_UNSIGNED_RELEASE:+--allow-unsigned}

# The frozen platform binary is the only binary the tests may use.
case "$(uname -s)-$(uname -m)" in
Darwin-arm64) PLAT="kiwi-darwin-arm64" ;;
Darwin-x86_64) PLAT="kiwi-darwin-amd64" ;;
Linux-aarch64|Linux-arm64) PLAT="kiwi-linux-arm64" ;;
Linux-x86_64|Linux-amd64) PLAT="kiwi-linux-amd64" ;;
*) die "unsupported host for candidate certification" ;;
esac
CAND_BIN="$CANDIDATE_DIR/$PLAT"
[ -f "$CAND_BIN" ] || die "candidate bundle missing $CAND_BIN"
CAND_SHA="$(awk -v n="$PLAT" '$2==n{print $1; exit}' "$CANDIDATE_DIR/SHA256SUMS")"
[ -n "$CAND_SHA" ] || die "candidate SHA256SUMS has no entry for $PLAT"
export KIWI_CANDIDATE_BIN="$CAND_BIN"
export KIWI_CANDIDATE_SHA256="$CAND_SHA"
export KIWI_CANDIDATE_FREEZE="$CANDIDATE_DIR/FREEZE"
export KIWI_CANDIDATE_PLATFORM="$PLAT"
echo "certify-candidate: frozen $PLAT sha256=$CAND_SHA"

echo "certify-candidate: 2/5 resolve published N-1"
./scripts/with-n-minus-one.sh true

echo "certify-candidate: 3/5 certify the FROZEN bytes (release-gate)"
./scripts/with-n-minus-one.sh make release-gate

echo "certify-candidate: 4/5 tag the frozen commit"
COMMIT="$(awk -F= '/^commit=/{print $2; exit}' "$CANDIDATE_DIR/FREEZE")"
[ -n "$COMMIT" ] || die "FREEZE is missing commit="
HEAD_SHA="$(git rev-parse HEAD)"
[ "$HEAD_SHA" = "$COMMIT" ] || die "HEAD $HEAD_SHA != frozen commit $COMMIT"
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
	git rev-list -n1 "$VERSION" | grep -q "^$COMMIT$" || die "tag $VERSION already points elsewhere"
	echo "certify-candidate: tag $VERSION already present at $COMMIT"
else
	git tag -a "$VERSION" -m "release $VERSION (certified frozen candidate $CAND_SHA)"
	echo "certify-candidate: tagged $VERSION at $COMMIT"
fi

echo "certify-candidate: 5/5 publish the SAME bytes (no rebuild)"
./scripts/release.sh --publish-frozen "$CANDIDATE_DIR" "$VERSION"

echo "certify-candidate: COMPLETE version=$VERSION commit=$COMMIT sha256=$CAND_SHA"

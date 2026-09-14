#!/bin/sh
# release.sh builds release binaries for every supported platform, hashes
# them (SHA256SUMS, sorted by filename), records per-binary `go version -m`
# build info, and emits per-binary CycloneDX SBOMs plus optional signed
# SLSA provenance via cmd/release-tool.
#
# Usage: scripts/release.sh [TAG] [--update-formula] [--allow-unsigned]
#
# Signing is mandatory by default (--require-signing is the implicit
# default): when KIWI_RELEASE_SIGNING_KEY is missing the script exits 1
# and nothing is published. The only escape hatch for an explicit
# disaster recovery run is --allow-unsigned or KIWI_ALLOW_UNSIGNED_RELEASE=1.
#
# Inputs (env):
#   VERSION                       release version override (default: TAG
#                                 with a leading "v" stripped, or the
#                                 checked-out git tag)
#   KIWI_RELEASE_SIGNING_KEY      Ed25519 PKCS#8 private key PEM, or a path
#                                 to a PEM file. Required unless
#                                 --allow-unsigned / KIWI_ALLOW_UNSIGNED_RELEASE=1.
#   KIWI_ALLOW_UNSIGNED_RELEASE   set to 1 to permit an unsigned release
#                                 (disaster recovery only).
#   REPO                          repository URL override (default: origin)
#   COMMIT / BUILD_DATE / DIRTY   build identity overrides (defaults: git)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAG=""
UPDATE_FORMULA=""
ALLOW_UNSIGNED=""
for arg in "$@"; do
	case "$arg" in
	--update-formula) UPDATE_FORMULA=1 ;;
	--require-signing) ALLOW_UNSIGNED="" ;;
	--allow-unsigned) ALLOW_UNSIGNED=1 ;;
	*) TAG="$arg" ;;
	esac
done

if [ -z "$TAG" ]; then
	TAG="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
	[ -n "$TAG" ] || TAG="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
fi
[ -n "$TAG" ] || TAG="v0.0.0"

VERSION="${VERSION:-${TAG#v}}"
[ -n "$VERSION" ] || VERSION="0.0.0"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIRTY="${DIRTY:-$(test -z "$(git status --porcelain 2>/dev/null)" && echo false || echo true)}"
REPO="${REPO:-$(git remote get-url origin 2>/dev/null | sed 's/\.git$//' || true)}"
[ -n "$REPO" ] || REPO="https://github.com/Bel-Consulting-OU/kiwi-ci"

# Signed releases are mandatory (fail closed). Refuse to build or publish
# anything when the signing key is missing, unless the caller explicitly
# opted into an unsigned disaster release via --allow-unsigned or
# KIWI_ALLOW_UNSIGNED_RELEASE=1.
if [ -z "${KIWI_RELEASE_SIGNING_KEY:-}" ] && [ "${ALLOW_UNSIGNED:-}" != "1" ] && [ "${KIWI_ALLOW_UNSIGNED_RELEASE:-}" != "1" ]; then
	echo "release: KIWI_RELEASE_SIGNING_KEY is not set; unsigned releases are not allowed." >&2
	echo "release: refusing to publish an unsigned release. Set the Ed25519" >&2
	echo "release: PKCS#8 PEM via KIWI_RELEASE_SIGNING_KEY, or pass" >&2
	echo "release: --allow-unsigned (or KIWI_ALLOW_UNSIGNED_RELEASE=1) only" >&2
	echo "release: for an explicit disaster recovery release." >&2
	exit 1
fi

LDFLAGS="-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=$VERSION \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=$COMMIT \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=$BUILD_DATE \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=$DIRTY"

OUT="dist/release"
rm -rf "$OUT"
mkdir -p "$OUT"

TMP_DIR="$(mktemp -d)"
TMP_KEY=""
cleanup() {
	rm -rf "$TMP_DIR"
	[ -n "$TMP_KEY" ] && rm -f "$TMP_KEY"
}
trap cleanup EXIT INT TERM

build_one() {
	goos="$1"
	goarch="$2"
	name="$3"
	GOOS="$goos" GOARCH="$goarch" go build -trimpath -buildvcs=false \
		-ldflags "$LDFLAGS" -o "$OUT/$name" ./cmd/kiwi
	go version -m "$OUT/$name" >"$OUT/$name.buildinfo.txt"
	echo "release: built $name"
}

build_one darwin arm64 kiwi-darwin-arm64
build_one darwin amd64 kiwi-darwin-amd64
build_one linux arm64 kiwi-linux-arm64
build_one linux amd64 kiwi-linux-amd64
build_one windows amd64 kiwi-windows-amd64.exe

go build -o "$TMP_DIR/release-tool" ./cmd/release-tool

if [ -n "${KIWI_RELEASE_SIGNING_KEY:-}" ]; then
	if [ -f "$KIWI_RELEASE_SIGNING_KEY" ]; then
		KEY_FILE="$KIWI_RELEASE_SIGNING_KEY"
	else
		TMP_KEY="$TMP_DIR/release-signing-key.pem"
		printf '%s\n' "$KIWI_RELEASE_SIGNING_KEY" >"$TMP_KEY"
		chmod 600 "$TMP_KEY"
		KEY_FILE="$TMP_KEY"
	fi
else
	KEY_FILE=""
	echo "release: proceeding WITHOUT provenance signing (unsigned disaster release)" >&2
fi

for name in kiwi-darwin-arm64 kiwi-darwin-amd64 kiwi-linux-arm64 kiwi-linux-amd64 kiwi-windows-amd64.exe; do
	set -- -binary "$OUT/$name" -name kiwi -version "$VERSION" -commit "$COMMIT" \
		-repo "$REPO" -ref "$TAG" -out "$OUT"
	[ -n "$KEY_FILE" ] && set -- "$@" -key "$KEY_FILE"
	"$TMP_DIR/release-tool" "$@"
done

if command -v sha256sum >/dev/null 2>&1; then
	hash_cmd() { sha256sum "$1"; }
else
	hash_cmd() { shasum -a 256 "$1"; }
fi
(
	cd "$OUT"
	: >SHA256SUMS
	for f in *; do
		[ "$f" = "SHA256SUMS" ] && continue
		hash_cmd "$f"
	done | LC_ALL=C sort -k2 >SHA256SUMS
)

echo "release: bundle at $OUT"
echo "release: version=$VERSION tag=$TAG commit=$COMMIT"

DARWIN_ARM64_SHA="$(awk '$2 == "kiwi-darwin-arm64" {print $1}' "$OUT/SHA256SUMS")"
DARWIN_AMD64_SHA="$(awk '$2 == "kiwi-darwin-amd64" {print $1}' "$OUT/SHA256SUMS")"
echo "release: Homebrew sha256 darwin/arm64: $DARWIN_ARM64_SHA"
echo "release: Homebrew sha256 darwin/amd64: $DARWIN_AMD64_SHA"

if [ "$UPDATE_FORMULA" = "1" ]; then
	FORMULA="Formula/kiwi.rb"
	TMP_FORMULA="$TMP_DIR/kiwi.rb"
	sed -e "s/PLACEHOLDER-DARWIN-ARM64-SHA256/$DARWIN_ARM64_SHA/" \
		-e "s/PLACEHOLDER-DARWIN-AMD64-SHA256/$DARWIN_AMD64_SHA/" \
		"$FORMULA" >"$TMP_FORMULA"
	mv "$TMP_FORMULA" "$FORMULA"
	echo "release: updated Homebrew formula sha256 entries in $FORMULA"
fi

#!/bin/sh
# release.sh builds Kiwi CI release or snapshot binaries, hashes them
# (SHA256SUMS, sorted by filename), records per-binary `go version -m` build
# info, and emits per-binary CycloneDX SBOMs plus optional signed SLSA
# provenance via cmd/release-tool.
#
# Modes:
#   release (default)  fail-closed release build. Requires ALL of:
#                        * HEAD is an exact semver tag (vX.Y.Z)
#                        * VERSION (if set) equals the tag without "v"
#                        * the tag points at HEAD and HEAD is the tagged commit
#                        * the working tree is clean
#                        * the recorded commit is the FULL 40-char lowercase SHA
#                        * the Ed25519 signing key is present (unless the caller
#                          explicitly opts into an unsigned disaster release)
#                      The tag is never inferred from a branch name. On
#                      success Formula/kiwi.rb is re-rendered from
#                      Formula/kiwi.rb.tmpl.
#   --snapshot         branch/dirty development build. Records the short SHA
#                      and a "-snapshot+<shortsha>" version suffix, labels the
#                      bundle with a SNAPSHOT marker, never touches
#                      Formula/kiwi.rb, and does not require a signing key.
#   --render-formula   internal helper used by scripts/release-formula-test.sh:
#                      renders Formula/kiwi.rb.tmpl deterministically.
#
# Usage:
#   scripts/release.sh [vX.Y.Z] [--allow-unsigned] [--require-signing]
#   scripts/release.sh --snapshot [--allow-unsigned]
#   scripts/release.sh --render-formula VERSION SHA_DARWIN_ARM64 SHA_DARWIN_AMD64 [OUT]
#
# Signing policy: releases are signed by default. --allow-unsigned is the
# explicit opt-out; KIWI_ALLOW_UNSIGNED_RELEASE=1 is only the default policy.
# An explicit --require-signing wins over both and cannot be neutralized by
# the environment variable. When both flags are given, the last one wins.
# --require-signing applies to release builds only: snapshots are never signed,
# so it is rejected with a usage error for --snapshot. --allow-unsigned is
# accepted and ignored for snapshots.
#
# Inputs (env):
#   VERSION                       release version override; in release mode it
#                                 must exactly match the tag without the "v"
#   KIWI_RELEASE_SIGNING_KEY      Ed25519 PKCS#8 private key PEM, or a path
#                                 to a PEM file. Required in release mode
#                                 unless --allow-unsigned /
#                                 KIWI_ALLOW_UNSIGNED_RELEASE=1. Optional in
#                                 snapshot mode.
#   KIWI_ALLOW_UNSIGNED_RELEASE   set to 1 to permit an unsigned release
#                                 (disaster recovery only) unless an explicit
#                                 --require-signing was given, which always
#                                 wins.
#   SOURCE_DATE_EPOCH             reproducible-build epoch. In release mode it
#                                 defaults to the tagged commit's committer
#                                 date (`git log -1 --format=%ct <tag>`); in
#                                 snapshot mode it defaults to the current
#                                 time. It only pins the recorded BuildDate
#                                 (artifact bytes); provenance and SBOM
#                                 timestamps stay truthful.
#   BUILD_DATE                    explicit RFC3339 UTC BuildDate override
#                                 (YYYY-MM-DDTHH:MM:SSZ). Any other value is
#                                 rejected before the build.
#   COMMIT / REF                  build identity overrides. In release mode
#                                 COMMIT must be the full 40-char SHA of the
#                                 tagged commit.
#   REPO                          repository URL override (default: origin)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() {
	echo "release: $*" >&2
	exit 1
}

usage() {
	echo "release: $*" >&2
	exit 2
}

require_sha256() {
	value="$1"
	label="$2"
	case "$value" in
	"" | *[!0-9a-f]*)
		die "$label is not a lowercase hex SHA256: '$value'"
		;;
	esac
	if [ "${#value}" -ne 64 ]; then
		die "$label is not a 64-char SHA256: '$value'"
	fi
}

# require_rfc3339 verifies that a caller-supplied timestamp is exactly the
# RFC3339 UTC form emitted by epoch_to_rfc3339 (YYYY-MM-DDTHH:MM:SSZ). The
# case guard rejects characters outside the allowed set first -- including
# whitespace and newlines -- so a multi-line value cannot pass on a matching
# first line and then be whitespace-split by cmd/go into extra linker flags.
require_rfc3339() {
	value="$1"
	label="$2"
	case "$value" in
	*[!0-9TZ:.-]*)
		die "$label must be an RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ), got '$value'"
		;;
	esac
	if ! printf '%s\n' "$value" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'; then
		die "$label must be an RFC3339 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ), got '$value'"
	fi
}

# render_formula writes a complete Formula/kiwi.rb from Formula/kiwi.rb.tmpl.
# It always re-reads the template, so rendering over an already-rendered file
# is safe and independent of any prior placeholder state.
render_formula() {
	version="$1"
	arm64_sha="$2"
	amd64_sha="$3"
	out="${4:-Formula/kiwi.rb}"
	tmpl="Formula/kiwi.rb.tmpl"
	[ -f "$tmpl" ] || die "formula template $tmpl is missing"
	[ -n "$version" ] || die "formula version is empty"
	case "$version" in
	*__*) die "formula version '$version' contains a template token" ;;
	esac
	require_sha256 "$arm64_sha" "darwin/arm64 digest"
	require_sha256 "$amd64_sha" "darwin/amd64 digest"
	tmp="$out.tmp.$$"
	if ! sed -e "s|__VERSION__|$version|g" \
		-e "s|__SHA_DARWIN_ARM64__|$arm64_sha|g" \
		-e "s|__SHA_DARWIN_AMD64__|$amd64_sha|g" \
		"$tmpl" >"$tmp"; then
		rm -f "$tmp"
		die "failed to render $out from $tmpl"
	fi
	if grep -q '__[A-Z][A-Z0-9_]*__' "$tmp"; then
		rm -f "$tmp"
		die "formula rendering left unsubstituted tokens; update $tmpl"
	fi
	if ! mv "$tmp" "$out"; then
		rm -f "$tmp"
		die "failed to replace $out"
	fi
	echo "release: rendered $out for version $version"
}

# epoch_to_rfc3339 converts seconds since the Unix epoch to an RFC3339 UTC
# timestamp, supporting both BSD (macOS) and GNU date.
epoch_to_rfc3339() {
	epoch="$1"
	case "$epoch" in
	"" | *[!0-9]*)
		die "SOURCE_DATE_EPOCH must be a non-negative integer, got '$epoch'"
		;;
	esac
	if out="$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" && [ -n "$out" ]; then
		printf '%s' "$out"
		return 0
	fi
	if out="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" && [ -n "$out" ]; then
		printf '%s' "$out"
		return 0
	fi
	die "cannot convert SOURCE_DATE_EPOCH '$epoch' with this date(1)"
}

if [ "${1:-}" = "--render-formula" ]; then
	[ "$#" -ge 4 ] && [ "$#" -le 5 ] || usage "usage: release.sh --render-formula VERSION SHA_DARWIN_ARM64 SHA_DARWIN_AMD64 [OUT]"
	render_formula "$2" "$3" "$4" "${5:-Formula/kiwi.rb}"
	exit 0
fi

SNAPSHOT=""
SIGNING_POLICY=""
TAG_ARG=""
for arg in "$@"; do
	case "$arg" in
	--snapshot) SNAPSHOT=1 ;;
	--require-signing) SIGNING_POLICY=require ;;
	--allow-unsigned) SIGNING_POLICY=allow ;;
	-*) usage "unknown option '$arg'" ;;
	*)
		[ -z "$TAG_ARG" ] || usage "multiple tags given: '$TAG_ARG' and '$arg'"
		TAG_ARG="$arg"
		;;
	esac
done

if [ "$SNAPSHOT" = "1" ] && [ -n "$TAG_ARG" ]; then
	usage "--snapshot cannot be combined with a release tag ('$TAG_ARG')"
fi

# Snapshots are never signed (no key is ever used for them), so an explicit
# --require-signing has no meaning and must not appear to be honored. Fail
# closed here, at argument parsing, before any git or build work happens.
if [ "$SNAPSHOT" = "1" ] && [ "$SIGNING_POLICY" = "require" ]; then
	usage "--require-signing applies to release builds only; snapshots are never signed, so drop --require-signing"
fi

REPO="${REPO:-$(git remote get-url origin 2>/dev/null | sed 's/\.git$//' || true)}"
[ -n "$REPO" ] || REPO="https://github.com/Bel-Consulting-OU/kiwi-ci"

if [ "$SNAPSHOT" = "1" ]; then
	SHORT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
		DIRTY=false
	else
		DIRTY=true
	fi
	BRANCH="$(git symbolic-ref --short -q HEAD 2>/dev/null || echo detached)"
	BASE_VERSION="${VERSION:-0.1.0-dev}"
	VERSION="${BASE_VERSION}-snapshot+${SHORT_SHA}"
	if [ "$DIRTY" = "true" ]; then
		VERSION="${VERSION}.dirty"
	fi
	COMMIT="${COMMIT:-$SHORT_SHA}"
	case "$COMMIT" in
	"" | *[!0-9a-f]*) die "snapshot COMMIT '$COMMIT' is not lowercase hex" ;;
	esac
	REF="${REF:-$BRANCH}"
	TAG="$REF"
	OUT="dist/snapshot"
	if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
		BUILD_DATE="$(epoch_to_rfc3339 "$SOURCE_DATE_EPOCH")"
	else
		BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
		require_rfc3339 "$BUILD_DATE" "BUILD_DATE"
	fi
	echo "release: SNAPSHOT build (NOT a release): version=$VERSION commit=$COMMIT ref=$REF dirty=$DIRTY"
else
	git rev-parse --git-dir >/dev/null 2>&1 || die "not a git checkout; releases require git metadata"
	EXACT_TAG="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
	[ -n "$EXACT_TAG" ] || die "HEAD is not an exact tag; releases must be cut from a tagged commit (use --snapshot for branch/dirty development builds)"
	if [ -n "$TAG_ARG" ]; then
		[ "$TAG_ARG" = "$EXACT_TAG" ] || die "tag '$TAG_ARG' is not the exact tag at HEAD ('$EXACT_TAG')"
	fi
	TAG="$EXACT_TAG"
	if ! printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
		die "tag '$TAG' is not an exact semver release tag (want vX.Y.Z)"
	fi
	HEAD_SHA="$(git rev-parse HEAD)"
	case "$HEAD_SHA" in
	*[!0-9a-f]*) die "HEAD SHA '$HEAD_SHA' is not lowercase hex" ;;
	esac
	if [ "${#HEAD_SHA}" -ne 40 ]; then
		die "HEAD SHA '$HEAD_SHA' is not a full 40-char SHA"
	fi
	TAG_SHA="$(git rev-list -n1 "$TAG")"
	[ "$TAG_SHA" = "$HEAD_SHA" ] || die "tag $TAG points at $TAG_SHA, not HEAD ($HEAD_SHA)"
	if [ -n "$(git status --porcelain)" ]; then
		die "working tree is dirty; commit or stash changes before releasing (use --snapshot for dirty builds)"
	fi
	WANT_VERSION="${TAG#v}"
	if [ -n "${VERSION:-}" ] && [ "$VERSION" != "$WANT_VERSION" ]; then
		die "VERSION '$VERSION' does not match tag '$TAG' (want '$WANT_VERSION')"
	fi
	VERSION="$WANT_VERSION"
	if [ -n "${COMMIT:-}" ]; then
		if ! printf '%s\n' "$COMMIT" | grep -Eq '^[0-9a-f]{40}$'; then
			die "COMMIT '$COMMIT' is not a full 40-char lowercase SHA"
		fi
		[ "$COMMIT" = "$HEAD_SHA" ] || die "COMMIT '$COMMIT' does not match the tagged commit $HEAD_SHA"
	fi
	COMMIT="$HEAD_SHA"
	DIRTY=false
	if [ -n "${BUILD_DATE:-}" ]; then
		require_rfc3339 "$BUILD_DATE" "BUILD_DATE"
	elif [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
		BUILD_DATE="$(epoch_to_rfc3339 "$SOURCE_DATE_EPOCH")"
	else
		SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$TAG")"
		BUILD_DATE="$(epoch_to_rfc3339 "$SOURCE_DATE_EPOCH")"
	fi
	echo "release: RELEASE build: version=$VERSION tag=$TAG commit=$COMMIT source_date_epoch=${SOURCE_DATE_EPOCH:-unset}"

	# Signed releases are mandatory (fail closed). Refuse to build or publish
	# anything when the signing key is missing. An explicit --require-signing
	# wins over KIWI_ALLOW_UNSIGNED_RELEASE=1: the environment variable is only
	# the default policy and never overrides the command line.
	if [ -z "${KIWI_RELEASE_SIGNING_KEY:-}" ]; then
		case "$SIGNING_POLICY" in
		allow) ;;
		require)
			die "KIWI_RELEASE_SIGNING_KEY is not set and --require-signing was given; refusing to publish an unsigned release. Set the Ed25519 PKCS#8 PEM (or a path to it), or drop --require-signing."
			;;
		*)
			[ "${KIWI_ALLOW_UNSIGNED_RELEASE:-}" = "1" ] || die "KIWI_RELEASE_SIGNING_KEY is not set; refusing to publish an unsigned release. Set the Ed25519 PKCS#8 PEM (or a path to it), or pass --allow-unsigned / KIWI_ALLOW_UNSIGNED_RELEASE=1 only for an explicit disaster recovery release."
			;;
		esac
	fi
fi

LDFLAGS="-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=$VERSION \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=$COMMIT \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.BuildDate=$BUILD_DATE \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=$DIRTY"

OUT="${OUT:-dist/release}"
rm -rf "$OUT"
mkdir -p "$OUT"

TMP_DIR="$(mktemp -d)"
TMP_KEY=""
cleanup() {
	rm -rf "$TMP_DIR"
	if [ -n "$TMP_KEY" ]; then
		rm -f "$TMP_KEY"
	fi
	return 0
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

go build -trimpath -buildvcs=false \
	-ldflags "-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Version=$VERSION \
-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=$COMMIT" \
	-o "$TMP_DIR/release-tool" ./cmd/release-tool

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
	if [ "$SNAPSHOT" = "1" ]; then
		echo "release: snapshot build WITHOUT provenance signing (no KIWI_RELEASE_SIGNING_KEY)" >&2
	else
		echo "release: proceeding WITHOUT provenance signing (unsigned disaster release)" >&2
	fi
fi

for name in kiwi-darwin-arm64 kiwi-darwin-amd64 kiwi-linux-arm64 kiwi-linux-amd64 kiwi-windows-amd64.exe; do
	set -- -binary "$OUT/$name" -name kiwi -version "$VERSION" -commit "$COMMIT" \
		-repo "$REPO" -ref "$TAG" -out "$OUT"
	if [ -n "$KEY_FILE" ]; then
		set -- "$@" -key "$KEY_FILE"
	fi
	"$TMP_DIR/release-tool" "$@"
done

if [ "$SNAPSHOT" = "1" ]; then
	{
		echo "SNAPSHOT build, not a release."
		echo "version=$VERSION"
		echo "commit=$COMMIT"
		echo "ref=$REF"
	} >"$OUT/SNAPSHOT"
fi

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

if [ "$SNAPSHOT" = "1" ]; then
	echo "release: snapshot bundle labeled $OUT/SNAPSHOT; Homebrew formula untouched"
else
	DARWIN_ARM64_SHA="$(awk '$2 == "kiwi-darwin-arm64" {print $1}' "$OUT/SHA256SUMS")"
	DARWIN_AMD64_SHA="$(awk '$2 == "kiwi-darwin-amd64" {print $1}' "$OUT/SHA256SUMS")"
	[ -n "$DARWIN_ARM64_SHA" ] || die "missing kiwi-darwin-arm64 digest in $OUT/SHA256SUMS"
	[ -n "$DARWIN_AMD64_SHA" ] || die "missing kiwi-darwin-amd64 digest in $OUT/SHA256SUMS"
	echo "release: Homebrew sha256 darwin/arm64: $DARWIN_ARM64_SHA"
	echo "release: Homebrew sha256 darwin/amd64: $DARWIN_AMD64_SHA"
	render_formula "$VERSION" "$DARWIN_ARM64_SHA" "$DARWIN_AMD64_SHA" "Formula/kiwi.rb"
fi

#!/bin/sh
# fetch-n-minus-one.sh resolves the PUBLISHED previous-release binary for
# release certification and exports KIWI_N_MINUS_ONE_BIN /
# KIWI_N_MINUS_ONE_SHA256 so dogfood-release-artifacts cannot fall back to a
# source rebuild.
#
# Resolution order:
#   1. KIWI_N_MINUS_ONE_BIN (already supplied) + optional KIWI_N_MINUS_ONE_SHA256
#   2. KIWI_N_MINUS_ONE_URL + KIWI_N_MINUS_ONE_SHA256 (download + verify)
#   3. GitHub Releases latest asset (download + verify against SHA256SUMS)
#
# Fail-closed: a missing or unverifiable artifact is fatal. Source rebuild is
# never performed here.
set -eu

die() {
	echo "fetch-n-minus-one: $*" >&2
	exit 1
}

require_sha256() {
	value="$1"
	label="$2"
	case "$value" in
	"" | *[!0-9a-f]*) die "$label is not a lowercase hex SHA256: '$value'" ;;
	esac
	[ "${#value}" -eq 64 ] || die "$label is not a 64-char SHA256: '$value'"
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

export KIWI_REQUIRE_RELEASED_N_MINUS_ONE="${KIWI_REQUIRE_RELEASED_N_MINUS_ONE:-1}"

CACHE="${KIWI_N_MINUS_ONE_CACHE:-${TMPDIR:-/tmp}/kiwi-n-minus-one}"
mkdir -p "$CACHE"

# write_env records the resolved pin so the caller (Make, CI) can source it
# after this script exits. Every success path must call it — a computed
# SHA256 that only lives in this process is a silent empty pin downstream.
write_env() {
	[ -n "${KIWI_N_MINUS_ONE_BIN:-}" ] || die "write_env: KIWI_N_MINUS_ONE_BIN unset"
	[ -n "${KIWI_N_MINUS_ONE_SHA256:-}" ] || die "write_env: KIWI_N_MINUS_ONE_SHA256 unset"
	require_sha256 "$KIWI_N_MINUS_ONE_SHA256" "KIWI_N_MINUS_ONE_SHA256"
	{
		echo "KIWI_N_MINUS_ONE_BIN=$KIWI_N_MINUS_ONE_BIN"
		echo "KIWI_N_MINUS_ONE_SHA256=$KIWI_N_MINUS_ONE_SHA256"
		echo "KIWI_REQUIRE_RELEASED_N_MINUS_ONE=1"
	} >"$CACHE/n-minus-one.env"
	echo "fetch-n-minus-one: env file $CACHE/n-minus-one.env"
}

if [ -n "${KIWI_N_MINUS_ONE_BIN:-}" ]; then
	[ -f "$KIWI_N_MINUS_ONE_BIN" ] || die "KIWI_N_MINUS_ONE_BIN '$KIWI_N_MINUS_ONE_BIN' is not a readable file"
	if [ -n "${KIWI_N_MINUS_ONE_SHA256:-}" ]; then
		require_sha256 "$KIWI_N_MINUS_ONE_SHA256" "KIWI_N_MINUS_ONE_SHA256"
		got="$(sha256_of "$KIWI_N_MINUS_ONE_BIN")"
		[ "$got" = "$KIWI_N_MINUS_ONE_SHA256" ] || die "supplied N-1 sha256 $got != pinned $KIWI_N_MINUS_ONE_SHA256"
	elif [ "${KIWI_REQUIRE_RELEASED_N_MINUS_ONE:-}" = "1" ]; then
		export KIWI_N_MINUS_ONE_SHA256="$(sha256_of "$KIWI_N_MINUS_ONE_BIN")"
	fi
	export KIWI_N_MINUS_ONE_BIN
	echo "fetch-n-minus-one: using supplied $KIWI_N_MINUS_ONE_BIN sha256=${KIWI_N_MINUS_ONE_SHA256:-unset}"
	write_env
	exit 0
fi

if [ -n "${KIWI_N_MINUS_ONE_URL:-}" ]; then
	[ -n "${KIWI_N_MINUS_ONE_SHA256:-}" ] || die "KIWI_N_MINUS_ONE_URL requires KIWI_N_MINUS_ONE_SHA256"
	require_sha256 "$KIWI_N_MINUS_ONE_SHA256" "KIWI_N_MINUS_ONE_SHA256"
	out="$CACHE/kiwi-n1-$(echo "$KIWI_N_MINUS_ONE_SHA256" | cut -c1-16)"
	if [ ! -f "$out" ]; then
		tmp="$out.tmp.$$"
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL -o "$tmp" "$KIWI_N_MINUS_ONE_URL" || die "download $KIWI_N_MINUS_ONE_URL failed"
		else
			die "curl is required to fetch $KIWI_N_MINUS_ONE_URL"
		fi
		got="$(sha256_of "$tmp")"
		[ "$got" = "$KIWI_N_MINUS_ONE_SHA256" ] || {
			rm -f "$tmp"
			die "downloaded N-1 sha256 $got != pinned $KIWI_N_MINUS_ONE_SHA256"
		}
		mv "$tmp" "$out"
		chmod 755 "$out"
	fi
	export KIWI_N_MINUS_ONE_BIN="$out"
	export KIWI_N_MINUS_ONE_SHA256
	echo "fetch-n-minus-one: fetched $KIWI_N_MINUS_ONE_URL -> $out"
	write_env
	exit 0
fi

REPO_SLUG="${KIWI_GITHUB_REPOSITORY:-Bel-Consulting-OU/kiwi-ci}"
API="${KIWI_GITHUB_API:-https://api.github.com}"
command -v curl >/dev/null 2>&1 || die "curl is required to auto-fetch the published N-1"
command -v python3 >/dev/null 2>&1 || die "python3 is required to parse GitHub release assets"

AUTH_HEADER=""
if [ -n "${GITHUB_TOKEN:-}" ]; then
	AUTH_HEADER="Authorization: Bearer $GITHUB_TOKEN"
elif [ -n "${GH_TOKEN:-}" ]; then
	AUTH_HEADER="Authorization: Bearer $GH_TOKEN"
fi

api_get() {
	url="$1"
	if [ -n "$AUTH_HEADER" ]; then
		curl -fsSL -H "$AUTH_HEADER" -H "Accept: application/vnd.github+json" "$url"
	else
		curl -fsSL -H "Accept: application/vnd.github+json" "$url"
	fi
}

latest_json="$CACHE/latest-release.json"
if ! api_get "$API/repos/$REPO_SLUG/releases/latest" >"$latest_json.tmp" 2>/dev/null; then
	rm -f "$latest_json.tmp"
	die "no published release found for $REPO_SLUG (set KIWI_N_MINUS_ONE_BIN/KIWI_N_MINUS_ONE_SHA256 or KIWI_N_MINUS_ONE_URL; source rebuild is not release certification)"
fi
mv "$latest_json.tmp" "$latest_json"

platform="linux-amd64"
case "$(uname -s)-$(uname -m)" in
Darwin-arm64) platform="darwin-arm64" ;;
Darwin-x86_64) platform="darwin-amd64" ;;
Linux-aarch64|Linux-arm64) platform="linux-arm64" ;;
Linux-x86_64|Linux-amd64) platform="linux-amd64" ;;
esac
BIN_NAME="kiwi-$platform"

pairs="$CACHE/asset-pairs.txt"
python3 - "$latest_json" >"$pairs" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1]))
for a in doc.get("assets") or []:
    name=a.get("name") or ""
    url=a.get("browser_download_url") or ""
    if name and url:
        print(name+"\t"+url)
PY

SUMS_URL="$(awk -F'\t' '$1=="SHA256SUMS"{print $2; exit}' "$pairs")"
BIN_URL="$(awk -F'\t' -v n="$BIN_NAME" '$1==n{print $2; exit}' "$pairs")"
[ -n "$BIN_URL" ] || die "published release has no asset named $BIN_NAME"
[ -n "$SUMS_URL" ] || die "published release has no SHA256SUMS asset"

sums="$CACHE/SHA256SUMS"
curl -fsSL -o "$sums" "$SUMS_URL" || die "download SHA256SUMS failed"
want="$(awk -v n="$BIN_NAME" '$2==n{print $1; exit}' "$sums")"
[ -n "$want" ] || die "SHA256SUMS does not list $BIN_NAME"
require_sha256 "$want" "published digest for $BIN_NAME"

out="$CACHE/$BIN_NAME-$want"
if [ ! -f "$out" ]; then
	tmp="$out.tmp.$$"
	curl -fsSL -o "$tmp" "$BIN_URL" || die "download $BIN_URL failed"
	got="$(sha256_of "$tmp")"
	[ "$got" = "$want" ] || {
		rm -f "$tmp"
		die "downloaded $BIN_NAME sha256 $got != published $want"
	}
	mv "$tmp" "$out"
	chmod 755 "$out"
fi

export KIWI_N_MINUS_ONE_BIN="$out"
export KIWI_N_MINUS_ONE_SHA256="$want"
echo "fetch-n-minus-one: published $BIN_NAME sha256=$want -> $out"
write_env

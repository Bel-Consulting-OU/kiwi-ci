#!/bin/sh
# release-store.sh is the PUBLISHED artifact store the N-1 upgrade chain
# consumes. A release is not "published" until its bytes live here, hashed
# in a SHA256SUMS the store itself generated — that digest is the
# INDEPENDENT metadata fetch-n-minus-one.sh verifies against. Computing the
# hash of a file someone handed you proves nothing about its provenance.
#
# Layout:
#   <store>/<version>/
#     kiwi-<os>-<arch>[.exe]
#     SHA256SUMS          (generated here; the trust anchor)
#     RELEASE             (version= / commit= / published_at=)
#
# Usage:
#   scripts/release-store.sh publish <store> <version> <commit> <bin>...
#   scripts/release-store.sh verify  <store> <version>
#   scripts/release-store.sh resolve <store> <platform>   # prints bin + sha
#   scripts/release-store.sh list    <store>
set -eu

die() {
	echo "release-store: $*" >&2
	exit 1
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

require_sha256() {
	value="$1"
	case "$value" in
	"" | *[!0-9a-f]*) die "not a lowercase hex SHA256: '$value'" ;;
	esac
	[ "${#value}" -eq 64 ] || die "not a 64-char SHA256: '$value'"
}

cmd="${1:-}"
shift || true

case "$cmd" in
publish)
	store="${1:-}"; version="${2:-}"; commit="${3:-}"
	shift 3 2>/dev/null || die "usage: release-store.sh publish <store> <version> <commit> <bin>..."
	[ -n "$store" ] || die "store is required"
	[ -n "$version" ] || die "version is required"
	[ -n "$commit" ] || die "commit is required"
	[ "$#" -ge 1 ] || die "at least one binary is required"
	case "$version" in
	v*) ;;
	*) die "version must look like v1.2.3, got '$version'" ;;
	esac
	case "$commit" in
	"" | *[!0-9a-f]*) die "commit must be lowercase hex" ;;
	esac
	[ "${#commit}" -eq 40 ] || die "commit must be a full 40-char SHA"
	dir="$store/$version"
	rm -rf "$dir"
	mkdir -p "$dir"
	for bin in "$@"; do
		[ -f "$bin" ] || die "binary '$bin' is not a readable file"
		cp -p "$bin" "$dir/$(basename "$bin")"
	done
	# The store generates SHA256SUMS over the binaries it holds. This is
	# the independent digest an N-1 resolver verifies against.
	(
		cd "$dir"
		: >SHA256SUMS.unsorted
		for f in *; do
			case "$f" in
			SHA256SUMS|SHA256SUMS.unsorted|RELEASE) continue ;;
			esac
			[ -f "$f" ] || continue
			printf '%s  %s\n' "$(sha256_of "$f")" "$f" >>SHA256SUMS.unsorted
		done
		LC_ALL=C sort -k2 SHA256SUMS.unsorted >SHA256SUMS
		rm -f SHA256SUMS.unsorted
	)
	{
		echo "version=$version"
		echo "commit=$commit"
		echo "published_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$dir/RELEASE"
	echo "release-store: published $version at $dir"
	;;
verify)
	store="${1:-}"; version="${2:-}"
	[ -n "$store" ] && [ -n "$version" ] || die "usage: release-store.sh verify <store> <version>"
	dir="$store/$version"
	[ -d "$dir" ] || die "no such release: $dir"
	[ -f "$dir/SHA256SUMS" ] || die "missing SHA256SUMS in $dir"
	[ -f "$dir/RELEASE" ] || die "missing RELEASE manifest in $dir"
	while read -r sum name; do
		[ -n "$sum" ] && [ -n "$name" ] || continue
		require_sha256 "$sum"
		[ -f "$dir/$name" ] || die "SHA256SUMS lists $name but it is missing"
		got="$(sha256_of "$dir/$name")"
		[ "$got" = "$sum" ] || die "byte mismatch for $name: sums=$sum actual=$got"
	done <"$dir/SHA256SUMS"
	echo "release-store: $version verified"
	;;
resolve)
	store="${1:-}"; plat="${2:-}"
	[ -n "$store" ] && [ -n "$plat" ] || die "usage: release-store.sh resolve <store> <platform>"
	# Newest version (lexicographic v-semver is not enough; use the
	# published_at order in RELEASE, falling back to directory mtime).
	latest=""
	latest_ts=0
	for d in "$store"/v*; do
		[ -d "$d" ] || continue
		[ -f "$d/SHA256SUMS" ] || continue
		want="$(awk -v n="kiwi-$plat" '$2==n{print $1; exit}' "$d/SHA256SUMS")"
		[ -n "$want" ] || continue
		ts=$(stat -c %Y "$d" 2>/dev/null || stat -f %m "$d" 2>/dev/null || echo 0)
		if [ "$ts" -gt "$latest_ts" ] || [ -z "$latest" ]; then
			latest="$d"
			latest_ts="$ts"
		fi
	done
	[ -n "$latest" ] || die "no published release in $store provides kiwi-$plat"
	bin="$latest/kiwi-$plat"
	[ -f "$bin" ] || die "release $latest is missing kiwi-$plat"
	# Verify the bytes against the store's own SHA256SUMS before handing
	# them out — the store is the trust anchor.
	want="$(awk -v n="kiwi-$plat" '$2==n{print $1; exit}' "$latest/SHA256SUMS")"
	require_sha256 "$want"
	got="$(sha256_of "$bin")"
	[ "$got" = "$want" ] || die "stored $bin sha256=$got, want published $want"
	printf '%s %s\n' "$bin" "$want"
	;;
list)
	store="${1:-}"
	[ -n "$store" ] || die "usage: release-store.sh list <store>"
	for d in "$store"/v*; do
		[ -d "$d" ] || continue
		[ -f "$d/RELEASE" ] || continue
		ver="$(basename "$d")"
		commit="$(awk -F= '/^commit=/{print $2; exit}' "$d/RELEASE")"
		echo "$ver commit=$commit"
	done
	;;
*)
	die "usage: release-store.sh publish|verify|resolve|list ..."
	;;
esac

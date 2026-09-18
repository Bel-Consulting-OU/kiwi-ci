#!/bin/sh
# dockerfile-buildargs-check.sh executes the Dockerfile's VERSION/COMMIT
# validation RUN block natively, without a Docker daemon, so the build-arg
# contract stays covered by CI. The block between the BEGIN and END marker
# comments is extracted, reconstructed into a runnable script (leading `RUN `
# stripped, backslash continuations joined), and executed under sh/dash with
# controlled VERSION/COMMIT values. Every accept/reject expectation in the
# case table below must match the block; the first mismatch names the case
# and exits non-zero.
#
# Usage: scripts/dockerfile-buildargs-check.sh
#
# Environment:
#   DOCKERFILE       file to extract the block from (default: the Dockerfile
#                    next to this script)
#   KC_BUILDARGS_SH  shell that executes the extracted block (default: sh;
#                    use dash to exercise the BusyBox-safe path explicitly)
# Injection payloads below are intentionally literal (never expanded here).
# shellcheck disable=SC2016
set -eu

BEGIN_MARKER='# BEGIN version-commit validation'
END_MARKER='# END version-commit validation'

die() {
	printf 'dockerfile-buildargs-check: error: %s\n' "$*" >&2
	exit 1
}

quote_value() {
	printf "'%s'" "$1"
}

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd)
DOCKERFILE=${DOCKERFILE:-$script_dir/../Dockerfile}
SH_CMD=${KC_BUILDARGS_SH:-sh}

[ -f "$DOCKERFILE" ] || die "Dockerfile not found: $DOCKERFILE"
dockerfile_dir=$(CDPATH='' cd "$(dirname "$DOCKERFILE")" && pwd)
DOCKERFILE=$dockerfile_dir/$(basename "$DOCKERFILE")
command -v "$SH_CMD" >/dev/null 2>&1 || die "shell not found: $SH_CMD"

begin_count=$(grep -c -x -F "$BEGIN_MARKER" "$DOCKERFILE" || true)
end_count=$(grep -c -x -F "$END_MARKER" "$DOCKERFILE" || true)
[ "$begin_count" -eq 1 ] || die "expected exactly one '$BEGIN_MARKER' marker in $DOCKERFILE, found $begin_count"
[ "$end_count" -eq 1 ] || die "expected exactly one '$END_MARKER' marker in $DOCKERFILE, found $end_count"
begin_line=$(grep -n -x -F "$BEGIN_MARKER" "$DOCKERFILE" | cut -d: -f1)
end_line=$(grep -n -x -F "$END_MARKER" "$DOCKERFILE" | cut -d: -f1)
[ "$begin_line" -lt "$end_line" ] || die "END marker at line $end_line precedes BEGIN marker at line $begin_line in $DOCKERFILE"

block=$(awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" '
	$0 == begin { inside = 1; next }
	$0 == end { inside = 0; next }
	inside { print }
' "$DOCKERFILE")
[ -n "$block" ] || die "marker block is empty in $DOCKERFILE"

script=$(printf '%s\n' "$block" | awk '
	{
		line = $0
		if (line ~ /\\$/) {
			sub(/\\$/, "", line)
			printf "%s", line
			next
		}
		printf "%s\n", line
	}
')

newline='
'
case "$script" in
*"$newline"*)
	die "marker block must be a single RUN instruction with every continuation line ending in a backslash"
	;;
esac
case "$script" in
'RUN '*) ;;
*) die "marker block must start with a 'RUN ' instruction, got '${script%% *}'" ;;
esac
script=${script#RUN }
[ -n "$script" ] || die "RUN instruction body is empty"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/dockerfile-buildargs-check.XXXXXX")
cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$tmpdir/sub"
printf 'sentinel\n' >"$tmpdir/sentinel.txt"
printf 'nested sentinel\n' >"$tmpdir/sub/nested.txt"
cp "$DOCKERFILE" "$tmpdir/Dockerfile.copy"

version_cases=0
commit_cases=0
tree_cases=0

snapshot_tree() {
	(
		cd "$1" || exit 1
		find . -print | LC_ALL=C sort
		find . -type f -exec cksum {} + | LC_ALL=C sort
	)
}

check_case() {
	expected=$1
	name=$2
	value=$3
	description=$4
	case "$name" in
	VERSION)
		VERSION="$value"
		COMMIT=unknown
		;;
	COMMIT)
		VERSION=dev
		COMMIT="$value"
		;;
	*)
		die "internal error: unknown variable '$name'"
		;;
	esac
	if output=$(cd "$tmpdir" || exit 1; env -i PATH="$PATH" VERSION="$VERSION" COMMIT="$COMMIT" "$SH_CMD" -c "$script" 2>&1 >/dev/null); then
		status=0
	else
		status=$?
	fi
	if [ "$expected" = accept ]; then
		[ "$status" -eq 0 ] || die "case $name=$(quote_value "$value") ($description): expected ACCEPT, got exit $status; block said: $(printf '%s\n' "$output" | tail -n 1)"
	else
		[ "$status" -ne 0 ] || die "case $name=$(quote_value "$value") ($description): expected REJECT, got exit 0 (value smuggled through)"
	fi
	case "$name" in
	VERSION) version_cases=$((version_cases + 1)) ;;
	COMMIT) commit_cases=$((commit_cases + 1)) ;;
	esac
}

tab=$(printf '\t')

# VERSION: allowed charset [A-Za-z0-9._+-]; the ARG default covers unset, an
# explicit empty cannot inject. Everything whitespace/quote/expansion-shaped
# must be refused before it reaches -ldflags.
check_case accept VERSION dev 'plain sentinel version'
check_case accept VERSION 0.1.0-dev 'Makefile development default'
check_case accept VERSION 1.2.3 'release semver'
check_case accept VERSION '0.1.0-dev-snapshot+1a2b3c4.dirty' 'snapshot with build metadata (+, .)'
check_case accept VERSION '' 'explicit empty cannot inject (unset is covered by the ARG default)'
check_case reject VERSION '-X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Dirty=true' 'extra linker -X pair'
check_case reject VERSION '"1.2.3"' 'double quotes'
check_case reject VERSION "'1.2.3'" 'single quotes'
check_case reject VERSION '$(id)' 'command substitution'
check_case reject VERSION '`id`' 'backtick substitution'
check_case reject VERSION '1.2.3 4' 'space inside value'
check_case reject VERSION ' 1.2.3' 'leading space'
check_case reject VERSION '1.2.3 ' 'trailing space'
check_case reject VERSION "1.2.3${tab}4" 'tab inside value'
check_case reject VERSION '""' 'quoted-empty injection'
check_case reject VERSION '$(true)' 'empty command substitution'
check_case reject VERSION ' ' 'whitespace-only value'

# COMMIT: literal "unknown" or 7-40 lowercase hex; the hex set is spelled out
# in the block so UTF-8 collation cannot smuggle uppercase A-F through.
check_case accept COMMIT unknown 'explicit unknown sentinel'
check_case accept COMMIT 1a2b3c4 '7-char short SHA'
check_case accept COMMIT 0123456789abcdef0123456789abcdef01234567 '40-char full SHA'
check_case accept COMMIT deadbeef '8-char SHA fragment'
check_case reject COMMIT 1A2B3C4 'uppercase hex (collation trap)'
check_case reject COMMIT ABCDEF0 'all-uppercase hex'
check_case reject COMMIT UNKNOWN 'uppercase unknown sentinel'
check_case reject COMMIT 1a2b3 '5-char short SHA'
check_case reject COMMIT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa '41-char SHA'
check_case reject COMMIT 1234567g 'invalid hex character at valid length'
check_case reject COMMIT -X 'linker flag fragment'
check_case reject COMMIT '' 'empty value'
check_case reject COMMIT '1a2b3c4 ' 'trailing space'
check_case reject COMMIT ' 1a2b3c4' 'leading space'

# A valid combination must exit 0 and leave a populated temp tree untouched.
before=$(snapshot_tree "$tmpdir")
if output=$(cd "$tmpdir" || exit 1; env -i PATH="$PATH" VERSION=0.1.0-dev COMMIT=1a2b3c4 "$SH_CMD" -c "$script" 2>&1 >/dev/null); then
	:
else
	die "valid combination VERSION=0.1.0-dev COMMIT=1a2b3c4 exited non-zero in the temp tree; block said: $(printf '%s\n' "$output" | tail -n 1)"
fi
after=$(snapshot_tree "$tmpdir")
[ "$before" = "$after" ] || die "valid combination modified the temp tree (sentinel or Dockerfile.copy changed)"
tree_cases=1

printf 'dockerfile-buildargs-check: ok: %d cases passed (%d VERSION, %d COMMIT), %d valid-combination run left the temp tree unchanged (shell %s, dockerfile %s)\n' \
	"$((version_cases + commit_cases))" "$version_cases" "$commit_cases" "$tree_cases" "$SH_CMD" "$DOCKERFILE"

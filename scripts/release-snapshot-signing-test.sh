#!/bin/sh
# release-snapshot-signing-test.sh proves snapshot builds are never signed,
# even when KIWI_RELEASE_SIGNING_KEY is exported. The script under test runs
# inside temp clones of this repository with a stubbed `go` on PATH, so no Go
# toolchain is needed and every release-tool invocation is recorded: argv,
# the contents of its temp directory, and the permission bits of any key file
# materialized next to it.
#
# Expectations:
#   * --snapshot with KIWI_RELEASE_SIGNING_KEY set: release-tool receives no
#     -key argument and no key file is materialized, and the run still
#     succeeds through the full per-binary loop and emits the SNAPSHOT marker.
#   * release-mode control with the same environment: release-tool does
#     receive -key pointing at a mode-600 temp file, proving the key is
#     honored only where the documented policy says it is.
#
# Usage: scripts/release-snapshot-signing-test.sh
#
# Environment:
#   KC_RELEASE_SH  scripts/release.sh to test (default: the working-tree copy).
#                  Point it at `git show HEAD:scripts/release.sh` in a temp
#                  file to prove this test fails against the pre-fix script.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/release-snapshot-signing-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM

fail() {
	echo "release-snapshot-signing-test: $*" >&2
	exit 1
}

RELEASE_SH=${KC_RELEASE_SH:-$ROOT/scripts/release.sh}
[ -f "$RELEASE_SH" ] || fail "release script not found: $RELEASE_SH"
command -v git >/dev/null 2>&1 || fail "git is required"

STUB_BIN="$TMP/bin"
LOG_DIR="$TMP/log"
mkdir -p "$STUB_BIN" "$LOG_DIR"

# The `go` stub answers `go build -o` (placeholder binaries; the release-tool
# output is an instrumented script) and `go version -m` (sidecar build info).
# The instrumented release-tool appends one record per invocation to the log
# named by KC_TEST_RELEASE_TOOL_LOG.
cat >"$STUB_BIN/go" <<'STUB_GO'
#!/bin/sh
set -eu
case "${1:-}" in
build)
	out=""
	pkg=""
	prev=""
	for arg in "$@"; do
		if [ "$prev" = "-o" ]; then
			out="$arg"
		fi
		prev="$arg"
		pkg="$arg"
	done
	[ -n "$out" ] || { echo "stub go: build without -o: $*" >&2; exit 1; }
	if [ "$pkg" = "./cmd/release-tool" ]; then
		cat >"$out" <<'STUB_TOOL'
#!/bin/sh
set -eu
dir="$(CDPATH='' cd "$(dirname "$0")" && pwd)"
{
	printf 'argv:'
	for arg in "$@"; do
		printf ' [%s]' "$arg"
	done
	printf '\n'
	printf 'dir:'
	for entry in "$dir"/*; do
		[ -e "$entry" ] || continue
		printf ' [%s]' "$(basename "$entry")"
	done
	printf '\n'
	for entry in "$dir"/*.pem; do
		[ -e "$entry" ] || continue
		printf 'keyperm: [%s] %s\n' "$(basename "$entry")" "$(LC_ALL=C ls -l "$entry" | awk '{print $1}')"
	done
} >>"$KC_TEST_RELEASE_TOOL_LOG"
STUB_TOOL
		chmod +x "$out"
	else
		printf 'stub binary: %s\n' "$pkg" >"$out"
	fi
	;;
version)
	printf '%s: go1.27 stub\n' "${3:-binary}"
	;;
*)
	echo "stub go: unexpected invocation: $*" >&2
	exit 1
	;;
esac
STUB_GO
chmod +x "$STUB_BIN/go"

# Throwaway Ed25519 PKCS#8 private key PEM: it only has to look exactly like
# the real secret. release-tool is stubbed and never parses it; passing the
# PEM inline exercises release mode's materialize-to-temp-file branch.
KEY_PEM='-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEKJOYLJMpBQTgVAg45+KKKT+6OADJUnzgmMrGE15OSF
-----END PRIVATE KEY-----'

HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"

# clone_repo checks out HEAD into $1, pins the script under test (so the
# uncommitted working-tree fix is exercised, not the committed revision),
# commits it to keep the tree clean, and tags v1.2.3 for the release control.
clone_repo() {
	dest="$1"
	git clone --quiet "$ROOT" "$dest" || fail "git clone of $ROOT failed"
	git -C "$dest" checkout --quiet --detach "$HEAD_SHA" || fail "cannot detach $dest at $HEAD_SHA"
	cp "$RELEASE_SH" "$dest/scripts/release.sh"
	chmod +x "$dest/scripts/release.sh"
	git -C "$dest" add scripts/release.sh
	if ! git -C "$dest" diff --cached --quiet; then
		git -C "$dest" -c user.name=release-test -c user.email=release-test@example.invalid \
			commit --quiet -m "release-snapshot-signing-test: pin script under test"
	fi
	git -C "$dest" tag -f v1.2.3
}

# release_env runs the script under test with a minimal environment: only the
# stub bin directory ahead of the normal PATH, HOME, the inline signing key,
# and the release-tool log path. No ambient VERSION/COMMIT/BUILD_DATE/SIGNING
# variables can leak into the run.
release_env() {
	log="$1"
	shift
	env -i \
		PATH="$STUB_BIN:$PATH" \
		HOME="${HOME:-$TMP}" \
		KIWI_RELEASE_SIGNING_KEY="$KEY_PEM" \
		KC_TEST_RELEASE_TOOL_LOG="$log" \
		sh "$@"
}

# --- Snapshot: the env key must be ignored entirely. ---
SNAP_CLONE="$TMP/snapshot-repo"
clone_repo "$SNAP_CLONE"
SNAP_LOG="$LOG_DIR/snapshot.log"
: >"$SNAP_LOG"
if release_env "$SNAP_LOG" "$SNAP_CLONE/scripts/release.sh" --snapshot >"$TMP/snapshot.out" 2>&1; then
	:
else
	fail "snapshot run failed: $(tail -n 1 "$TMP/snapshot.out")"
fi
[ -f "$SNAP_CLONE/dist/snapshot/SNAPSHOT" ] || fail "snapshot run did not produce dist/snapshot/SNAPSHOT"
for name in kiwi-darwin-arm64 kiwi-darwin-amd64 kiwi-linux-arm64 kiwi-linux-amd64 kiwi-windows-amd64.exe; do
	grep -q "\[-binary\] \[[^]]*/$name\]" "$SNAP_LOG" || fail "snapshot run did not reach release-tool for $name"
done
if grep -q '\[-key\]' "$SNAP_LOG"; then
	fail "snapshot mode passed -key to release-tool: $(grep -e '-key' "$SNAP_LOG" | head -n 1)"
fi
if grep -Eq '\[[^]]*\.pem\]' "$SNAP_LOG"; then
	fail "snapshot mode materialized a key file next to release-tool"
fi
if grep -q '^keyperm:' "$SNAP_LOG"; then
	fail "snapshot mode materialized a key file (permission record present)"
fi

# --- Snapshot VERSION injection must be refused before any build. ---
# VERSION is embedded in -ldflags; a value carrying whitespace or an extra
# `-X ...` pair would otherwise be whitespace-split by cmd/go into additional
# linker arguments. The charset rule must reject it before the stub go is ever
# invoked, so nothing reaches release-tool.
INJ_CLONE="$TMP/snapshot-inject-repo"
clone_repo "$INJ_CLONE"
INJ_LOG="$LOG_DIR/snapshot-inject.log"
: >"$INJ_LOG"
if env -i \
	PATH="$STUB_BIN:$PATH" \
	HOME="${HOME:-$TMP}" \
	KIWI_RELEASE_SIGNING_KEY="$KEY_PEM" \
	KC_TEST_RELEASE_TOOL_LOG="$INJ_LOG" \
	VERSION="1.0.0 -X github.com/Bel-Consulting-OU/kiwi-ci/internal/version.Commit=evil" \
	sh "$INJ_CLONE/scripts/release.sh" --snapshot >"$TMP/snapshot-inject.out" 2>&1; then
	fail "snapshot with a VERSION carrying whitespace/extra -X was accepted"
fi
grep -q "snapshot VERSION" "$TMP/snapshot-inject.out" ||
	fail "snapshot VERSION rejection did not name the charset rule: $(tail -n 1 "$TMP/snapshot-inject.out")"
if [ -s "$INJ_LOG" ]; then
	fail "snapshot VERSION injection reached release-tool: $(head -n 1 "$INJ_LOG")"
fi

# --- Release control: the same environment must sign. ---
REL_CLONE="$TMP/release-repo"
clone_repo "$REL_CLONE"
REL_LOG="$LOG_DIR/release.log"
: >"$REL_LOG"
if release_env "$REL_LOG" "$REL_CLONE/scripts/release.sh" >"$TMP/release.out" 2>&1; then
	:
else
	fail "release-mode control run failed: $(tail -n 1 "$TMP/release.out")"
fi
grep -q '\[-key\]' "$REL_LOG" || fail "release mode did not pass -key despite KIWI_RELEASE_SIGNING_KEY being set"
grep -Eq '\[-key\] \[[^]]*release-signing-key\.pem\]' "$REL_LOG" ||
	fail "release-mode -key did not point at the materialized inline-PEM temp file"
grep -q '^keyperm: \[release-signing-key\.pem\] -rw-------' "$REL_LOG" ||
	fail "release mode did not materialize the inline PEM as a mode-600 temp file"

echo "release-snapshot-signing-test: snapshot ignored KIWI_RELEASE_SIGNING_KEY (no -key, no key file), refused a VERSION carrying whitespace/extra -X before any build, and release control passed -key pointing at a mode-600 temp file"

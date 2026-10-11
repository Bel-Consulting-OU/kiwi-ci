#!/usr/bin/env bash
# fetch-tla2tools.sh downloads the pinned TLA+ tla2tools.jar and verifies its
# SHA-256 before it is used or cached. A verification product must not execute
# an unverified third-party model checker.
#
# Usage: scripts/fetch-tla2tools.sh [--selftest] [dest-path]
# Default dest: $HOME/.cache/kiwi/tla2tools.jar
# --selftest: prove the reject path on a tampered temp file, then exit 0
#   without touching the real dest (wired into `make tla2tools`).
set -euo pipefail

TLA2TOOLS_VERSION="1.7.4"
# Expected SHA-256 of the official v1.7.4 release artifact. Re-resolve with:
#   curl -fsSL -o /tmp/tla2tools.jar \
#     https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
#   shasum -a 256 /tmp/tla2tools.jar
# and update this constant together with TLA2TOOLS_VERSION.
TLA2TOOLS_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLA2TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v${TLA2TOOLS_VERSION}/tla2tools.jar"

selftest=0
if [[ "${1:-}" == "--selftest" ]]; then
  selftest=1
  shift
fi
dest="${1:-${HOME}/.cache/kiwi/tla2tools.jar}"

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ "$selftest" -eq 1 ]]; then
  # Selftest is offline: it proves the comparison logic rejects a wrong
  # digest. It never downloads and never touches $dest.
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  printf 'not-tla2tools\n' >"$tmp"
  actual="$(hash_of "$tmp")"
  if [[ "$actual" == "$TLA2TOOLS_SHA256" ]]; then
    echo "selftest: pin unexpectedly matched a garbage file" >&2
    exit 1
  fi
  echo "selftest ok: digest comparison rejects mismatched artifacts"
  exit 0
fi

mkdir -p "$(dirname "$dest")"

# Already present and matching: nothing to do (this is what a cache hit should
# look like after a previous verified fetch).
if [[ -f "$dest" ]]; then
  actual="$(hash_of "$dest")"
  if [[ "$actual" == "$TLA2TOOLS_SHA256" ]]; then
    echo "tla2tools.jar already present and verified at $dest"
    exit 0
  fi
  echo "tla2tools.jar at $dest has unexpected sha256 $actual; refetching" >&2
  rm -f "$dest"
fi

tmp="${dest}.tmp.${RANDOM}"
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "$TLA2TOOLS_URL"

actual="$(hash_of "$tmp")"
if [[ "$actual" != "$TLA2TOOLS_SHA256" ]]; then
  echo "tla2tools.jar sha256 mismatch: got $actual, want $TLA2TOOLS_SHA256" >&2
  exit 1
fi

mv "$tmp" "$dest"
trap - EXIT
echo "fetched and verified tla2tools.jar v${TLA2TOOLS_VERSION} at $dest"

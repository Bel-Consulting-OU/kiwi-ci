#!/bin/sh
# with-n-minus-one.sh resolves the PUBLISHED N-1 pin (unless
# KIWI_ALLOW_SOURCE_N_MINUS_ONE=1) and then execs the given command with
# KIWI_N_MINUS_ONE_BIN / KIWI_N_MINUS_ONE_SHA256 /
# KIWI_REQUIRE_RELEASED_N_MINUS_ONE in the environment.
#
# Every target that runs a test needing N-1 must go through this wrapper:
# resolving the pin in only one sibling target is how production lost the
# pin and died on "REQUIRE_RELEASED also requires SHA256".
set -eu

if [ "$#" -eq 0 ]; then
	echo "with-n-minus-one: usage: $0 command [args...]" >&2
	exit 2
fi

CACHE="${KIWI_N_MINUS_ONE_CACHE:-${TMPDIR:-/tmp}/kiwi-n-minus-one}"

if [ -z "${KIWI_N_MINUS_ONE_BIN:-}" ] && [ "${KIWI_ALLOW_SOURCE_N_MINUS_ONE:-}" = "1" ]; then
	echo "with-n-minus-one: KIWI_ALLOW_SOURCE_N_MINUS_ONE=1 — dev fallback (NOT release certification)" >&2
	export KIWI_REQUIRE_N_MINUS_ONE=1
	exec "$@"
fi

# Resolve (supplied BIN gets its pin computed/verified here too).
./scripts/fetch-n-minus-one.sh

if [ -f "$CACHE/n-minus-one.env" ]; then
	# shellcheck disable=SC1090
	. "$CACHE/n-minus-one.env"
fi

if [ -z "${KIWI_N_MINUS_ONE_BIN:-}" ]; then
	echo "with-n-minus-one: fetch produced no KIWI_N_MINUS_ONE_BIN" >&2
	exit 1
fi
if [ -z "${KIWI_N_MINUS_ONE_SHA256:-}" ]; then
	echo "with-n-minus-one: fetch produced no KIWI_N_MINUS_ONE_SHA256" >&2
	exit 1
fi

export KIWI_N_MINUS_ONE_BIN KIWI_N_MINUS_ONE_SHA256
export KIWI_REQUIRE_N_MINUS_ONE=1 KIWI_REQUIRE_RELEASED_N_MINUS_ONE=1
exec "$@"

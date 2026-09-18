#!/bin/sh
# toolchain-check.sh keeps the Go toolchain contract from drifting.
#
# Checks (all offline, no temporary files, POSIX sh):
#   1. Read the exact `go <version>` directive from go.mod (the minimum
#      toolchain the module requires; no loose regex on the version).
#   2. Require every top-level Markdown doc that states a Go minimum to
#      state exactly that minimum, with the phrase "Go <version> or later":
#      README.md and CONTRIBUTING.md must state it (a missing statement is
#      an error), and any other top-level doc that states a minimum must
#      not contradict go.mod. Top-level docs are scanned without git so the
#      check stays offline and fast.
#   3. Require the `go` binary on PATH to satisfy go.mod's directive
#      (dotted-numeric comparison, GOOS/GOARCH-independent; `go version`
#      never downloads a toolchain, so the check is safe offline).
#
# Usage:
#   scripts/toolchain-check.sh [ROOT]    check ROOT (default: repo root)
#   scripts/toolchain-check.sh --selftest
#     Prove the pass path and the failure paths on doctored temp copies.
#
# Wired into `make schema-check` and invoked as the first command of every
# Woodpecker workflow (see .woodpecker/*.yml).
set -eu

SELF=$0
case $SELF in
	/*) ;;
	*) SELF=$(pwd)/$SELF ;;
esac

DEFAULT_ROOT=$(CDPATH='' cd "$(dirname "$SELF")/.." && pwd)
ROOT=$DEFAULT_ROOT

usage() {
	echo "usage: $0 [ROOT]" >&2
	echo "       $0 --selftest" >&2
}

fail() {
	echo "toolchain-check: FAIL: $*" >&2
	exit 1
}

# Dotted-numeric version comparison: version_ge A B is true when A >= B.
version_ge() {
	v1=$1
	v2=$2
	while [ -n "$v1" ] || [ -n "$v2" ]; do
		if [ "${v1%%.*}" = "$v1" ]; then
			a=$v1
			v1=
		else
			a=${v1%%.*}
			v1=${v1#*.}
		fi
		if [ "${v2%%.*}" = "$v2" ]; then
			b=$v2
			v2=
		else
			b=${v2%%.*}
			v2=${v2#*.}
		fi
		[ -n "$a" ] || a=0
		[ -n "$b" ] || b=0
		if [ "$a" -gt "$b" ]; then
			return 0
		fi
		if [ "$a" -lt "$b" ]; then
			return 1
		fi
	done
	return 0
}

check() {
	root=$1
	[ -f "$root/go.mod" ] || fail "go.mod not found under $root"

	# Top-level docs that must state go.mod's minimum exactly. Every other
	# top-level Markdown doc that states a minimum must agree with go.mod.
	required_docs="README.md CONTRIBUTING.md"
	for required in $required_docs; do
		[ -f "$root/$required" ] || fail "$required not found under $root"
	done

	go_mod_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")
	[ -n "$go_mod_version" ] || fail "go.mod has no 'go <version>' directive"
	case $go_mod_version in
		*[!0-9.]*) fail "go.mod requires '$go_mod_version', which is not a plain dotted numeric version" ;;
	esac
	echo "toolchain-check: go.mod requires go $go_mod_version"

	for doc in "$root"/*.md; do
		[ -f "$doc" ] || continue
		name=${doc##*/}
		documented=$(grep -oE 'Go [0-9]+\.[0-9]+(\.[0-9]+)? or later' "$doc" |
			sed -e 's/^Go //' -e 's/ or later$//' | sort -u)
		required=false
		case " $required_docs " in
			*" $name "*) required=true ;;
		esac
		if [ -z "$documented" ]; then
			if [ "$required" = true ]; then
				fail "$name does not document a minimum Go version with the exact phrase 'Go <version> or later'"
			fi
			continue
		fi
		documented_count=$(printf '%s\n' "$documented" | wc -l | tr -d ' ')
		if [ "$documented_count" -ne 1 ] || [ "$documented" != "$go_mod_version" ]; then
			fail "$name must document exactly 'Go $go_mod_version or later'; found: $(printf '%s' "$documented" | tr '\n' ' ')"
		fi
	done

	command -v go >/dev/null 2>&1 || fail "go is not on PATH"
	go_raw=$(go version)
	go_running=$(printf '%s\n' "$go_raw" | awk '{print $3; exit}')
	go_running=${go_running#go}
	case $go_running in
		''|*[!0-9.]*) fail "cannot parse a dotted numeric version out of '$go_raw'" ;;
	esac
	version_ge "$go_running" "$go_mod_version" ||
		fail "running $go_raw is older than go.mod's go $go_mod_version"

	echo "toolchain-check: top-level docs document the same minimum (Go $go_mod_version)"
	echo "toolchain-check: $go_raw satisfies go $go_mod_version"
	echo "toolchain-check: OK"
}

selftest() {
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/kiwi-toolchain-check.XXXXXX")
	trap 'rm -rf "$tmp"' EXIT HUP INT TERM
	status=0

	mkdir -p "$tmp/pass" "$tmp/readme-drift" "$tmp/contributing-drift" \
		"$tmp/contributing-missing" "$tmp/other-doc-drift" "$tmp/mod-drift" "$tmp/no-readme"
	cp "$DEFAULT_ROOT/go.mod" "$tmp/pass/go.mod"
	cp "$DEFAULT_ROOT/README.md" "$tmp/pass/README.md"
	cp "$DEFAULT_ROOT/CONTRIBUTING.md" "$tmp/pass/CONTRIBUTING.md"

	printf 'module example.com/drift\n\ngo 1.27.1\n' >"$tmp/readme-drift/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.23 or later.\n' >"$tmp/readme-drift/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/readme-drift/CONTRIBUTING.md"

	printf 'module example.com/drift\n\ngo 1.27.1\n' >"$tmp/contributing-drift/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/contributing-drift/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.23 or later.\n' >"$tmp/contributing-drift/CONTRIBUTING.md"

	printf 'module example.com/drift\n\ngo 1.27.1\n' >"$tmp/contributing-missing/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/contributing-missing/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go (any recent release).\n' >"$tmp/contributing-missing/CONTRIBUTING.md"

	printf 'module example.com/drift\n\ngo 1.27.1\n' >"$tmp/other-doc-drift/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/other-doc-drift/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/other-doc-drift/CONTRIBUTING.md"
	printf '# Other doc fixture\n\nContributors need Go 1.24 or later.\n' >"$tmp/other-doc-drift/ARCHITECTURE.md"

	printf 'module example.com/drift\n\ngo 99.0.0\n' >"$tmp/mod-drift/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 99.0.0 or later.\n' >"$tmp/mod-drift/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 99.0.0 or later.\n' >"$tmp/mod-drift/CONTRIBUTING.md"

	printf 'module example.com/drift\n\ngo 1.27.1\n' >"$tmp/no-readme/go.mod"
	printf '# Drift fixture\n\n## Requirements\n\n- Go (any recent release).\n' >"$tmp/no-readme/README.md"
	printf '# Drift fixture\n\n## Requirements\n\n- Go 1.27.1 or later.\n' >"$tmp/no-readme/CONTRIBUTING.md"

	run_case() {
		case_name=$1
		case_root=$2
		case_want=$3
		case_msg=$4
		case_out=$(sh "$SELF" "$case_root" 2>&1) && case_got=0 || case_got=$?
		if [ "$case_got" -ne "$case_want" ]; then
			echo "toolchain-check: selftest FAIL: $case_name exited $case_got, expected $case_want" >&2
			printf '%s\n' "$case_out" >&2
			status=1
			return
		fi
		if [ -n "$case_msg" ] && ! printf '%s\n' "$case_out" | grep -q "$case_msg"; then
			echo "toolchain-check: selftest FAIL: $case_name did not mention '$case_msg'" >&2
			printf '%s\n' "$case_out" >&2
			status=1
			return
		fi
		echo "toolchain-check: selftest ok: $case_name (exit $case_got)"
	}

	run_case pass "$tmp/pass" 0 ""
	run_case readme-drift "$tmp/readme-drift" 1 "README.md"
	run_case contributing-drift "$tmp/contributing-drift" 1 "CONTRIBUTING.md"
	run_case contributing-missing "$tmp/contributing-missing" 1 "CONTRIBUTING.md"
	run_case other-doc-drift "$tmp/other-doc-drift" 1 "ARCHITECTURE.md"
	run_case mod-drift "$tmp/mod-drift" 1 "older than"
	run_case no-readme "$tmp/no-readme" 1 "README.md"

	if [ "$status" -ne 0 ]; then
		fail "selftest failed"
	fi
	echo "toolchain-check: selftest OK"
}

if [ $# -gt 1 ]; then
	usage
	exit 2
fi
case ${1:-} in
	'') ;;
	--selftest)
		selftest
		exit $?
		;;
	--help|-h)
		usage
		exit 0
		;;
	-*)
		usage
		exit 2
		;;
	*)
		ROOT=$1
		;;
esac
check "$ROOT"

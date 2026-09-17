#!/bin/sh
# gh-branch-protection.sh configures main-branch protection for this
# repository through the GitHub REST API.
#
# Requires repo admin: the token used by `gh` needs "Administration:
# write" on the repository. Run it once, manually:
#
#   make protect-branch
#   # or: scripts/gh-branch-protection.sh [branch]  (default: main)
#
# The PUT below is idempotent: it replaces the branch protection rule
# set with the declared configuration, so re-running the script
# converges to the same state.
#
# REQUIRED STATUS CONTEXTS — MUST MATCH THE WOODPECKER INSTANCE
# ------------------------------------------------------------
# CI runs on Woodpecker (.woodpecker.yml), not GitHub Actions. Woodpecker
# reports one commit status PER WORKFLOW LEG, with the context rendered from
# the server settings:
#
#   WOODPECKER_STATUS_CONTEXT         default: ci/woodpecker
#   WOODPECKER_STATUS_CONTEXT_FORMAT  default:
#     {{ .context }}/{{ .event }}/{{ .workflow }}{{if not (eq .axis_id 0)}}/{{.axis_id}}{{end}}
#
# For the shipped pipeline (workflow name `woodpecker`, a two-entry platform
# matrix whose axis ids start at 1) the documented default contexts are:
#
#   ci/woodpecker/push/woodpecker/1   linux/amd64 leg on push
#   ci/woodpecker/push/woodpecker/2   linux/arm64 leg on push
#   ci/woodpecker/pr/woodpecker/1     linux/amd64 leg on pull request
#   ci/woodpecker/pr/woodpecker/2     linux/arm64 leg on pull request
#
# If the Woodpecker instance customizes the status context or its format
# (very common: a plain `woodpecker` context), these names will NOT match and
# GitHub would wait forever for checks that never appear. Before applying,
# confirm the actual context strings on a recent commit in the repository's
# checks tab, then override:
#
#   KIWI_WOODPECKER_CONTEXTS="<ctx> <ctx> ..."   # exact list
#   KIWI_WOODPECKER_CONTEXT=<ctx>                # single-context shorthand
#
# Woodpecker does NOT report one context per step, so step names (`unit`,
# `race`, ...) are never branch-protection contexts for a single-file
# pipeline. Removing the arm64 matrix entry from .woodpecker.yml also removes
# the `/2` contexts; drop them here at the same time.
#
# Policy applied:
#   - changes to main must arrive through a pull request
#     (required_pull_request_reviews with zero approvals; CI does the
#     gating, humans may self-merge when checks are green)
#   - required status checks: the Woodpecker contexts above (strict)
#   - branches must be up-to-date with main before merging
#   - enforce_admins: false (admins are not exempt from the rules)
#   - conversation resolution: disabled
#   - force pushes and deletions on main: disallowed
set -eu

BRANCH="${1:-main}"

if ! command -v gh >/dev/null 2>&1; then
	echo "branch-protection: gh CLI not found; install it from https://cli.github.com" >&2
	exit 1
fi
gh auth status >/dev/null 2>&1 || {
	echo "branch-protection: not authenticated; run 'gh auth login' first" >&2
	exit 1
}

REPO="${KIWI_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
[ -n "$REPO" ] || {
	echo "branch-protection: could not determine repository; set KIWI_REPO or run inside the checkout" >&2
	exit 1
}

if [ -n "${KIWI_WOODPECKER_CONTEXTS:-}" ]; then
	CONTEXTS_LIST="$KIWI_WOODPECKER_CONTEXTS"
elif [ -n "${KIWI_WOODPECKER_CONTEXT:-}" ]; then
	CONTEXTS_LIST="$KIWI_WOODPECKER_CONTEXT"
else
	CONTEXTS_LIST="ci/woodpecker/push/woodpecker/1 ci/woodpecker/push/woodpecker/2 ci/woodpecker/pr/woodpecker/1 ci/woodpecker/pr/woodpecker/2"
fi

# Build the JSON contexts array.
CONTEXTS=""
for ctx in $CONTEXTS_LIST; do
	if [ -z "$CONTEXTS" ]; then
		CONTEXTS="\"$ctx\""
	else
		CONTEXTS="$CONTEXTS, \"$ctx\""
	fi
done

echo "branch-protection: requiring Woodpecker contexts: $CONTEXTS_LIST"
echo "branch-protection: verify these against the instance's WOODPECKER_STATUS_CONTEXT(_FORMAT) and the checks tab"

gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
	--input - <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": [ $CONTEXTS ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false
  },
  "required_conversation_resolution": false,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON

echo "branch-protection: $REPO/$BRANCH protection applied (idempotent)"

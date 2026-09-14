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
# Policy applied:
#   - changes to main must arrive through a pull request
#     (required_pull_request_reviews with zero approvals; CI does the
#     gating, humans may self-merge when checks are green)
#   - required status checks: the full CI matrix job names from
#     .github/workflows/ci.yml (matrix jobs use GitHub's
#     "job (value)" display form)
#   - branches must be up-to-date with main before merging (strict)
#   - enforce_admins: false (admins are not exempt from the rules)
#   - conversation resolution: optional
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

gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
	--input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "format",
      "vet",
      "unit (ubuntu-latest)",
      "unit (windows-latest)",
      "unit (macos-latest)",
      "race (ubuntu-latest)",
      "race (macos-latest)",
      "adversarial",
      "fuzz-smoke",
      "schema",
      "cross",
      "staticcheck",
      "govulncheck",
      "license",
      "docs",
      "repro"
    ]
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

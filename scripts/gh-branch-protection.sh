#!/bin/sh
# gh-branch-protection.sh configures main-branch protection for Kiwi CI.
#
# Required status contexts are the stable, EVENT-INDEPENDENT Woodpecker
# workflow contexts (one per workflow file). For this to be stable, the
# Woodpecker instance must use the documented status format, e.g.:
#
#   {{ .context }}/{{ .workflow }}{{if not (eq .axis_id 0)}}/{{.axis_id}}{{end}}
#
# so the contexts look like:
#   ci/woodpecker/linux-amd64
#   ci/woodpecker/linux-arm64
#   ci/woodpecker/docker-workspace
#   ci/woodpecker/native-windows
#   ci/woodpecker/native-macos
#   ci/woodpecker/integration-coverage
#
# The script refuses to install a context it has NEVER observed on a recent
# commit, so abandoned or mistyped context names cannot silently weaken (or
# brick) protection. Requires repository admin.
set -eu
REPO="${KIWI_REPO:-Bel-Consulting-OU/kiwi-ci}"
BRANCH="${KIWI_BRANCH:-main}"
CONTEXTS="${KIWI_CONTEXTS:-ci/woodpecker/linux-amd64 ci/woodpecker/linux-arm64 ci/woodpecker/docker-workspace ci/woodpecker/integration-coverage ci/woodpecker/native-windows ci/woodpecker/native-macos}"

echo "== recent commit statuses observed on $REPO"
OBSERVED=$(gh api "repos/$REPO/commits?sha=$BRANCH&per_page=5" -q '.[].sha' 2>/dev/null | while read -r sha; do
	gh api "repos/$REPO/commits/$sha/statuses" -q '.[].context' 2>/dev/null || true
done | sort -u)
echo "$OBSERVED"

MISSING=""
for ctx in $CONTEXTS; do
	if ! printf '%s\n' "$OBSERVED" | grep -qx "$ctx"; then
		MISSING="$MISSING $ctx"
	fi
done
if [ -n "$MISSING" ]; then
	echo "refusing to install protection: contexts never observed on recent commits:$MISSING" >&2
	echo "check the Woodpecker status-context format on your instance, or set KIWI_CONTEXTS explicitly" >&2
	exit 1
fi

JSON_CONTEXTS=$(printf '%s' "$CONTEXTS" | tr ' ' '\n' | sed 's/.*/"&"/' | paste -sd, -)
gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" --input - <<EOF
{
  "required_status_checks": {"strict": true, "contexts": [$JSON_CONTEXTS]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
echo "branch protection applied to $REPO@$BRANCH"

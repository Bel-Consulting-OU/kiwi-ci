#!/bin/sh
# gh-branch-protection.sh configures main-branch protection for Kiwi CI.
#
# INVARIANT: a required status context must come from a workflow that actually
# runs on the event being gated. Required PR contexts are therefore only the
# EVENT-INDEPENDENT Woodpecker workflow contexts whose `when` includes
# `pull_request`:
#
#   ci/woodpecker/linux-amd64
#   ci/woodpecker/linux-arm64
#   ci/woodpecker/docker-workspace
#   ci/woodpecker/integration-coverage
#
# The native workflows (ci/woodpecker/native-windows, ci/woodpecker/native-macos)
# are deliberately NOT required for pull requests. Their workflows run only on
# push/manual/tag because the local backend executes directly on dedicated
# hosts and must never run untrusted fork code; a fork PR head produces no such
# context, so requiring them would leave every fork PR waiting forever for a
# check that is intentionally never scheduled. They remain post-merge (push)
# and tag gates per the workflow `when`, and their absence on a PR is expected,
# not a failure.
#
# For the required contexts to be stable, the Woodpecker instance must use the
# documented status format, e.g.:
#
#   {{ .context }}/{{ .workflow }}{{if not (eq .axis_id 0)}}/{{.axis_id}}{{end}}
#
# The script refuses to install a context it has NEVER observed on a recent
# commit, so abandoned or mistyped context names cannot silently weaken (or
# brick) protection. Requires repository admin.
set -eu
REPO="${KIWI_REPO:-Bel-Consulting-OU/kiwi-ci}"
BRANCH="${KIWI_BRANCH:-main}"
# Required for PRs: only workflows whose `when` contains `pull_request`.
CONTEXTS="${KIWI_CONTEXTS:-ci/woodpecker/linux-amd64 ci/woodpecker/linux-arm64 ci/woodpecker/docker-workspace ci/woodpecker/integration-coverage}"
# Never added to required PR contexts: push/manual/tag-only gates (see the
# invariant above). Listed for observability warnings only.
NATIVE_CONTEXTS="${KIWI_NATIVE_CONTEXTS:-ci/woodpecker/native-windows ci/woodpecker/native-macos}"

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

# Native gates are informational here: they run on push/manual/tag, so their
# absence from PR-time statuses proves nothing about protection.
for ctx in $NATIVE_CONTEXTS; do
	if printf '%s\n' "$OBSERVED" | grep -qx "$ctx"; then
		echo "native gate observed (push/manual/tag only, not required for PRs): $ctx"
	else
		echo "note: native gate $ctx not observed on recent $BRANCH commits; it is not a required PR context" >&2
	fi
done

JSON_CONTEXTS=$(printf '%s' "$CONTEXTS" | tr ' ' '\n' | sed 's/.*/"&"/' | paste -sd, -)
# enforce_admins:true applies protection to administrators as well, so no one
# can bypass the required contexts with an admin merge.
gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" --input - <<EOF
{
  "required_status_checks": {"strict": true, "contexts": [$JSON_CONTEXTS]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
echo "branch protection applied to $REPO@$BRANCH"

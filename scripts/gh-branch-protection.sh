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
#
# Optional app binding: a required `contexts` entry accepts a same-named
# status from ANY publisher with permission to write statuses. Set
# KIWI_WOODPECKER_APP_ID to the numeric ID of the GitHub App that publishes
# the Woodpecker statuses to emit the newer app-bound form instead:
#
#   checks: [{"context": "...", "app_id": <id>}, ...]
#
# Without the variable, the legacy `contexts` array is emitted unchanged.
# API version compatibility: `checks[].app_id` is part of the versioned REST
# API, so the app-bound call also sends `X-GitHub-Api-Version: 2022-11-28`
# (override with KIWI_GH_API_VERSION). On GitHub Enterprise Server older than
# 3.9 the field was still gated behind the legacy luke-cage preview media
# type; set KIWI_GH_ACCEPT=application/vnd.github.luke-cage-preview+json
# there. The default Accept is application/vnd.github+json. The legacy
# contexts call keeps sending no explicit headers, exactly as before.
set -eu
REPO="${KIWI_REPO:-Bel-Consulting-OU/kiwi-ci}"
BRANCH="${KIWI_BRANCH:-main}"
# Required for PRs: only workflows whose `when` contains `pull_request`.
CONTEXTS="${KIWI_CONTEXTS:-ci/woodpecker/linux-amd64 ci/woodpecker/linux-arm64 ci/woodpecker/docker-workspace ci/woodpecker/integration-coverage}"
# Never added to required PR contexts: push/manual/tag-only gates (see the
# invariant above). Listed for observability warnings only.
NATIVE_CONTEXTS="${KIWI_NATIVE_CONTEXTS:-ci/woodpecker/native-windows ci/woodpecker/native-macos}"
# Optional: numeric GitHub App ID that must publish each required context.
APP_ID="${KIWI_WOODPECKER_APP_ID:-}"
GH_API_VERSION="${KIWI_GH_API_VERSION:-2022-11-28}"
GH_ACCEPT="${KIWI_GH_ACCEPT:-application/vnd.github+json}"

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
if [ -n "$APP_ID" ]; then
	# Numeric only: JSON is assembled by hand and GitHub expects an integer.
	case $APP_ID in
		*[!0-9]*)
			echo "KIWI_WOODPECKER_APP_ID must be the numeric GitHub App ID, got: $APP_ID" >&2
			exit 1
			;;
	esac
	JSON_CHECKS=$(printf '%s' "$CONTEXTS" | tr ' ' '\n' |
		awk -v app_id="$APP_ID" '{ printf "%s{\"context\": \"%s\", \"app_id\": %s}", (NR > 1 ? ", " : ""), $0, app_id }')
	REQUIRED_STATUS_CHECKS="{\"strict\": true, \"checks\": [$JSON_CHECKS]}"
else
	REQUIRED_STATUS_CHECKS="{\"strict\": true, \"contexts\": [$JSON_CONTEXTS]}"
fi
# enforce_admins:true applies protection to administrators as well, so no one
# can bypass the required contexts with an admin merge.
#
# App-bound checks need the versioned REST API surface; the legacy contexts
# form keeps the original header-less `gh api` invocation.
set --
if [ -n "$APP_ID" ]; then
	set -- -H "Accept: $GH_ACCEPT" -H "X-GitHub-Api-Version: $GH_API_VERSION"
fi
gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" "$@" --input - <<EOF
{
  "required_status_checks": $REQUIRED_STATUS_CHECKS,
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
echo "branch protection applied to $REPO@$BRANCH"

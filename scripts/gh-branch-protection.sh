#!/bin/sh
# gh-branch-protection.sh configures main-branch protection for Kiwi CI.
#
# INVARIANT: a required status context must come from a workflow that actually
# runs on the event being gated. Woodpecker's status format is
# `ci/woodpecker/<event>/<workflow>[/<axis>]`, with `pull_request` mapped to
# the literal `pr` (verified against server/forge/common/status.go in
# v3.18.1 and against observed statuses). Required PR contexts are therefore
# only the `pr/` contexts of the workflows whose `when` includes
# `pull_request`:
#
#   ci/woodpecker/pr/linux-amd64
#   ci/woodpecker/pr/linux-arm64
#   ci/woodpecker/pr/integration-coverage
#
# Woodpecker publishes ONE commit status per workflow and event, not one per
# step, so the lanes inside a workflow are not separately requireable. The
# three contexts above are the COMPLETE pull_request workflow set (re-verified
# against every .woodpecker/*.yml `when`; internal/workflowguard fails the
# build if an entry names a workflow that never runs on its claimed event) and
# therefore carry the whole PR lane matrix:
#
#   pr/linux-amd64           format, vet, unit, unit-nonroot, race,
#                            race-double, single-p, checkptr, stress,
#                            adversarial, schema, cross, license, docs, repro,
#                            staticcheck, govulncheck, fuzz-smoke
#   pr/linux-arm64           unit, race
#   pr/integration-coverage  integration-postgres, unit-nonroot, coverage
#                            (merged unit+integration coverage floor)
#
# The native windows/macos lanes and docker-integration run on trusted events
# only (push/manual/tag) and stay post-merge gates (see NATIVE_CONTEXTS and
# the docker-workspace note below); never add them to the required PR list.
#
# docker-workspace is deliberately NOT a required PR context: it mounts the
# agent host's Docker daemon socket with host volumes, and Woodpecker gates
# volumes on the repository-level Trusted flag alone (no PR/fork gating), so a
# pull_request run would execute PR-authored code with host-daemon control.
# Its workflow `when` is push/manual/tag only and it stays a post-merge gate as
# `ci/woodpecker/push/docker-workspace` (see PUSH_CONTEXTS).
#
# The native workflows (ci/woodpecker/push/native-windows,
# ci/woodpecker/push/native-macos) are deliberately NOT required for pull
# requests. They run only on push/manual/tag because the local backend
# executes directly on dedicated hosts and must never run untrusted fork code;
# a fork PR head produces no such context, so requiring them would leave every
# fork PR waiting forever for a check that is intentionally never scheduled.
# They remain post-merge (push) and tag gates per the workflow `when`, and
# their absence on a PR is expected, not a failure.
#
# For the required contexts to be stable, the Woodpecker instance must use the
# canonical status format, i.e. at least:
#
#   {{context}}/{{event}}/{{workflow}}
#
# Matrix workflows append `/<axis_id>`; none of the workflows here use a
# matrix, so the plain three-segment form is what the lists below name.
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
# Required for PRs: the complete set of workflows whose `when` contains
# `pull_request` (the lane inventory is in the header). Woodpecker's context
# format is `{{context}}/{{event}}/{{workflow}}` with the pull_request event
# mapped to the literal `pr` (verified against server/forge/common/status.go
# in v3.18.1 and against observed statuses). Matrix axes append `/<axis_id>`;
# none of these workflows use a matrix. docker-workspace is absent on purpose:
# it mounts the host Docker socket and is push/manual/tag only (see the
# invariant above). One status per workflow, not per step: the lanes listed in
# the header are enforced through these three contexts, while windows, macos
# and docker-integration remain post-merge gates.
CONTEXTS="${KIWI_CONTEXTS:-ci/woodpecker/pr/linux-amd64 ci/woodpecker/pr/linux-arm64 ci/woodpecker/pr/integration-coverage}"
# Push variants are posted for every push; they are listed so operators can
# require them for direct pushes instead (a direct push to a protected branch
# can never satisfy only-pr contexts, and pr-only contexts block direct pushes
# when enforce_admins is true).
PUSH_CONTEXTS="${KIWI_PUSH_CONTEXTS:-ci/woodpecker/push/linux-amd64 ci/woodpecker/push/linux-arm64 ci/woodpecker/push/docker-workspace ci/woodpecker/push/integration-coverage}"
# Never added to required PR contexts: push/manual/tag-only gates (see the
# invariant above). Listed for observability warnings only.
NATIVE_CONTEXTS="${KIWI_NATIVE_CONTEXTS:-ci/woodpecker/push/native-windows ci/woodpecker/push/native-macos}"
# Optional: numeric GitHub App ID that must publish each required context.
APP_ID="${KIWI_WOODPECKER_APP_ID:-}"
GH_API_VERSION="${KIWI_GH_API_VERSION:-2022-11-28}"
GH_ACCEPT="${KIWI_GH_ACCEPT:-application/vnd.github+json}"
# enforce_admins applies required checks to administrators too. Default true is
# the documented policy, but it also blocks direct pushes to the protected
# branch (a fresh commit has no statuses yet); set KIWI_ENFORCE_ADMINS=false
# when the repository workflow is direct pushes rather than pull requests.
ENFORCE_ADMINS="${KIWI_ENFORCE_ADMINS:-true}"
case "$ENFORCE_ADMINS" in true|false) ;; *) echo "KIWI_ENFORCE_ADMINS must be true or false, got: $ENFORCE_ADMINS" >&2; exit 2 ;; esac

echo "== push contexts (require these instead when direct pushes must be gated): $PUSH_CONTEXTS"
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
  "enforce_admins": $ENFORCE_ADMINS,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
echo "branch protection applied to $REPO@$BRANCH"

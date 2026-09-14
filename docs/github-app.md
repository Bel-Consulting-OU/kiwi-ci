# GitHub integration

Kiwi CI accepts GitHub webhooks, fetches pipeline files through the
GitHub API, and publishes check runs back to the repository.

## Webhook setup

1. In the repository (or organization) settings, add a webhook to
   `https://<your-kiwi-host>/hooks/github`.
2. Content type: `application/json`.
3. Secret: the value of `--github-webhook-secret` (or
   `KIWI_GITHUB_WEBHOOK_SECRET`). Kiwi verifies `X-Hub-Signature-256`
   before processing anything.
4. Events: `Pushes` and `Pull requests` at minimum.

## Trust handling

- Push events are trusted.
- Pull requests from the same repository are trusted; pull requests
  from forks are untrusted.
- For fork PRs, the pipeline definition is fetched from the base
  commit of the base repository; the fork code is checked out
  separately. Untrusted runs get the hard capability floor: no secrets,
  no OIDC, no native execution, no egress, and immutable `@sha256:`
  pinned images/VMs.

## Authentication

Two modes:

- **Personal access token** (`--github-token`): used for fetching
  private pipeline files and changed-file lists.
- **GitHub App** (`github.app_id` + `github.private_key_path`): the
  recommended mode. The App authenticates with short-lived installation
  access tokens minted from RS256-signed JWTs, cached per repository
  until shortly before expiry. This is required for Checks API use on
  many installations.

## Trigger matching

The pipeline's `on` section is evaluated before enqueue
(`internal/forge` `MatchesTrigger`): event keys (`push`,
`pull_request`, and `<event>.<action>` forms like
`pull_request.opened`), branch and tag filters (globs), path filters
over the server-fetched changed-file list, and draft status (draft PRs
never match). Deliveries are deduplicated by `X-GitHub-Delivery`: a
retried delivery returns the original run.

## Checks

Pipeline state is published as GitHub Check Runs via a durable outbox
(`Kiwi / <pipeline>`, per-job entries). Check runs carry
queued/in_progress/completed states, annotations for failures, and the
details URL back to the Kiwi dashboard. Publication is idempotent by
external ID and survives server restarts (outbox replay).

## Config reference

```toml
[github]
app_id = 123456
private_key_path = "/etc/kiwi/github.pem"
webhook_secret = "high-entropy-secret"
token = ""            # PAT fallback only
```

See [production-deployment.md](production-deployment.md) for the server
setup and [security-model.md](security-model.md) for trust semantics.

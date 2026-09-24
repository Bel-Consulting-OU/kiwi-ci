# GitLab integration

Kiwi CI accepts GitLab webhooks, fetches pipeline files through the
GitLab API, and publishes commit statuses.

## Webhook setup

1. In the project settings, add a webhook to
   `https://<your-kiwi-host>/hooks/gitlab`.
2. Secret token: the value of `--gitlab-webhook-secret`-equivalent
   `gitlab.webhook_secret` (or `KIWI_GITLAB_WEBHOOK_SECRET`). Kiwi
   verifies the `X-Gitlab-Token` header before processing anything.
3. Triggers: `Push events` and `Merge request events` at minimum.

Ping events are acknowledged without action.

## Events handled

- `push` — enqueues a run when the head SHA is known.
- `merge_request` — actions `opened`, `reopened`, and `synchronize`
  enqueue runs. Merge requests from forks are untrusted: the pipeline
  definition is read from the base commit and the fork code is checked
  out separately, with the untrusted capability floor applied (no
  secrets, no OIDC, no native execution, no egress, digest-pinned
  images).

## Trigger matching

The pipeline `on` section is evaluated per event with the same
semantics as GitHub: `merge_request` keys (with `pull_request` as
fallback), `<event>.<action>` precedence, branch and tag globs, path
filters over the server-fetched changed files, and draft status.
Deliveries are deduplicated by `X-GitLab-Event-UUID`.

## Status publishing

GitLab does not expose GitHub-style checks; Kiwi falls back to commit
statuses (`pending`/`running`, `success`, `failure`, `cancelled`)
published through the durable outbox.

## Config reference

```toml
[gitlab]
# Instance root. Default https://gitlab.com; point it at a self-managed
# instance (https:// required in production; plaintext http is allowed
# only for a loopback development instance).
base_url = "https://gitlab.example.com"
webhook_secret = "high-entropy-secret"
token = ""        # API token for private pipeline fetches and statuses
```

`base_url` may also be set with `--gitlab-base-url` or
`KIWI_GITLAB_BASE_URL`. It must not carry userinfo, a query or a fragment;
credentials go in `token`.

See [production-deployment.md](production-deployment.md) for server
setup.

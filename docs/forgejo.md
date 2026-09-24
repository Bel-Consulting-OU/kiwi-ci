# Forgejo integration

Kiwi CI accepts Forgejo (and Gitea) webhooks, fetches pipeline files
through the Forgejo API, and publishes commit statuses.

## Webhook setup

1. In the repository settings, add a webhook to
   `https://<your-kiwi-host>/hooks/forgejo`.
2. Secret: the value of `forgejo.webhook_secret` (or
   `KIWI_FORGEJO_WEBHOOK_SECRET`). Kiwi verifies the HMAC-SHA256
   signature (the same `X-Hub-Signature-256` scheme GitHub uses) before
   processing anything.
3. Events: `Push` and `Pull Request` at minimum.

## Events handled

- `push` — enqueues a run.
- `pull_request` — `opened`, `reopened`, `synchronize` (and equivalent
  action names) enqueue runs. Pull requests from forks are untrusted:
  the pipeline definition is read from the base commit, fork code is
  checked out separately, and the untrusted capability floor applies
  (no secrets, no OIDC, no native execution, no egress, digest-pinned
  images).

## Trigger matching

The pipeline `on` section is evaluated per event with the standard
semantics: `pull_request` keys and `<event>.<action>` precedence,
branch and tag globs, path filters over the server-fetched changed-file
list, and draft status. Deliveries are deduplicated by the delivery
header when present.

## Status publishing

Forgejo exposes commit statuses; Kiwi publishes
pending/running/success/failure/cancelled statuses through the durable
outbox.

## Config reference

```toml
[forgejo]
# Instance root. Default https://codeberg.org; point it at a self-managed
# Forgejo/Gitea instance (https:// required in production; plaintext http
# is allowed only for a loopback development instance).
base_url = "https://forgejo.example.com"
webhook_secret = "high-entropy-secret"
token = ""        # API token for private pipeline fetches and statuses
```

`base_url` may also be set with `--forgejo-base-url` or
`KIWI_FORGEJO_BASE_URL`. It must not carry userinfo, a query or a fragment;
credentials go in `token`.

See [production-deployment.md](production-deployment.md) for server
setup.

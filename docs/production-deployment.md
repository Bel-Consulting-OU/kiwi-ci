# Production deployment

This document covers running the Kiwi CI control plane in production:
PostgreSQL, HA leader election, TLS, the config file, and runner
enrollment. Dev mode (in-memory state, single instance) is fine for
local testing and is not covered here beyond the basics.

## Server modes

- `dev` — in-memory state; a `--data-dir` adds filesystem persistence
  (state snapshot plus lease/OIDC keys).
- `production` — enforced startup contract:

  - `--database-url` (PostgreSQL) is required;
  - distinct `--admin-token` and `--runner-token` are required unless
    `--allow-shared-token` acknowledges a shared credential;
  - `--external-url` starting with `https://` is required (the OIDC
    issuer always serves in production);
  - `--tls-cert`/`--tls-key` are required.

```bash
kiwi server \
  --mode production \
  --listen :8443 \
  --external-url https://ci.example.com \
  --database-url "postgres://kiwi:pass@db:5432/kiwi" \
  --admin-token "$ADMIN_TOKEN" \
  --runner-token "$RUNNER_TOKEN" \
  --tls-cert /etc/kiwi/server.crt \
  --tls-key /etc/kiwi/server.key \
  --data-dir /var/lib/kiwi
```

## PostgreSQL

The durable SQL store (`internal/storage/postgres.go`, migrations in
`internal/storage/migrations/`) holds runs, jobs, leases, completion
receipts, runners, artifacts, test reports, logs, audit events, and
webhook deliveries. The server auto-migrates at startup when a database
URL is set; `kiwi database migrate` and `kiwi database status` do the
same explicitly.

Hot-path columns (status, lease, counters, timestamps) are relational
columns; the full model struct is a jsonb payload. Job completion is a
single transaction: lock the job, verify generation and runner, insert
the completion receipt idempotently, update counters, recompute
dependents and the run, and append the audit event.

## HA leader election

Exactly one instance may lease jobs, recover expired leases, or run
background maintenance. Leadership is a session-level PostgreSQL
advisory lock (`kiwi-scheduler`) held on a dedicated connection with a
soft renewal TTL (default 15 seconds). A standby instance serves reads
and polls for promotion (`Server.Maintain`). See [ha.md](ha.md) for the
full leader-duty list.

Run at least two instances behind a load balancer. Each instance needs
the same database URL, tokens, external URL, and a shared `--data-dir`
for lease/OIDC key material (or a process for provisioning the keys).

## TLS

Set `--tls-cert`/`--tls-key` (or `server.tls_cert`/`server.tls_key` in
the config file) to serve HTTPS. `--external-url` must match the public
base URL: it is advertised as the OIDC issuer and used for forge
statuses. In production, external URL must be `https://`.

## Configuration file

`kiwi server --config kiwi.toml` loads the TOML file described by
`kiwi.example.toml`. Precedence: CLI flags > `KIWI_*` environment
variables > config file > defaults. `kiwi config check --config
kiwi.toml` validates a file. Sections: `server`, `database`,
`runner_pki`, `blob`, `github`, `gitlab`, `forgejo`, `policy`,
`observability`, `rate_limit`, `auth`.

## Blob storage

Artifact bytes live in the `blob` backend: `fs` (local data directory,
default) or `s3` (endpoint, bucket, region, access key, secret key).
S3 requires all three coordinates. The content-addressed CAS layer
verifies digests on write and read regardless of backend.

## Runners and enrollment

Register a runner with a bearer token:

```bash
kiwi runner --server https://ci.example.com \
  --token "$RUNNER_TOKEN" --labels linux,x64
```

The runner bearer token is a SHARED credential: every runner presents the
same token, so it authenticates "some registered runner" but is not a
per-runner identity and cannot distinguish runners. Production strongly
prefers persistent per-runner mTLS identities. The control plane fails
closed: in production, an admin token without either a runner token or
enforced runner mTLS is a startup error.

For mTLS identity binding, create a runner CA once:

```bash
openssl req -x509 -newkey ed25519 -keyout runner-ca.key -out runner-ca.crt \
  -subj "/CN=kiwi-runner-ca" -days 3650 -noenc
```

Then start the server with `--runner-ca-cert`/`--runner-ca-key` (or
`--data-dir` plus `--runner-enroll-token` to persist a generated CA),
and enroll runners:

```bash
kiwi runner --server https://ci.example.com \
  --runner-enroll-token "$ENROLL_TOKEN" --runner-mtls
```

The runner generates its key locally, the server signs a certificate
with a server-synthesized `spiffe://kiwi/runner/<id>` identity (CSR
identity fields are discarded), and all subsequent traffic is mutually
authenticated. Keep the enrollment token short-lived; it is the
bootstrap credential for runner identities. Enrollment also supports
single-use grants (`CreateEnrollGrant`) with expiry and optional label
binding for automated runner provisioning.

When a runner CA is configured, the shared HTTPS listener verifies
client certificates when presented (`VerifyClientCertIfGiven`), and
runner-tier routes demand a valid runner certificate
(`--runner-require-client-certs`, default on); admin, forge and
enrollment traffic stays reachable on the same listener.

## Health and metrics

- `GET /readiness` — ready to serve traffic. DB mode checks the store. In
  fs mode (data-dir snapshot store) a failed snapshot write degrades the
  control plane: `/readiness` answers 503 with `X-Kiwi-State: degraded` and a
  fixed body (the raw error stays in the server logs), and new runner leases
  are refused with 503 so no capability is issued for state the snapshot does
  not contain. The state self-heals on the next successful persist and is
  cleared when the server switches to DB mode (the abandoned snapshot is no
  longer authoritative). Configure probes and load balancers to stop routing
  traffic to an instance while `/readiness` answers 503, and alert on the
  degraded state so a persistent snapshot-write failure is not masked.
- `GET /liveness` — process is up.
- `GET /metrics` — Prometheus-style metrics, optionally on a separate
  `observability.metrics_listen` address.

## Web UI

The embedded dashboard listens on the server address (`GET /`). Admin
login uses the admin token (`POST /api/v1/login`) with HMAC-signed
session cookies and CSRF protection.

## Production capabilities

- Server-side schedules: cron-parsed, leader-gated firing with
  exactly-once nominal occurrence claims (`schedule_occurrences`).
- OIDC signing-key rotation: active + previous verification keys with
  retire-after windows — see [oidc.md](oidc.md).
- OpenTelemetry export: OTLP/HTTP traces for requests, forge intake,
  enqueue, lease, and completion spans.
- Deployment and snapshot records persist durably (PostgreSQL or
  data-dir state file); scheduling semantics are enforced either way.


## CI (Woodpecker) server requirements

Kiwi's CI runs entirely on Woodpecker (`.woodpecker/` multi-workflow layout).
The Woodpecker instance hosting it must be configured so CI reflects reality:

- `WOODPECKER_FORCE_IGNORE_SERVICE_FAILURE=false` — otherwise a dead
  PostgreSQL service is ignored and the `integration-coverage` workflow
  passes without exercising the real database.
- Stable, event-independent commit-status contexts, so branch protection can
  require names like `ci/woodpecker/linux-amd64` instead of event-scoped
  variants.
- Agents labelled `platform=linux-amd64`, `platform=linux-arm64`,
  `capability=docker`, `platform=windows-amd64` and `platform=darwin-arm64`
  matching the workflow label sets; the Docker lane is REQUIRED and fails
  (never skips) when its daemon is unavailable.
- The clone plugin and every workflow image are pinned by OCI digest.

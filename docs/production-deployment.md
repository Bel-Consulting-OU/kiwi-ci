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
with a `spiffe://kiwi/runner/<id>` identity, and all subsequent traffic
is mutually authenticated. Keep the enrollment token short-lived; it is
the bootstrap credential for runner identities.

## Health and metrics

- `GET /readiness` — ready to serve traffic (DB mode checks the store).
- `GET /liveness` — process is up.
- `GET /metrics` — Prometheus-style metrics, optionally on a separate
  `observability.metrics_listen` address.

## Web UI

The embedded dashboard listens on the server address (`GET /`). Admin
login uses the admin token (`POST /api/v1/login`) with HMAC-signed
session cookies and CSRF protection.

## What production does not do yet

- Server-side schedules (cron) — the CLI scaffold exists, firing is
  deferred.
- OIDC signing-key rotation — see [oidc.md](oidc.md).
- OpenTelemetry export — the endpoint is accepted but a no-op.
- Deployment and snapshot records persist only in memory (DB
  persistence deferred); the scheduling semantics are enforced.

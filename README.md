# Kiwi CI

Kiwi CI is a single-binary CI/CD engine: one Go program runs as a local
CLI, a control plane, and a runner. It executes the same compiled
pipeline DAG locally and remotely, with first-class caches, artifacts,
retries, cancellation, secrets, and an auditable execution boundary for
untrusted code.

## What exists

- **Pipeline language v1**: jobs with `needs` dependencies, matrices,
  conditions, expressions, caches, artifacts, downloads, services,
  environments with approvals, sandboxing, placement, test
  intelligence, downstream pipelines, deployments, snapshots, and
  digest-pinned reusable components. See
  [docs/pipeline-reference.md](docs/pipeline-reference.md).
- **Local/remote parity**: `kiwi run` and remote runners execute the
  same compiled DAG. Local runs get isolated per-job workspaces.
- **Backends**: native (process-group cancellation), hardened Docker
  containers (rootless verification, capability drop, immutable image
  enforcement), and disposable Tart VMs on Apple Silicon.
- **Control plane**: PostgreSQL-backed scheduler with per-job leases,
  HA leader election, REST API, web dashboard, audit log, and
  Prometheus metrics.
- **Security**: capability-based admission policy with a deny-by-default
  untrusted floor, mTLS runner enrollment, HMAC-only lease tokens,
  sealed secret delivery, OIDC token issuance, and hardened archive
  extraction. See [docs/security-model.md](docs/security-model.md).
- **Forge integrations**: GitHub (App auth, Checks API), GitLab, and
  Forgejo webhooks with verified signatures, trigger matching, and
  deduplicated deliveries.
- **Explainability**: `kiwi explain --why JOB` shows why a job would or
  would not run; queued jobs carry machine-readable queue reasons.

## Requirements

- Go 1.23 or later.
- `git` on the PATH.
- Docker (for `runtime: container`) and Tart (for `runtime: tart`)
  only where those runtimes are used.

## Quick start

Build from source:

```bash
go install github.com/Bel-Consulting-OU/kiwi-ci/cmd/kiwi@latest
# or:
git clone https://github.com/Bel-Consulting-OU/kiwi-ci.git
cd kiwi-ci && go build -o kiwi ./cmd/kiwi
```

Check the host, then validate and run the example pipeline:

```bash
./kiwi doctor
./kiwi validate -f examples/kiwi.yaml
./kiwi explain --why test -f examples/kiwi.yaml
./kiwi run -f examples/kiwi.yaml
```

`kiwi init` scaffolds a `.kiwi/pipeline.yaml` in the current
repository.

## Server

Dev mode (in-memory state, no external services):

```bash
export KIWI_RUNNER_TOKEN='runner-token'
./kiwi server --listen :8080
```

Production mode (PostgreSQL, TLS, distinct admin/runner credentials):

```bash
./kiwi server \
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

Production mode enforces its contract at startup: database URL,
distinct tokens (or `--allow-shared-token`), an `https://` external URL
(the OIDC issuer), and TLS. See
[docs/production-deployment.md](docs/production-deployment.md).

Configuration can also come from a `kiwi.toml` file
(`--config kiwi.toml`, checked with `kiwi config check`); precedence is
CLI flags > `KIWI_*` environment variables > config file > defaults.

## Runner

```bash
./kiwi runner --server http://127.0.0.1:8080 \
  --token "$KIWI_RUNNER_TOKEN" --labels macos,arm64
```

For mTLS identity binding, create a runner CA (or let the server
persist one with `--data-dir`), set `--runner-enroll-token`, and start
the runner with `--runner-enroll-token`/`--runner-mtls`. The runner
negotiates protocol v3, drains cleanly on `--drain`, and self-cancels
if it loses contact with the control plane past its lease deadline.

Manage runners with `kiwi runner list|drain|disable|enable`.

## Webhooks

Point the forge at `https://<host>/hooks/github`, `/hooks/gitlab`, or
`/hooks/forgejo` with the matching webhook secret configured. Kiwi
verifies the signature before processing anything, applies the
pipeline's `on` triggers, and publishes checks/statuses back. Fork pull
requests are untrusted: the pipeline comes from the base commit, the
fork code is checked out separately, and the untrusted capability floor
applies (no secrets, no OIDC, no native execution, no egress,
digest-pinned images). See [docs/github-app.md](docs/github-app.md).

Manual dispatch:

```bash
./kiwi dispatch --repo owner/name --ref main \
  --input environment=staging --pipeline .kiwi/pipeline.yaml
```

## CLI overview

```
kiwi init | run | validate | explain [--why JOB] | doctor
kiwi server [--mode dev|production] [--config kiwi.toml]
kiwi config check | kiwi database migrate|status
kiwi runner [--server URL --token TOKEN] | kiwi runner list|drain|disable|enable
kiwi dispatch | kiwi runs | kiwi jobs | kiwi logs [--follow]
kiwi cancel | kiwi approve | kiwi rerun | kiwi artifacts
kiwi schedules list|trigger   (scaffold; server-side schedules deferred)
kiwi policy check [-f FILE] [--trusted]
kiwi version
```

## Repository layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component map and
[FILE_MAP.md](FILE_MAP.md) for a per-file inventory (generated by
`cmd/filemap`).

## Status

v0.1 development series. The core is a compiling, tested engine rather
than a claim of feature parity with GitHub Actions or GitLab CI; the
parts that exist are built as security boundaries first. See
[ROADMAP.md](ROADMAP.md) for what is done and what remains.

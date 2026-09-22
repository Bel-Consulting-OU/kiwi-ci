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
  Prometheus metrics. The runs collection is keyset-paginated so older
  runs stay reachable; see [docs/runs-api.md](docs/runs-api.md).
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

- Go 1.27.1 or later.
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
  --runner-tokens-file /etc/kiwi/runner-tokens.json \
  --tls-cert /etc/kiwi/server.crt \
  --tls-key /etc/kiwi/server.key \
  --data-dir /var/lib/kiwi
```

Production mode enforces its contract at startup: database URL,
distinct tokens (or `--allow-shared-token`), an `https://` external URL
(the OIDC issuer), and TLS. The runner-auth half is enforced once the
database is open, because per-runner bearer credentials may already be
provisioned in `runner_bearer_tokens`: production requires at least one
actual per-runner mechanism — enforced runner mTLS
(`--runner-ca-cert`/`--runner-ca-key` with `--runner-require-client-certs`)
or per-runner bearer credentials (`--runner-tokens-file`, a JSON map of
runner ID to SHA-256 token digest, or rows already provisioned in
`runner_bearer_tokens`).

The shared `--runner-token` is **dev/bootstrap compatibility only**: a
production server clears it at startup, so it can never authenticate
runner traffic there, and a production server with only `--runner-token`
and no per-runner credentials refuses to start. HA replicas share every
signing material through the database-backed cluster key store by
default; an explicit `--cluster-key-dir` on shared storage is the
alternative, while a per-node `--data-dir` key store is refused in
HA/production mode. See
[docs/production-deployment.md](docs/production-deployment.md).

Configuration can also come from a `kiwi.toml` file
(`--config kiwi.toml`, checked with `kiwi config check`); precedence is
CLI flags > `KIWI_*` environment variables > config file > defaults.

Untrusted jobs are bounded at admission by server-side resource ceilings —
2 CPU, 4 GiB memory, 10 GiB disk and 256 PIDs per job plus at most 8
services — and a declaration above a ceiling is rejected before the run is
signed or persisted (`untrusted_resource_ceiling_exceeded` /
`untrusted_service_ceiling_exceeded`); trusted jobs are unconstrained. The
ceilings are configurable under `[quota]` (`untrusted_cpu_ceiling`,
`untrusted_memory_ceiling`, `untrusted_disk_ceiling`,
`untrusted_pids_ceiling`), by flag, or by `KIWI_QUOTA_UNTRUSTED_*`
environment variable; see
[docs/pipeline-reference.md](docs/pipeline-reference.md#untrusted-ceilings).

## Runner

```bash
./kiwi runner --server http://127.0.0.1:8080 \
  --token "$KIWI_RUNNER_TOKEN" --labels macos,arm64
```

For mTLS identity binding, create a runner CA (or let the server
persist one with `--data-dir`), set `--runner-enroll-token`, and start
the runner with `--runner-enroll-token`/`--runner-mtls`. The runner
generates its key locally; the server signs a certificate with a
server-synthesized `spiffe://kiwi/runner/<id>` identity (the CSR's own
identity fields are ignored), so each runner has a persistent,
revocable per-runner identity — unlike the shared runner bearer token.
The runner negotiates protocol v3, drains cleanly on `--drain`, and
self-cancels if it loses contact with the control plane past its lease
deadline.

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
kiwi replay RUN JOB [STEP]   (restores the exact workspace snapshot)
kiwi schedules list|trigger
kiwi outbox dead-letters list|requeue|delete
kiwi policy check [-f FILE] [--trusted]
kiwi version
```

`kiwi outbox dead-letters` lists forge-delivery intents that exhausted
their retries and can requeue or delete one by ID (DB mode takes
`--database-url`). See [docs/upgrades.md](docs/upgrades.md#behavioral-compatibility-notes)
for the outbox versioning and dead-letter semantics.

## Repository layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component map and
[FILE_MAP.md](FILE_MAP.md) for a per-file inventory (generated by
`cmd/filemap`).

## Status

v0.1 development series. The core is a compiling, tested engine rather
than a claim of feature parity with GitHub Actions or GitLab CI; the
parts that exist are built as security boundaries first. See
[ROADMAP.md](ROADMAP.md) for what is done and what remains.

## Install

Prebuilt binaries for macOS (Intel/Apple Silicon), Linux (amd64/arm64)
and Windows are attached to every
[GitHub release](https://github.com/Bel-Consulting-OU/kiwi-ci/releases)
together with `SHA256SUMS`, per-binary CycloneDX SBOMs, and signed
provenance envelopes.

macOS via Homebrew (bottle-less formula in `Formula/kiwi.rb`):

```bash
brew install ./Formula/kiwi.rb
# or host the formula in a tap and `brew tap`/`brew install` from there
```

Docker (distroless, nonroot, static binary):

```bash
docker pull ghcr.io/bel-consulting-ou/kiwi-ci:v0.1.0
docker run --rm -p 8080:8080 ghcr.io/bel-consulting-ou/kiwi-ci:v0.1.0
```

Build your own with `make release` (cross-compiled bundle) and
`make docker-build`. See [docs/releases.md](docs/releases.md) for the
release/snapshot gates, artifact verification, signing-key lifecycle, and
reproducible builds.

## CI status

CI is **Woodpecker-only** (`.woodpecker/` multi-workflow layout; agent
selection is by workflow-level labels). There is no GitHub Actions workflow
and no other CI system in this repository.

| Workflow | Agent label | What it runs |
|---|---|---|
| `linux-amd64` | `platform=linux/amd64` | format, vet, unit (`-vet=all -shuffle`), race, race-double, single-P (`GOMAXPROCS=1`), checkptr (`-d=checkptr=2 -race`), stress (`-count=10` adversarial patterns), adversarial, schema (+FILE_MAP), cross, license, docs, repro, staticcheck (`-checks=all` minus stylistic), govulncheck (`-test`), fuzz smoke (30s/target) |
| `linux-arm64` | `platform=linux/arm64` | unit + race natively |
| `docker-workspace` | `platform=linux/amd64`, `capability=docker` | REQUIRED rootless/hardened container workspace integration; a missing/unusable Docker daemon FAILS this lane. Mounts the host Docker socket, so it is trusted push/manual/tag-only (never `pull_request`) |
| `integration-coverage` | `platform=linux/amd64` | PostgreSQL service + integration tests + merged coverage with the 95% floor |
| `native-windows` | `platform=windows/amd64` | native Windows `go vet` + full unit suite + the platform-sensitive packages (safefs, tui, executor, runner, storage, workspace, config). Trusted events only |
| `native-macos` | `platform=darwin/arm64` | native macOS unit + race + termios/Tart-sensitive packages. Trusted events only (local backend executes on the host) |
| `nightly` | `platform=linux/amd64` | cron: every fuzz target for 5 minutes plus the 50x stress battery |

Operational requirements for the Woodpecker instance:

- Every execution and service image is **pinned by OCI digest** in the
  workflow files.
- `WOODPECKER_FORCE_IGNORE_SERVICE_FAILURE=false` on the server, so the
  PostgreSQL service being down fails `integration-coverage` instead of
  being ignored (see [docs/production-deployment.md](docs/production-deployment.md)).
- `docker-workspace` mounts the agent host's Docker socket into its steps
  (`volumes: - /var/run/docker.sock:/var/run/docker.sock`), so the repository
  must be marked **trusted** in Woodpecker; `capability=docker` only selects
  an agent and injects nothing. Woodpecker gates volumes on the
  repository-level Trusted flag alone (no per-event or fork gating), so the
  lane runs on trusted events only (`push`/`manual`/`tag`) and never on
  `pull_request`; running it on PRs again needs a socket-less variant. A
  dedicated agent that mounts the socket into every pipeline container
  instead can set
  `WOODPECKER_BACKEND_DOCKER_VOLUMES=/var/run/docker.sock:/var/run/docker.sock`.
- Commit-status contexts use Woodpecker's canonical
  `ci/woodpecker/<event>/<workflow>` form, with the pull_request event mapped
  to the literal `pr`, so branch protection requires names like
  `ci/woodpecker/pr/linux-amd64` (not the flat pre-event form). The native
  macOS/Windows workflows run on trusted events only, so their `push/`
  contexts are not required for, and cannot be produced by, pull requests.
  Platform labels use the canonical `GOOS/GOARCH` slash form
  (`platform=linux/amd64`), matching the built-in agent label.

`main` is branch-protected: merges require a pull request, the workflow
contexts above green, and the branch up to date. Protection is applied by
`make protect-branch` (`scripts/gh-branch-protection.sh`), which REFUSES to
install any context it has not observed on a recent commit. By default the
script emits the legacy `contexts` array; set
`KIWI_WOODPECKER_APP_ID=<app-id>` to emit app-bound required checks
(`checks: [{"context": "...", "app_id": <id>}, ...]`), which pins each
context to the Woodpecker GitHub App instead of accepting a same-named status
from any publisher. App-bound checks are sent with
`X-GitHub-Api-Version: 2022-11-28` (override `KIWI_GH_API_VERSION`) and
`Accept: application/vnd.github+json` (`KIWI_GH_ACCEPT`; GitHub Enterprise
Server older than 3.9 needs the legacy
`application/vnd.github.luke-cage-preview+json` media type). Dependabot keeps
Go modules current with weekly PRs (`.github/dependabot.yml`); tool versions
are pinned in the workflow files and upgraded deliberately (see
[docs/upgrades.md](docs/upgrades.md)).


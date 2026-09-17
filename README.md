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
(the OIDC issuer), and TLS. The `--runner-token` is a SHARED credential
across all runners — not a per-runner identity — so production strongly
prefers persistent per-runner mTLS identities (`--runner-ca-cert`/
`--runner-ca-key` plus enrollment); without a runner token, enforced
runner mTLS is required. See
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
`make docker-build`.

## CI status

CI runs on [Woodpecker CI](https://woodpecker-ci.org) (`.woodpecker.yml`);
the GitHub Actions workflows have been removed. Every push, pull request,
manual run and tag executes one pipeline with these lanes:

- `format`, `vet`: `gofmt -l` and `go vet ./...`.
- `unit`, `race`: `go test -shuffle=on -timeout=15m ./...` and the race
  detector build; both run on a `linux/amd64` and a `linux/arm64` matrix leg
  (the arm64 entry needs an agent labelled `platform=linux/arm64`; remove the
  matrix entry when the fleet has none).
- `adversarial`, `fuzz-smoke`: the adversarial/security/property suites and
  10-second fuzz smoke over every registered fuzz target.
- `schema`: pipeline schema tests plus `go run ./cmd/filemap --check`.
- `cross`, `docs`, `license`, `repro`: cross-compilation, documentation and
  licence presence checks, and byte-identical reproducible builds.
- `staticcheck` (`honnef.co/go/tools/cmd/staticcheck@v0.8.1`) and
  `govulncheck` (`golang.org/x/vuln/cmd/govulncheck@v1.8.0`, needs network):
  pinned tool versions, cached through the shared `/go` workspace volume.
- `smoke`: builds the binary and validates `.kiwi/pipeline.yaml` and
  `examples/kiwi.yaml` (container-free; `kiwi run` needs a container runtime
  and is covered by the executor test suites).
- `coverage`: `go test -coverprofile=coverage.out ./...` prints the total and
  enforces the floor through `scripts/coverage-floor.sh` (default
  `KC_MIN_COVERAGE=60`).
- `integration-postgres`: a real PostgreSQL 16 service container, a
  stdlib-only readiness probe, then
  `KIWI_TEST_POSTGRES_URL=... go test -count=1 -timeout=20m -run Integration
  ./internal/storage ./internal/scheduler ./internal/server`. The tests create
  and drop their own `kiwi_it_<random>` schema per test, so the lane is
  repeatable and never touches shared tables.

A `nightly` cron job in the Woodpecker repository settings (schedule
`0 3 * * *`, branch `main`) runs the `fuzz-nightly` step: every fuzz target
for 30 seconds.

Woodpecker reports one commit status per workflow leg. With the server
defaults (`WOODPECKER_STATUS_CONTEXT=ci/woodpecker` and the default context
format with a `/<axis_id>` suffix for matrix legs) this pipeline reports
`ci/woodpecker/push/woodpecker/1` (amd64) and `.../2` (arm64) on pushes, and
the matching `/pr/` contexts on pull requests. `main` is branch-protected:
merges require a pull request, those Woodpecker contexts green, and the branch
up-to-date with `main`; admins are not exempt. The protection rule is applied
idempotently by `make protect-branch` (`scripts/gh-branch-protection.sh`,
repo-admin token required); the required contexts are configurable
(`KIWI_WOODPECKER_CONTEXTS`) and must match the Woodpecker instance
configuration. Dependabot keeps Go modules up to date with weekly PRs
(`.github/dependabot.yml`); CI tool versions are pinned in `.woodpecker.yml`
and upgraded deliberately (see [docs/upgrades.md](docs/upgrades.md)).

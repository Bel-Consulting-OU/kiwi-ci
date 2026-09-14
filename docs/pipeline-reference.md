# Pipeline reference

This document describes the Kiwi CI pipeline language, version 1
(`version: 1`). It matches the typed schema in
`internal/pipeline/spec.go` and the limits enforced by
`internal/pipeline/validate.go`. A machine-readable JSON Schema
(Draft 2020-12) lives at `.kiwi/schema.json` and is embedded in the
binary; a test pins the two together.

Example:

```yaml
version: 1
name: app

on:
  push:
    branches: [main]
  pull_request:
    paths: ["src/**", "go.mod", "go.sum"]

inputs:
  flavor:
    type: string
    default: dev

env:
  CGO_ENABLED: "0"

secrets: [npm_token]

defaults:
  shell: bash
  timeout: 15m
  retry:
    max: 1
    backoff: 2s

concurrency:
  group: "${{ repo }}:${{ branch }}"
  cancel_in_progress: true

jobs:
  test:
    matrix:
      GO: ["1.23", "1.24"]
    cache:
      - name: deps
        key: "go-${{ matrix.GO }}"
        hash_files: [go.sum]
        paths: [".kiwi/go-cache"]
    steps:
      - name: test
        run: go test ./...

  build:
    needs: [test]
    runtime: container
    image: golang@sha256:0123...
    steps:
      - run: go build ./...
```

## Top level

| Key | Type | Description |
|---|---|---|
| `version` | int | Must be `1` (or absent; defaults to 1). |
| `name` | string | Optional pipeline name. |
| `on` | map | Trigger filters keyed by event (`push`, `pull_request`, ...). |
| `inputs` | map | Typed inputs for manual dispatch. |
| `env` | map | Pipeline-level environment variables. |
| `secrets` | list | Secret names resolvable by any job in the pipeline. |
| `defaults` | object | Default shell, timeout, and retry policy. |
| `permissions` | object | `id_token: true` requests OIDC issuance. |
| `concurrency` | object | Run-level concurrency group. |
| `packages` | map | Declared monorepo packages with paths and dependencies. |
| `components` | map | Component references (`ref`, `with`). |
| `jobs` | map | Required. At least one job. |

## Jobs

A job has a `steps` list (required, at least one step) plus:

- `name` — display name.
- `needs` — list of job IDs this job depends on. The DAG is validated:
  unknown dependencies, duplicates, self-references, and cycles are
  rejected. A job whose dependency fails is `blocked` unless its `if`
  condition admits the failed status.
- `if` — condition expression evaluated against the aggregate dependency
  status. See [conditions.md](conditions.md).
- `runner` — required runner labels; a runner must carry all of them.
- `runtime` — `native`, `container`, or `tart` (see below).
- `image` — container image (`runtime: container`). Untrusted jobs must
  pin an `@sha256:` digest.
- `vm` — Tart VM reference (`runtime: tart`); required for Tart.
- `network` — `bridge`, `host`, or `none`.
- `shell` — see shell resolution below.
- `timeout`, `queue_timeout` — Go durations (`30s`, `15m`).
- `retry` — `max` (attempts beyond the first), `backoff` (exponential,
  default 1s), `on` (retry classes; see below).
- `infra_retries` — extra attempts budget for lost-runner requeueing by
  the control plane.
- `env` — job-level environment.
- `matrix` — see below.
- `paths`, `paths_ignore` — glob filters over the event's changed files.
- `services` — sidecar containers (see below).
- `cache` — cache restore/save declarations.
- `artifacts` — artifact upload declarations.
- `downloads` — artifact downloads from dependency jobs.
- `test_reports` — JUnit globs uploaded for test intelligence.
- `environment` — protected-environment targeting (see
  [environments.md](environments.md)).
- `permissions` — `id_token: true`.
- `outputs` — named job outputs, interpolatable by dependents.
- `sandbox` — `rootless`, `read_only_rootfs`, `network`.
- `placement` — `regions`, `labels` steering.
- `resources` — `cpu`, `memory`, `disk`, `pids`.
- `tests` — `reports`, `manifest`, `shards`, `retry_failed`,
  `quarantine_flaky`.
- `generate` — child graph generation (`path`, `max_jobs`, `max_depth`).
- `downstream` — trigger a pipeline in another repository.
- `deployment` — `canary`, `verify`, `rollback` step lists.
- `snapshot` — `on` events that capture a workspace snapshot.
- `component` — `name@sha256:...` reference; resolved server-side.
- `with` — component input values.

### Matrix

`matrix` maps dimension names to scalar value lists (strings, numbers,
booleans). Expansion is deterministic (sorted dimension order) and
produces one compiled job per combination, named
`job[K=v,K2=v2]`. Matrix values are available as `${{ matrix.NAME }}`
and as `KIWI_MATRIX_<NAME>` environment variables. A `needs` reference
to a base job expands to every combination.

### Runtime rules

- `native`: runs on the runner host. Must not set `image` or `vm`.
  Denied for untrusted pipelines.
- `container`: Docker-isolated Linux jobs. Image required at execution
  time.
- `tart`: disposable Apple Silicon VMs. `vm` is required.

### Steps

| Key | Type | Description |
|---|---|---|
| `id` | string | Step identifier; used for outputs. |
| `name` | string | Display name (defaults to `step-N`). |
| `run` | string | Required shell script. |
| `if` | string | Condition; defaults to `success()`. |
| `shell` | string | Shell override for this step. |
| `working_directory` | string | Workspace-relative directory. |
| `env` | map | Step-level environment. |
| `secrets` | list | Secret names visible only to this step. |
| `timeout` | duration | Per-step deadline. |
| `retry` | object | Per-step retry policy. |
| `continue_on_error` | bool | Record failure but keep the job going. |

A hard step failure does not abort the job: later steps whose conditions
admit the new status (`failure()`, `always()`, ...) still run. After
cancellation, only steps that explicitly admit the cancelled state run,
under a 60-second cleanup budget.

Shell resolution order: step `shell` > job `shell` > `defaults.shell` >
per-runtime default (`sh` for containers, `bash` for Tart, `pwsh` on
native Windows, `bash` otherwise). Allowed names: `bash`, `sh`, `zsh`,
`pwsh`, `powershell`, `fish`, `dash`, `ksh`, `python`.

### Retry classes

`retry.on` accepts: `failure` (command failures), `infra`
(infrastructure), `timeout`, `cancelled`, `command` (alias of
`failure`), `any`. An empty `on` list retries everything except
cancellation.

### Services

`services` runs sidecar containers for `runtime: container` jobs on a
dedicated network:

```yaml
services:
  - name: db
    image: postgres@sha256:0123...
    env: {POSTGRES_PASSWORD: dev}
    healthcheck: pg_isready -h localhost
    interval: 5s
    timeout: 10s
    retries: 5
```

When `sandbox.network` is `none` or `services-only`, the network is
created with `--internal`, so the job can reach its services but not the
internet. With no services, those policies map to network `none`
(container backend) or fail closed (Tart backend).

### Cache

```yaml
cache:
  - name: deps
    key: go-${{ matrix.GO }}
    hash_files: [go.sum]
    paths: [.kiwi/go-cache]
    restore_keys: [go-]
```

The final key is `sha256(namespace|key|GOOS|GOARCH|runtime|hashed
files)`. Restore tries the primary key then `restore_keys` in order.
Caches save only on job success. See [cache.md](cache.md).

### Artifacts and downloads

```yaml
artifacts:
  - name: app
    paths: [dist/**]
    if: success()
    retention: 7d   # or "forever"
downloads:
  - from: build
    name: app
    path: .
```

`downloads.from` must be a declared `needs` dependency. Retention
accepts Go durations or `forever`/`infinite`/`never`. See
[artifacts.md](artifacts.md).

### Deployment

`deployment.canary`, `deployment.verify`, and `deployment.rollback` are
step lists executed as the corresponding phases for environment jobs.
See [environments.md](environments.md).

### Snapshot

`snapshot.on` lists the events that trigger a workspace snapshot upload
to the control plane (`success`, `failure`, `always`, `never`).

## Expressions and interpolation

`${{ ... }}` holes interpolate in most string fields. See
[conditions.md](conditions.md) and the expression engine
(`internal/expr`).

## Validation limits

Enforced on every admission path (`internal/pipeline/validate.go`):

| Limit | Value |
|---|---|
| Pipeline source | 2 MiB |
| Scalar | 1 MiB |
| YAML depth / nodes | 100 / 1,000,000 |
| Declared jobs | 1,024 |
| Expanded jobs per run | 4,096 |
| Matrix dimensions | 12 |
| Matrix combinations per job | 512 |
| Steps per job | 512 |
| Services per job | 32 |
| Secret names per job | 128 |
| Env vars per job (and per step) | 1,024 |
| Command | 1 MiB |
| Env value | 64 KiB |
| Artifact definitions | 128 |
| Output keys | 256 |

Also rejected: absolute paths and `..` components in path fields,
negative or zero explicit durations, unknown shells/network modes/runtime
combinations, non-scalar matrix values, empty matrix dimensions, invalid
IDs, duplicate step IDs, duplicate dependencies, duplicate artifact
names, unknown interpolation contexts, and unterminated `${{ ... }}`.

## YAML restrictions

The parser (yaml.v3 plus node-level validation) rejects aliases,
anchors, merge keys, custom tags, duplicate keys, multiple documents,
unknown fields, invalid UTF-8, and oversized scalars, with line-accurate
errors.

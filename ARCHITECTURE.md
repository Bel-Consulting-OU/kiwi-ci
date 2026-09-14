# Kiwi CI architecture

Kiwi CI separates **orchestration** from **execution** while keeping one
pipeline compiler and one expression engine for local and remote use.
One binary plays three roles: CLI (`kiwi run`, `validate`, `explain`),
control plane (`kiwi server`), and worker (`kiwi runner`).

## Flow

```
forge webhook → verify + dedupe → fetch pipeline (base commit for forks)
  → parse (yaml.v3, strict) → validate (limits) → policy admission
  → component resolution → compile graph (matrix, interpolation)
  → enqueue run + jobs (Postgres) → scheduler leases jobs
  → runner claims lease → checkout → execute DAG node → heartbeat
  → cache/artifact upload, log stream, test reports → complete (receipt)
  → dependents recomputed → forge status via durable outbox
```

## Components

1. `cmd/kiwi` — command router for the CLI, control plane, and runner.
2. `internal/app` — CLI command implementations: local run/validate/
   explain, doctor, init, server/runner startup, ops commands
   (runs/jobs/logs/cancel/approve/rerun/artifacts/schedules/policy),
   dispatch, database and config commands, artifact verification.
3. `internal/pipeline` — the v1 language: strict YAML parsing, typed
   spec, admission validation and limits, canonical JSON digests,
   deterministic matrix expansion, path matching, conditions, JSON
   Schema (pinned to `.kiwi/schema.json`).
4. `internal/expr` — expression and interpolation engine: parsed AST,
   context resolution (`matrix`, `needs`, `steps`, `env`, `runner`,
   `job`, `repo`, `git`, `event`, `inputs`, `kiwi`, `extra`, status
   scalars), built-in functions (`success`, `failure`, `cancelled`,
   `always`, `contains`, `startsWith`, `endsWith`, `fromJSON`,
   `toJSON`, `hashFiles`), deterministic evaluation.
5. `internal/executor` — job execution: DAG readiness, condition
   gating, per-step state machine with failure/cleanup semantics,
   retries, secret scoping, cache and artifact handling, and the
   backend contract (native, container, Tart), services, environment
   construction, outputs.
6. `internal/workspace` — isolated per-job workspaces for local runs
   (git worktree, APFS reflink, copy fallback).
7. `internal/cache` — cache archives, key computation, remote
   restore/save, signed manifests.
8. `internal/artifact` — artifact capture, manifests, retention.
9. `internal/blob` / `internal/cas` — immutable content store (`fs`,
   `s3`) and the SHA-256 content-addressed layer.
10. `internal/safefs` — hardened archive extraction and filesystem
    limits for untrusted input.
11. `internal/secrets` — local secret providers and multi-form log
    masking.
12. `internal/secretbroker` — remote broker interface with Vault, AWS,
    GCP, Azure, and 1Password providers, one-time delivery, sealed
    envelopes.
13. `internal/runnerpki` — Ed25519 runner CA, CSR enrollment,
    `spiffe://kiwi/runner/<id>` identities, mTLS verification.
14. `internal/auth` — principals, roles, per-repo grants, hashed token
    store, HTTP middleware.
15. `internal/policy` — capability sets, intersection, deny-by-default
    admission, untrusted floor.
16. `internal/scheduler` — PostgreSQL-backed scheduler: job-level
    leases, heartbeats, completion, expired-lease recovery, dependency
    outcomes, environment concurrency, priority, quotas, leader
    election.
17. `internal/storage` — the Store contract: PostgreSQL implementation
    with migrations, and the filesystem dev repository.
18. `internal/model` — shared control-plane types.
19. `internal/server` — HTTP API, webhook intake, leases, logs
    streaming, artifacts/cache endpoints, OIDC issuer, test intel,
    snapshots, deployments, GC, metrics, health, sessions, outbox, web
    UI.
20. `internal/forge` — GitHub, GitLab, and Forgejo adapters: webhook
    verification, event parsing, file/diff fetching, trigger matching,
    check/status publishing, GitHub App auth.
21. `internal/trigger` — trigger matching and schedule idempotency keys;
    `internal/server/schedules.go` fires leader-gated occurrences with
    exactly-once nominal claims.
22. `internal/importer` — migration importers for GitHub Actions,
    GitLab CI, CircleCI, and Woodpecker.
23. `internal/impact` — monorepo package graphs and affected-package
    computation.
24. `internal/snapshot` — workspace snapshot capture and restore with
    entry manifests.
25. `internal/deploy` — deployment lifecycle records.
26. `internal/components` — reusable digest-pinned job components
    resolved server-side.
27. `internal/explain` — the `--why` reasoning model.
28. `internal/queue` — queue reason codes.
29. `internal/quotas` — cost/energy accounting and quota limits.
30. `internal/ratelimit` — token-bucket per-class request limiting.
31. `internal/testintel` — streaming JUnit parsing and flaky-test
    history.
32. `internal/config` — `kiwi.toml` loading, environment and flag
    overlay, validation.
33. `internal/version` — build identity and protocol/schema versions.
34. `internal/logging` — structured logs and log sinks.

## Scheduling and leases

The remote scheduler is per-job. The control plane compiles the
pipeline into jobs with `needs` edges, stores them in PostgreSQL, and
leases individual jobs:

```
compiled job → ready queue → label/region match → environment
concurrency → priority (downstream depth) + age → lease (generation,
45s default) → heartbeat → execute → result + receipts → recompute
dependents → run status
```

A lease has an expiry and a generation number. Only the HMAC of the
raw lease token is persisted. Completion is idempotent through
generation-bound receipts. Lost runners are detected by lease expiry;
jobs requeue within the `infra_retries` budget, and runners
self-cancel when they lose contact past the acknowledged deadline, so
at most one valid generation executes after its lease expires. The
local executor uses the same condition evaluator over an in-process
DAG, preserving local/remote parity.

## Execution trust modes

- `native`: fastest; executes on the runner host. Trusted pipelines
  only.
- `container`: Docker-isolated Linux jobs with capability drop,
  rootless verification, and immutable-image enforcement for untrusted
  runs.
- `tart`: disposable Apple Silicon VMs; the default choice for
  untrusted macOS jobs.

## Scheduling guarantees

The compiler rejects unknown dependencies, self-dependencies, duplicate
dependencies, and cycles before execution. A job becomes runnable only
after all dependencies reach a terminal state and its condition admits
the aggregate outcome; failed dependencies block downstream jobs unless
the condition says otherwise (`always()`, `failure()`, ...).
Cancellation uses context propagation, process-group termination in
native mode, and a bounded 60-second cleanup phase for steps whose
conditions explicitly admit the cancelled state.

## Security invariants

- Webhook handlers verify signatures before any state mutation;
  deliveries are deduplicated.
- Trust is derived server-side; untrusted pipelines are clamped to a
  hard capability floor (no secrets, OIDC, native execution, or
  egress).
- Runner traffic authenticates by bearer token or mTLS certificate
  enrollment; every request is bound to its runner identity.
- Secrets resolve only for jobs holding an active lease, travel in
  sealed envelopes, and are scoped per step on the runner.
- Log masking happens at the source and again at display sinks.
- Cache and artifact extraction rejects traversal and resource abuse;
  payload digests are verified on write and read.
- Production control planes require PostgreSQL, TLS, and distinct
  admin/runner credentials; HA uses advisory-lock leader election.

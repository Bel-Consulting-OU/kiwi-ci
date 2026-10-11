# Changelog

All notable changes to Kiwi CI are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions before 0.1.0 are unreleased development builds; entries describe
the state of the `main` branch.

## [Unreleased]

### Added

- Execution-assurance levels (`model.ExecutionAssurance`) and
  external-effects classes (`model.ExternalEffectsClass`), derived purely
  from the durable job/payload/policy records. Execution attestation
  schema v4 binds the level, name, effects class, effective-policy digest,
  event-ledger frontier and run-graph fingerprint into the canonical
  digest; undefined values are refused at build and verification.
- Graph causality for dynamically generated jobs: `CreatedByNode`,
  `CreatedByMutation` and a bounded opaque `ExternalContext`, echoed in
  `graph.mutation_*` events and deliberately excluded from the fragment
  digest.
- Public evidence contract ([docs/evidence-contract.md](docs/evidence-contract.md)):
  the DSSE/in-toto evidence envelope, its field map, the six independent
  version dimensions, the assurance ladder, exact replay versus
  bit-reproducibility, evidence profiles and an explicit "what Kiwi does
  not guarantee" boundary.
- Forensic evidence materialization: `GET /api/v1/jobs/{id}/attestation?profile=forensic`
  returns the unsigned `kiwi-ci/execution-evidence-bundle/v1` bundle — the
  signed envelope plus the bounded run-scoped event timeline, digest/reference-only
  artifact, snapshot and report records, and retention watermarks.
- `kiwi up`: single-machine mode running the control plane and one local
  runner in one process, with the ledger, caches, artifacts and evidence
  rooted in one state directory. The state directory and persisted bearer
  token are verified before use (real directory owned by the current user,
  tightened to 0700; token file must be an owned 0600 regular file, created
  exclusively), and the control-plane listener is bound before the server
  starts so a local port squatter can never receive the runner credential.
- Formal TLA+ mirror of the lease/commit/retry/cancel protocol
  (`formal/kiwi_lease.tla`, bounded TLC instance, model-to-test mapping).
- Fuzz lanes for the completion wire body, secret issuance and OIDC
  issuance, registered in the fuzz smoke script.

### Changed

- Completion receipt replay across the runtime-evidence upgrade: a stored
  legacy (v1) receipt now replays only when the retried completion's
  normalized runtime evidence is nil-or-equal to the evidence the original
  attempt persisted (the server owns and re-fills the `Components` map from
  the job's component digest), exactly as before the v1 receipt was written.
  A retry whose runtime evidence genuinely differs still conflicts.

### Fixed

- The executor's privileged-tool proof now lives on unix rather than Linux
  and the platform-specific XFS/cgroup tests are tagged, so executor test
  binaries build and run on macOS and Windows.
- The cache namespace-lock helper process parks on a timer instead of
  `select{}`, so Go's deadlock detector can no longer kill it and silently
  release the lock mid-test; the cross-process lock test is deterministic.
- Runner test isolation pins the developer's Docker CLI context
  (`DOCKER_CONFIG`) and makes the maintenance tests hermetic, so runner
  lifecycle tests no longer depend on the host's container-runtime
  configuration.
- The enrollment-grant liveness fixture seeds an expired record directly
  instead of racing a one-nanosecond TTL against coarse host clocks.
- The staging canonical-dir fallback test skips with a documented reason
  on hosts (macOS) that resolve the path of a removed working directory,
  where `filepath.Abs` cannot fail.

## [0.1.0] - unreleased

Initial development version. Everything below is new in this release.

### Added

- Pipeline language v1: jobs, steps, needs-based DAG, deterministic matrix
  expansion, `if` conditions, per-step retries, caches with hash files and
  restore keys, artifacts with retention, downloads between jobs, test
  reports, environments with approval and concurrency, services, sandbox,
  placement, resources, test configuration, generate, downstream,
  deployment (canary/verify/rollback), snapshots, components, `with`
  inputs, and `on` trigger filters.
- Expression and interpolation engine (`internal/expr`): context
  references (`matrix`, `needs`, `steps`, `env`, `runner`, `job`,
  `inputs`, `repo`, `git`, `event`, `branch`, `ref`, `sha`, `status`,
  `kiwi`, `extra`) and the functions `success()`, `failure()`,
  `cancelled()`, `always()`, `contains()`, `startsWith()`, `endsWith()`,
  `fromJSON()`, `toJSON()`, `hashFiles()`.
- Strict YAML parsing via yaml.v3 with node-level validation: known
  fields only, duplicate keys, aliases, anchors, merge keys and custom
  tags rejected; 2 MiB source limit, depth and node limits, line-accurate
  errors.
- Hard pipeline admission limits (1024 declared jobs, 4096 expanded jobs,
  12 matrix dimensions, 512 combinations per job, 512 steps per job, and
  more) enforced on every admission path.
- Canonical JSON rendering and SHA-256 pipeline digests.
- JSON Schema (Draft 2020-12) for the pipeline language, embedded and
  pinned to `.kiwi/schema.json` by a test.
- Execution backends: native (process-group cancellation), hardened
  container (capability drop, no-new-privileges, rootless verification,
  read-only rootfs), and Tart VMs for macOS.
- Isolated per-job workspaces for local runs (git worktree, APFS reflink,
  copy fallback).
- Unified step state machine: `always()`/`failure()`/`cancelled()` steps
  run after failures with a bounded cleanup context.
- Cache system: content-addressed archives keyed by declared inputs and
  hash files, remote restore/save against the control plane, safe
  extraction via `safefs`, signed cache manifests over the blob/CAS
  layer.
- Artifacts: deterministic tar.gz capture with sidecar manifests,
  retention, provenance statements, and download contracts between jobs.
- Control plane HTTP API: runs, jobs, logs (including SSE streaming),
  artifacts, cache, test reports, snapshots, deployments, approvals,
  runner registration/leases, audit listing, OIDC discovery/JWKS and
  per-job audience-scoped token issuance.
- PostgreSQL storage with embedded migrations, transactional job
  completion, idempotent completion receipts, and session-level advisory
  locks for leader election.
- Job-level scheduler: per-job leases with generation counters, HMAC-only
  persisted tokens, heartbeat extension, orphan recovery within the
  infrastructure retry budget, priority (downstream depth) and age
  ordering, environment concurrency, queue reasons.
- Runner PKI: Ed25519 CA, `spiffe://kiwi/runner/<id>` identities,
  one-time enrollment tokens, mTLS binding, protocol negotiation v3.
- Runner self-cancellation when the control plane becomes unreachable
  past the acknowledged lease deadline.
- Auth and RBAC: hashed token store, principals with global roles and
  per-repository grants, admin/runner token separation, spoof-resistant
  audit actor identity.
- Capability-based admission policy: repository/organization/trust-domain
  intersection, deny-by-default untrusted floor, OIDC audience
  allowlists, egress policy, secret allowlists.
- Secret broker: Vault, AWS, GCP, Azure, and 1Password providers, chained
  lookup, one-time delivery, and X25519+HKDF+AES-GCM sealed envelopes
  delivered per active lease; per-step secret scoping on the runner.
- Forge integrations: GitHub (App auth, Checks API, webhook verification,
  delivery dedupe, fork-safe pipeline fetch from the base commit), GitLab
  (token verification, commit statuses), Forgejo (HMAC verification),
  with `on` trigger matching for all three.
- Test intelligence: streaming JUnit parsing, per-run report storage,
  flaky-test history, quarantine flag, sharding and failed-test retry
  configuration.
- Monorepo impact graphs: declared packages with dependencies, changed
  files to affected packages.
- Importer scaffold for GitHub Actions, GitLab CI, CircleCI, and
  Woodpecker pipelines.
- Reusable digest-pinned components resolved server-side at enqueue.
- Workspace snapshots with entry manifests and root digests.
- Deployment lifecycle records for environment jobs.
- Cost/energy accounting primitives and quota validation.
- Per-class token-bucket rate limiting.
- CLI: `init`, `run`, `validate`, `explain --why`, `doctor`, `server`,
  `runner` (plus `runner list|drain|disable|enable`), `dispatch`, `runs`,
  `jobs`, `logs`, `cancel`, `approve`, `rerun`, `artifacts`, `schedules`
  (scaffold), `policy check`, `database migrate|status`, `config check`,
  `version`.
- Config file (`kiwi.toml`) with CLI > environment > file > defaults
  precedence, dev and production modes, TLS, blob backend selection,
  rate limits.
- Web dashboard with session cookies, CSRF protection, and live log
  streaming.
- Prometheus-style `/metrics`, `/readiness`, `/liveness` endpoints.
- Durable forge-status outbox that survives restarts.

### Security

- Lease tokens persisted only as HMAC-SHA256 hashes; raw tokens exist
  only in runner memory.
- Cancelled or completed jobs lose their lease immediately; completion is
  idempotent via generation-bound receipts instead of dead leases.
- Server restarts preserve unexpired leases instead of force-requeueing
  running jobs.
- Runners run a minimal clean environment; host environment inheritance
  is an explicit local opt-in (`--inherit-env`/`--pass-env`) and is never
  used for remote jobs.
- Cache and artifact extraction hardened against traversal, symlink
  parents, duplicate entries, and resource exhaustion.
- GitHub credentials scoped to the canonical clone host; credential
  requests never follow redirects.
- OIDC issuance denied for untrusted jobs; audiences policy-controlled.
- Untrusted jobs require immutable `@sha256:` pinned images and VMs.
- Webhook handlers verify signatures before any state mutation; deliveries
  are deduplicated per forge delivery ID.

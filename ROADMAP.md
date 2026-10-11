# Kiwi CI roadmap

Status key: **Done** (in `main`), **P1** (next), **P2** (later).
The done list corresponds to the production-hardening audit items
implemented in phases 1-7; the remaining lists are the audit items and
extensions not yet implemented.

## Done

### Correctness and security (audit P0, phases 1-3)

- Clean runner environment with explicit `--inherit-env`/`--pass-env`
  opt-in for local runs only.
- Network egress policy (`none` / `services-only` / `internet`) with
  `--internal` service networks; Tart fails closed on `none`.
- Active-lease authorization (status + expiry + runner + generation)
  for every mutation endpoint; leases cleared on cancel/complete.
- Lease tokens persisted only as HMAC-SHA256 hashes.
- Server restarts preserve unexpired leases (no duplicate executions).
- Runner self-cancellation at the acknowledged lease deadline.
- Host-scoped Git credentials; redirect-free credential clients.
- Tart SSH host authentication kept on; per-job known hosts.
- Step outputs read inside the sandbox, not host-side.
- `internal/safefs`: hardened extraction (no symlink/hardlink/device
  entries, duplicate/`..`/absolute rejection, size/depth/ratio limits).
- OIDC denied for untrusted jobs; audience allowlists.
- Capability-based admission policy with intersection and a
  deny-by-default untrusted floor.
- Blob/CAS layer (`internal/blob`, `internal/cas`) with signed cache
  manifests and trust-domain namespaces.
- Runner PKI: Ed25519 CA, one-time enrollment, SPIFFE identities,
  mTLS binding, protocol negotiation v3.
- Auth/RBAC: hashed token store, principals with roles and per-repo
  grants, trusted/run split, spoof-proof audit actor.
- PostgreSQL storage with migrations and transactional completion;
  completion receipts for idempotent replay.
- HA leader election via session advisory locks with standby
  promotion; leader-only lease/recovery duties.
- Scheduler split out of the server god-file
  (`internal/scheduler`): leases, dependencies, priority, environment
  concurrency, quotas, unified condition semantics.

### Pipeline language (audit phase 4)

- yaml.v3-based strict parser: known fields, duplicate/alias/merge/tag
  rejection, size/depth/node limits, line-accurate errors.
- v1 spec expansion: placement, sandbox, resources, permissions,
  tests, generate, downstream, deployment, snapshot, components, with,
  queue timeout, packages.
- Rigorous admission limits (2 MiB source, 1024 declared / 4096
  expanded jobs, 12 matrix dimensions, 512 combinations, 512 steps,
  and the rest of the limit table).
- Expression/interpolation engine (`internal/expr`) with validated
  contexts and the standard function set.
- Canonical JSON and SHA-256 pipeline digests.
- Runtime-resolved shell defaults (step > job > defaults > per-runtime).

### Developer experience (audit phases 5-7)

- `kiwi init` scaffold generator.
- JSON Schema (Draft 2020-12) for pipeline YAML, embedded and pinned.
- `kiwi explain --why JOB` with event/branch/path/condition/policy/
  queue reasoning.
- Isolated per-job workspaces (git worktree, APFS reflink, copy).
- Step failure/cleanup state machine with bounded cleanup context.
- Web UI: dark dashboard, session cookies, CSRF protection, SSE log
  streaming.
- Forge adapters (GitHub/GitLab/Forgejo) with verified webhooks,
  trigger matching, delivery dedupe, canonical coordinates, GitHub App
  auth, Checks API, durable outbox.
- Secret broker (Vault/AWS/GCP/Azure/1Password) with one-time sealed
  delivery and per-step scoping; multi-form log masking.
- Test intelligence: streaming JUnit, per-run reports, flaky history,
  quarantine/shard/retry configuration.
- Monorepo impact graphs from declared packages and changed files.
- Components: digest-pinned reusable jobs resolved server-side.
- Workspace snapshots with entry manifests.
- Deployment lifecycle records and environment approvals/concurrency.
- Importer scaffold (GitHub Actions, GitLab CI, CircleCI, Woodpecker).
- `kiwi.toml` config with CLI > env > file > defaults precedence;
  dev/production modes; `kiwi config check`.
- Rate limiting (per-class token buckets), structured logs, Prometheus
  metrics, readiness/liveness endpoints.
- Ops CLI: `runs`, `jobs`, `logs --follow`, `cancel`, `approve`,
  `rerun`, `artifacts`, `runner list|drain|disable|enable`, `policy
  check`, `database migrate|status`.
- Queue reason codes surfaced to the API, UI, and explain output.

## Done (audit closure rounds 19-22)

- Runner wire-semantic protocol v2 with an explicit negotiation floor and
  a rolling-upgrade protocol (`docs/production-deployment.md`).
- Execution-semantics versioning (`model.ExecutionSemanticsVersion`),
  distinct from every wire/schema version, stamped at enqueue and bound
  into signed evidence.
- Scoped execution-event retention/recovery with typed cursors and
  snapshot parity (`docs/INVARIANTS.md` I4).
- Written invariant contract (`docs/INVARIANTS.md`): I1-I10 with
  enforcement points, regression tests and a per-class evidence map.
- Formal lease/commit/retry/cancel mirror (`formal/kiwi_lease.tla`).
- Execution assurance levels and external-effects classes
  (`model.ExecutionAssurance`, `model.ExternalEffectsClass`), derived
  from durable records and bound into execution attestation schema v4.
- Public, neutral evidence contract (`docs/evidence-contract.md`):
  in-toto v1 + DSSE envelopes, SLSA-v1 artifact provenance, exact-replay
  versus bit-reproducibility, assurance/effect vocabulary, profiles
  (minimal/standard/forensic) and an explicit "what Kiwi does not
  guarantee" boundary.
- Bounded graph-causality stamp for dynamically generated jobs
  (`CreatedByNode`, `CreatedByMutation`, opaque `ExternalContext`).
- Adversarial fuzz lanes at the wire boundaries: event cursors, generated
  fragments, completion bodies, secret issuance, OIDC issuance.
- Single-machine mode: `kiwi up` runs the control plane, a local runner,
  the ledger, caches, artifacts and evidence from one command.

## Core abstraction freeze

The audit's closure rule applies from this point: the core concepts are
FROZEN. New features must not change the MEANING of:

```text
runs, graphs, nodes, jobs, attempts, events, claims, capabilities,
artifacts, caches, replay, evidence, execution assurance, effect classes
```

Changes that need no architecture round:

- additive, version-gated fields (each with its own schema-version bump);
- new values in the closed sets that already define a bump rule;
- performance, operability, UX and deployment improvements.

Changes that REQUIRE an explicit semantics bump
(`model.ExecutionSemanticsVersion` and/or the evidence schema), an update
to `docs/INVARIANTS.md` and `docs/evidence-contract.md`, and mirrored
tests:

- changing how durable state is interpreted by the scheduler, runner or
  executor;
- changing the assurance ladder, the effect classes or the replay
  definition;
- adding a speculative/parallel-attempt surface (which additionally
  requires extending `formal/kiwi_lease.tla` with the speculation action
  and the single-winner invariant before the surface merges, per
  `formal/README.md` and I7).

## P1 — remaining

- Concurrency groups beyond supersession (queue serialization of
  in-progress groups).
- Pipeline debugger beyond `kiwi replay RUN JOB [STEP]`: interactive
  per-step diffing against the snapshot.
- OpenTelemetry metrics/logs export in addition to traces.

## P2 — governance and observability

- Full audit log retention and org/repository RBAC hierarchy beyond
  the current principal model.
- OpenTelemetry metrics/logs in addition to traces.
- Cost/energy reporting surfaced per team and repository from the
  existing quota primitives.
- Regional runner pools with speculative prewarming of images and VMs.
- Graceful schema compatibility checks in the upgrade workflow.
- Merge queues with superseded-run cancellation.
- Signed SBOM + Sigstore verification gates integrated with the
  provenance layer.

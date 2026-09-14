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

## P1 — remaining

- Server-side schedules: cron storage, leader-fired occurrences, and
  the `kiwi schedules` implementation (idempotency keys already exist
  in `internal/trigger`).
- Live TUI with searchable, virtualized, collapsible logs.
- OpenTelemetry traces and export (endpoint currently accepted as a
  no-op).
- Replay CLI: wire `kiwi` completion-replay tooling over the existing
  generation-bound receipts.
- Artifact transport through the CAS layer so payloads shared with
  cache entries are stored once.
- Nightly fuzz CI for the parser, expression engine, and `safefs`
  extraction.
- OIDC signing-key rotation with a previous-verification window.
- Deployment and snapshot record persistence in PostgreSQL (currently
  memory-backed).
- Windows Job Object cancellation for full descendant killing.
- SBOM attachment and Sigstore-style signature verification gates.
- Pipeline debugger: rerun one failed step against the exact workspace
  snapshot.
- Repository/organization policy file compilation (the
  `AdmissionCapabilities` seam exists; policy files are not compiled
  yet).
- Job-level heterogeneous runners across one DAG with
  runner-to-runner artifact/CAS transfer.
- Dynamic pipelines: typed generated child graphs end-to-end
  (`generate` parsed and validated; execution wiring incomplete).
- Cross-repository downstream pipelines end-to-end (`downstream`
  parsed and validated; execution wiring incomplete).
- Concurrency groups beyond supersession (queue serialization of
  in-progress groups).
- Scheduled/manual/API event parity for trigger matching (manual and
  API paths exist; scheduled firing does not).

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

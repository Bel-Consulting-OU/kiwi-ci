# Upgrades

This document describes the versioned surfaces of Kiwi CI and how to
upgrade a deployment safely.

## Versioned surfaces

| Surface | Version | Source |
|---|---|---|
| Runner API protocol | 3 | `internal/version` (`ProtocolVersion`), negotiated `ProtocolMin`/`ProtocolMax` per runner |
| Pipeline language | 1 | `PipelineSchemaVersion`; `version:` field in pipeline YAML |
| Storage snapshot (fs dev store) | 1 | `StorageSchemaVersion`; `Snapshot.Version` |
| PostgreSQL schema | sequential migration numbers | `internal/storage/migrations/*.sql` |

## Protocol negotiation (v3)

Runner registration declares `protocol_min`/`protocol_max` (both 3 for
current binaries). The server accepts only an overlap with its own
range. If security semantics change, old runners are rejected rather
than silently allowed to ignore new fields.

Upgrade order for protocol changes:

1. Upgrade the server (accepts the old protocol range if it still
   overlaps);
2. Upgrade runners;
3. Raise the minimum when the fleet has converged.

## Pipeline schema (v1)

The parser accepts `version: 1` only (absent defaults to 1). Unknown
versions are rejected at parse time, so a pipeline written for a newer
schema fails loudly rather than misbehaving. JSON Schema validation is
available through `.kiwi/schema.json`; a test pins the embedded schema
to that file.

## PostgreSQL migrations

Migrations are embedded and applied automatically at server startup
when a database URL is configured, or explicitly:

```bash
kiwi database migrate --database-url "$DATABASE_URL"
kiwi database status  --database-url "$DATABASE_URL"
```

Rules:

- Migration files are append-only and numbered; never edit a released
  migration.
- Apply migrations before deploying the new binary across instances
  (the new server performs this itself; multiple instances racing the
  migrate step is handled by the migration's transactionality).
- A schema bump in a migration implies the server release needs it;
  check `database status` after every upgrade.

### Migration locks

The automatic startup migration applies DDL in version order, one file per
transaction, so each file is its own lock window:

- The `outbox` metadata change in migration 0018 (`ALTER TABLE ... ADD COLUMN`
  with a constant default, plus the new empty `forge_check_state` table) is
  fast: the `ACCESS EXCLUSIVE` lock on `outbox` lives only for that file's
  catalog-only statements and is not held across any index build.
- The two `outbox` index builds (migrations 0019/0020, matching the unique
  `(logical_key, state_version)` identity and its pending variant) are
  non-concurrent and each hold a write-blocking `SHARE` lock on `outbox` for
  the duration of that single build. Reads are unaffected; `INSERT`s from
  completions and webhooks queue until the build finishes. This is brief for
  typical outbox sizes; on a deployment carrying a very large dead-letter
  backlog (for example after a long forge outage), plan a maintenance window
  so enqueues are not delayed.
- No manual step is required: the server migrates at startup, the split keeps
  each lock window independent, and re-running is idempotent (`IF NOT EXISTS`).

## Upgrade procedure

1. Back up PostgreSQL, the data directory key files (lease, OIDC, CA),
   and the blob store. See
   [disaster-recovery.md](disaster-recovery.md).
2. Drain runners you plan to replace: `kiwi runner drain <id>`.
3. Deploy the new server binary; it migrates the schema on startup.
4. Deploy new runners; verify protocol negotiation (`kiwi runner list`
   shows version metadata).
5. Verify health (`/readiness`), a canary pipeline run, and forge
   status delivery (outbox replay).

### Resource reservation ledger after a rolling upgrade

Migration 0030 adds the durable per-lease resource reservation ledger
(`job_resource_reservations`). It is written by the ATOMIC lease claim, so a
mixed-version window has two gaps: an OLD binary leases jobs without writing
rows (the ledger under-reserves, and a new leader could admit work the runner
cannot hold), and an OLD binary serving `/complete` or `/cancel` does not
delete the row of the job it finished (the ledger over-reserves that runner).
The new binary closes both:

- A new leader rebuilds the ledger from the authoritative persisted lease
  state BEFORE its first lease (the promotion hook), and the capacity reads
  count only rows whose job is still running, still leased and at the
  recorded generation — so an orphan row an old replica left behind stops
  shrinking the runner's capacity immediately, without operator action, and a
  new leader's rebuilt rows stop the over-admission.
- If a ledger is still mis-stated (the promotion hook failed, or the repair
  is wanted after the old replicas have drained), run the repair command an
  operator can invoke at any time:

  ```bash
  kiwi storage reconcile-reservations --database-url "$DATABASE_URL"
  ```

  It is idempotent, safe while the fleet serves traffic, serialized against
  other reconciliations and against leadership hand-over, and prints the
  operator-facing counters
  (`resource reservations reconciled: running=N upserted=N deleted=N`).
  It derives every row from the running jobs' persisted leases, never from
  caller input, so re-running it converges. No schema change is needed for
  the repair.
- Legacy service jobs: a job enqueued before the service-envelope field
  existed declares services with no `service_envelope_request`. A promoted
  leader cannot know the aggregate those services may consume, so it charges
  the job's own request a second time as the envelope (a conservative upper
  bound of the executor's fair split) instead of a zero envelope that would
  oversubscribe the runner. The rule stops applying as soon as those jobs
  end; a job written by this release always carries the field and is charged
  exactly its persisted envelope.

## Rollback

Rolling back the server binary is safe as long as the database schema
is compatible: new columns are additive. If a release contained a
breaking migration, roll back by restoring the database snapshot and
redeploying the old binary plus its data directory files.

fs mode has one silent data-loss boundary in that procedure. A binary
that predates the durable deployment records does not know the
`deployments` field of the data-dir snapshot
(`storage.Snapshot.Deployments`). It decodes `state.json` without those
records, and its first persist -- the server persists at startup and
after every mutation -- rewrites the whole snapshot from its own struct
and permanently drops every deployment record created after the
upgrade. Before downgrading across that boundary, export/back up the
deployment records (or do not downgrade); do not assume restoring the
data directory files alone preserves them. The PostgreSQL store is
unaffected: its deployment rows live in their own table.

The same silent-drop class does not apply to fs schedule occurrence
claims: they ride the separate `schedules.json` (`occurrences` field),
which pre-deployments binaries already read and rewrite. What older
snapshots lack is the run metadata (`schedule_id`/`schedule_nominal`)
this version uses to adopt a committed run after a crash between the
two fs writes; a downgrade loses that crash-window exactly-once
compensation (a crash in the window can refire a nominal) but not the
claims themselves.

## Behavioral compatibility notes

- Unrunning jobs carry their pipeline text, so a control plane
  restarted on a new version recompiles deterministically against the
  new compiler; test canary pipelines before rolling upgrades across
  large fleets.
- Lease and completion semantics (generation-bound receipts, HMAC-only
  tokens) are stable across restarts within protocol v3.
- Deployment records now persist durably: PostgreSQL through
  `DeploymentStore`, fs mode through the data-dir state snapshot
  (alongside `SnapshotStore` records, which were already persisted).
  Existing deployments are NOT backfilled: a snapshot written by an
  older version contains no deployment records, so deployments created
  before the upgrade are absent from listings after it. There is no
  migration for them; treat pre-upgrade deployment history as lost.
- fs-mode mutations are fail-closed when the snapshot write fails: the
  mutation is refused instead of acknowledged, the in-memory state
  rolls back to its pre-mutation value, and `/readiness` answers 503
  (`X-Kiwi-State: degraded`) until a later persist succeeds. The write
  paths whose state rides the snapshot are:
  - `POST /api/v1/runs` (503; enqueue persist failures used to map to
    400 and never acknowledge a run body) and the webhook enqueues
    `POST /hooks/github`, `/hooks/gitlab`, `/hooks/forgejo` (503).
  - `POST /api/v1/runners/{id}/next` (503 fixed body, the lease token
    is withheld, and the in-memory claim is reclaimed by the documented
    recovery contract).
  - `POST /api/v1/jobs/{id}/heartbeat` (503, see below).
  - `POST /api/v1/jobs/{id}/complete` including receipt replays,
    `.../approve`, `.../cancel` (503, no state change).
  - `POST /api/v1/jobs/{id}/snapshots`,
    `PUT /api/v1/jobs/{id}/artifacts/{name}`, sidecar attachment,
    `POST /api/v1/jobs/{id}/deployments`, runner
    `drain`/`disable`/`enable`, and generated fragments
    (`POST /api/v1/jobs/{id}/generated`) (503, with the record or
    artifact rolled back).
  - Runner-profile writes, cert-profile binds and runner-ID profile
    binds (`POST`/`PUT /api/v1/runner-profiles`,
    `PUT /api/v1/runner-profiles/{id}/cert/{serial}`,
    `PUT`/`DELETE /api/v1/runner-profiles/{id}/runner/{runnerID}`),
    test reports (`POST /api/v1/jobs/{id}/tests`) and schedule creation
    (`PUT /api/v1/schedules`) answer 500 or 503 after rolling back the
    partial record.
  - Maintenance lease recovery has no HTTP surface but runs the same
    rollback and degrades readiness.
  A 503 from these paths means the mutation did NOT partially apply;
  it also means it was not queued. The client must resubmit it once the
  instance (or the data directory) is writable again.
- Heartbeat is fail-closed: a heartbeat that cannot be persisted
  answers 503 and does not extend the stored lease expiry. The runner
  only moves its local deadline forward from confirmed responses, so a
  control plane that stays degraded until the acknowledged deadline
  makes the runner self-cancel instead of running on an extension the
  control plane never recorded.
- The forge outbox carries a versioned delivery identity. Each logical
  check is keyed by `(run, check)`; publications are ranked
  `queued=1 < running=2 < completed=3`; a newer version supersedes an
  older pending delivery; and the delivered-version watermark advances
  in the same statement as the ACK. A dispatcher guard refuses to
  publish a version at or below the delivered watermark, so a stale
  replay after a restart can never regress the remote check.
  `completion_reconcile` (internal effects) and `forge_delivery` are
  separate intents: internal reconciliation is retried until it
  converges and is never dead-lettered, while forge delivery follows
  the bounded retry/dead-letter policy. Unknown intent kinds are a
  second never-dead-lettered class that matters during rolling
  upgrades: a row written by a newer binary is neither dropped (ACKed
  away) nor dead-lettered by an older replica -- dispatch returns a
  typed error, the claim is released, and the row survives with bounded
  backoff until a replica that understands it processes it. A store or
  replica that cannot dispatch a kind must therefore leave it queued,
  not consume it. Legacy pre-0018 rows without
  version fields are normalized at dispatch (the logical key is derived
  from host + run + check name, the version from the status rank), so
  they obey the same watermark. A store that does not implement the
  `storage.ForgeCheckStateStore` contract (including
  `OutboxMarkDelivered`, which stamps the watermark for those legacy
  rows) is refused fail-closed by dispatch and versioned enqueue: no
  publication happens without the guard. Operators inspect and recover
  dead letters with:
  ```bash
  kiwi outbox dead-letters list [--database-url "$DATABASE_URL"]
  kiwi outbox dead-letters requeue <id> [--database-url "$DATABASE_URL"]
  kiwi outbox dead-letters delete <id> [--database-url "$DATABASE_URL"]
  ```
- Enqueue is fail-closed for custom stores: server enqueue requires
  the `storage.RunEnqueueStore` atomic contract
  (`InsertCompiledRun`). A store that does not implement it (for
  example an embedder's `storage.Store` wrapper) is refused at startup,
  and any HTTP enqueue that still reaches it (`POST /api/v1/runs`,
  `/hooks/github`, `/hooks/gitlab`, `/hooks/forgejo`) is refused with
  503 instead of falling back to a non-atomic scheduler enqueue plus a
  best-effort delivery upsert. The built-in memory, fs, and PostgreSQL
  stores implement the contract; no action is needed unless you
  wrapped the store.
- The native macOS/Windows workflows are Woodpecker local-backend
  jobs: they select dedicated agents by label
  (`platform=darwin/arm64` + `backend=local`,
  `platform=windows/amd64` + `backend=local`), run in `bash`/`pwsh`
  directly on the worker host, and are restricted to trusted events
  (`push`, `manual`, `tag`; never fork pull requests). Provision the
  workers as one-shot ephemeral hosts running the agent as a dedicated
  low-privilege user with no persistent credentials and Go 1.27.x on
  `PATH` (`GOTOOLCHAIN=local` prevents Go from downloading a toolchain
  and masking a stale worker). The `docker-workspace-diagnostic` job builds
  its digest-pinned test image locally from `ci/image/Dockerfile`
  (Go + git + Docker CLI + certs + make/gcc) instead of pulling one
  from a registry. It is a non-blocking diagnostic (`failure: ignore`):
  the current Woodpecker topology cannot run the workspace invariant (the
  docker backend exposes the pipeline workspace as a named volume), so the
  old required `ci/woodpecker/push/docker-workspace` context no longer
  exists and must be removed from any branch/ruleset that still requires it;
  see
  [production-deployment.md](production-deployment.md#native-and-local-ci-agents).
- fs-mode `/readiness` is now durability-aware: when a data-dir snapshot
  write fails, it answers 503 with `X-Kiwi-State: degraded` and a fixed body
  (the raw error is only logged), new leases are refused until a later
  persist succeeds, and switching the server to DB mode clears the state.
  Operators upgrading an fs-mode deployment must make probes and load
  balancers stop routing to a degraded instance; a healthy `/liveness` does
  not mean the instance can accept new work.
- Servers started with `--tls-cert`/`--tls-key` now actually serve TLS.
  Previously the flags were accepted but the listener stayed plaintext, so
  probe, load-balancer, and backend configurations pointed at such a server
  must move to `https://` (or terminate TLS in front of the instance) as
  part of the upgrade; a plaintext request to the TLS listener fails. See
  the probe guidance in
  [production-deployment.md](production-deployment.md#health-and-metrics).
- Runners fail closed at startup when no durable state directory can be
  resolved: the per-job log journal needs an explicit state/cache root, the
  enrollment identity directory (`--identity-dir`), or `HOME`, and the
  runner now refuses to start instead of silently running journal-less. A
  service unit that does not set `HOME` (common under systemd) must set
  `HOME` for the runner user or pass `--identity-dir <dir>`; the identity
  directory doubles as the state directory.
- Untrusted resource ceilings are configurable, and their rejections are
  named. An untrusted pipeline that declares a resource above a ceiling is
  refused at admission with `400` and reason
  `untrusted_resource_ceiling_exceeded` (never clamped); an unset dimension
  is filled with the ceiling, and trusted jobs are unconstrained. The
  built-in defaults are unchanged — 2 CPU, 4 GiB memory, 10 GiB disk,
  256 PIDs — so a pipeline that previously ran with e.g. `memory: 8GiB`
  under an older release now fails at submission. Raise a ceiling without
  rebuilding via `kiwi.toml`
  (`[quota] untrusted_memory_ceiling = 8589934592`, memory/disk in plain
  bytes, `0` disables a dimension), the equivalent flags
  (`--untrusted-cpu-ceiling`, `--untrusted-memory-ceiling`,
  `--untrusted-disk-ceiling`, `--untrusted-pids-ceiling`) or the
  `KIWI_QUOTA_UNTRUSTED_*` environment variables.
- The untrusted per-job service ceiling (`8`) is now enforced at
  ADMISSION instead of only by the executor before it starts containers: an
  untrusted submission declaring 9–32 services is rejected before it is
  signed, persisted or queued, with `400` and reason
  `untrusted_service_ceiling_exceeded`. Trusted pipelines keep the 32
  service allowance. Existing untrusted pipelines with more than 8 services
  that used to fail mid-run now fail at submission; split the job or
  reduce its sidecars (the ceiling is not configurable).
- Distributed runners now bound dependency spooling with a runner-wide
  staging budget: every restore reserves its exact artifact size (or the
  8 GiB per-artifact cap for chunked bodies) before downloading, so
  concurrent restores can no longer stage an unbounded amount of
  compressed data outside the job workspace quotas. The default budget is
  one maximum-size object (8 GiB), which serializes maximum-size spools;
  raise it with `--staging-max-bytes` and point
  `--staging-dir <dir>` at a dedicated filesystem for multi-GB dependency
  runs. A budget smaller than an artifact fails that restore closed.
- The declared job timeout is persisted at enqueue (`job_timeout`, the
  compiled job timeout or `defaults.timeout`) and the distributed runner
  starts it before workspace setup and checkout, so checkout, dependency
  restore and changed-files discovery are inside the declared budget.
  Legacy records without the field get a 15-minute setup-phase ceiling
  (`--setup-timeout <duration>`), so an unreported job timeout can no
  longer mean a `git clone` may hang forever.
- Staging cleanup debt is now maintained: a dependency spool whose removal
  fails keeps its bytes charged (fail-closed) and a dedicated 30-second
  maintenance pass retries the removal, so a transient unlink error can no
  longer wedge the default one-artifact budget for the life of the runner.
  The state is observable through `kiwi_runner_staging_bytes`,
  `kiwi_runner_staging_pending_cleanup` and
  `kiwi_runner_staging_cleanup_failures_total`. A fully joined `Run` retires
  the staging ownership (lock + registry entry) at shutdown; a shutdown
  still blocked by cleanup debt deliberately retains the OPEN ledger, and an
  in-process restart with the same bound reuses it (a changed bound fails
  with a clear error) until the debt is reclaimed.
- Post-job delivery is explicitly bounded: artifact and generated-fragment
  uploads stay inside the declared job timeout, and a deadline that cuts an
  artifact upload off now reports the job as cancelled instead of green
  with a warning. Test-report delivery and snapshot capture get a separate
  `--finalize-timeout` grace (default 2m), and terminal completion is
  bounded per call (30s) while honoring runner shutdown — a timed-out job
  still reports because completion is called with the runner context, and a
  wedged control plane can no longer pin the runner slot.
- A deadline during dependency restore now reports `cancelled` like a
  deadline during checkout; the setup phase uses one status rule
  (`statusForErr(setupCtx, err)`) for every context-bounded subphase.
- Distributed artifact packaging is now a temporary, budgeted publication
  path instead of the persistent local artifact tree: each archive is
  bounded by `min(8 GiB, the declaration's max_size)`, reserves its full
  size from the runner-wide staging budget before the first byte, and is
  deleted together with its manifest immediately after delivery. A
  distributed job can no longer accumulate archives outside the workspace
  quota. Cache archives now use the same 8 GiB default bound locally that
  the restore path and the upload endpoint already enforced (previously an
  unconfigured store wrote unbounded archives), and both cache and artifact
  archive creation stop promptly when the job deadline expires.
- Cancellation cleanup steps now survive only the JOB deadline, never the
  runner lifecycle: the runner passes its lifecycle context to the executor,
  so a shutdown aborts user cleanup immediately instead of waiting out the
  cleanup grace past the drain window, while a job that merely hits its own
  timeout still gets its bounded cleanup and `if: cancelled()` diagnostic
  artifacts. Success-only cache publication is skipped as soon as the job
  context ends, so a dead deadline can no longer spend minutes compressing
  an archive that is then discarded.
- Runner-local caches now have a REAL aggregate capacity bound: one shared
  cache manager per runner owns the root and policy, and every per-job store
  reserves capacity through it before a save OR a remote restore writes
  bytes, evicting least-recently-used entries until the reservation fits
  (default 32 GiB / 4096 entries / 14 days; `--cache-max-bytes`,
  `--cache-max-entries`, `--cache-max-age`, with `--cache-archive-max-bytes`
  for the per-archive bound). Inline retention uses the job context, eviction
  re-checks the ranked entry so a concurrent refresh is never deleted on
  stale information, and the download preflight uses the resolved per-archive
  bound instead of a raw zero that disabled it. A pipeline rotating its
  logical cache key can no longer fill the runner disk, even through many
  concurrent remote restores.
- Durable shared-cache manifests are retained per (repository, trust domain)
  namespace: an untrusted fork-PR manifest flood can never evict the
  protected repository's trusted entries, prune deletes only the exact
  ranked version (`created_at` + blob digest re-matched), and fs mode
  re-reads the manifest immediately before removal. The per-namespace byte
  bound counts LOGICAL manifest bytes (not digest-deduplicated) and is
  documented as a conservative upper bound. Secret broker scopes now carry
  the canonical authorization repository id
  (`storage.RepoIDForJob`) instead of the clone URL, with the checkout URL
  available as a separate field.
- Durable shared-cache manifests now have control-plane retention
  (`cache_manifest_retention`, default 30 days;
  `max_cache_manifests_per_repo`, default 4096;
  `max_cache_manifest_bytes_per_repo`, default 64 GiB): manifests are
  pruned per repository oldest-first, after which the CAS collector reclaims
  their blobs unless another reference remains. Cache key hashing and cache
  restore now observe the declared job lifetime end to end, and cache
  definitions are capped per job (64 absolute, 16 for untrusted runs).
- Pre-checkout hard-quota gating for untrusted jobs is fail-closed for
  legacy/malformed tasks and does NOT trust the unverified compiled
  payload: the runtime always comes from the persisted pipeline (parse +
  compile + persisted job key), and a payload that disagrees or cannot be
  decoded refuses the checkout. The payload is only authoritative after
  `verifyCompiledPayload`, which runs after checkout.

## Dependency upgrade policy

- Dependabot opens weekly pull requests for Go modules (`gomod`,
  commit prefix `deps`), capped at 5 open PRs (`.github/dependabot.yml`).
  A full CI pipeline runs on every dependency PR; merge only when it is
  green. CI runs exclusively on Woodpecker (`.woodpecker/`), so
  there is no `github-actions` ecosystem to upgrade.
- CI tooling versions are pinned in `.woodpecker/linux-amd64.yml`, not
  floating:
  - `staticcheck` `honnef.co/go/tools/cmd/staticcheck@v0.8.1`: bump the
    pin in the `staticcheck` step when the toolchain moves forward and
    re-run the pipeline baseline.
  - `govulncheck` `golang.org/x/vuln/cmd/govulncheck@v1.8.0`: the
    release gate; it needs network access to the vulnerability
    database.
  - All steps run in `golang:1.27` images with `GOTOOLCHAIN: local`, so
    the pipeline toolchain is the module's `go` directive, not a
    floating latest.
  - Woodpecker pipeline syntax changes (`when`, `matrix`, `services`,
    `depends_on`) are checked against the Woodpecker instance version;
    the schema assumptions are documented in the `.woodpecker/`
    workflow headers. The upstream JSON schema is a good pre-flight
    check.
- Upgrading the Go toolchain (the `go` directive in `go.mod`) must
  happen before bumping the staticcheck/govulncheck pins, and is a
  separate PR from dependency bumps so bisection stays clean.
- The real-PostgreSQL integration lane runs on a `postgres:16-alpine`
  service container; bump the service image deliberately together with
  a green `integration-postgres` run.
- Docker base images are digest-pinned in the `Dockerfile`; re-resolve
  digests (`docker buildx imagetools inspect <image>`) whenever the
  image tag is bumped.
- Release signing is mandatory: `scripts/release.sh` fails closed
  without `KIWI_RELEASE_SIGNING_KEY`. Unsigned releases are only
  possible through an explicit `KIWI_ALLOW_UNSIGNED_RELEASE=1` and must
  be treated as a disaster-recovery exception, never the norm.
- The runner cache manager's reservation accounting is now fail-closed in
  three more ways: a deferred release after a successful publication is a
  no-op (it previously double-subtracted the charge, driving the ledger
  negative and allowing oversubscription), an aborted operation whose temp
  file cannot be removed keeps its charge as cleanup debt retried by the
  cache maintenance pass, and an expired entry whose eviction fails stays in
  the retention pass's byte/count accounting instead of making the policy
  look satisfied. Each runner process now uses a private
  `<cache root>/<runner instance id>` directory: the ledger and locks are
  process-local, so two runners sharing a root previously each believed they
  owned the whole budget. A `Run` started with a changed cache root or
  policy replaces the manager, and a runner-local cache is no longer shared
  across runner processes (the cache is a performance optimization; a real
  disk bound wins).
- Cache temp cleanup is now crash-safe and fail-closed. Startup reclaims
  abandoned `.<key>.tar.gz-*.tmp` / `.<key>.remote-*.tmp` files left by a
  killed process (never following symlinks or directories) and charges any
  file it cannot remove, so repeated abnormal restarts cannot strand
  unaccounted multi-GiB temps. The pre-namespace shared cache layout
  (`<root>/cache/*.tar.gz`) is reclaimed once per root on upgrade — local
  cache is disposable, and the per-runner namespace is the only supported
  layout. Replacing the manager across an in-process restart first retries
  temp debt and refuses a changed root/policy while any charge remains.
  `Manager.Publish` now rejects nil/foreign/ended reservations with
  `ErrInvalidReservation` before running the publication callback, and the
  temp-cleanup retry reads its pending map under the manager lock (the
  unlocked length check was a data race).
- Runner startup now configures the cache manager before the dependency
  staging budget, so a cache-manager refusal (for example outstanding cleanup
  debt from a previous Run with a changed policy) can no longer leak the
  externally owned staging directory lock for a Run that never started.
  Incomplete legacy-cache reclamation is retried on every cache maintenance
  pass instead of only at manager installation.
- Each runner-local cache namespace now has a REAL cross-process ownership
  lock (`<namespace>/kiwi-cache.lock`, flock on Unix, an atomic lock file
  with dead-owner probing elsewhere). A second live process with the same
  runner identity is refused at startup with `ErrCacheDirOwned` instead of
  reclaiming the first process's live temp files; destructive crash recovery
  only runs while the lock is held. Runner startup is transactional: if the
  staging configuration fails after cache ownership is acquired, the cache
  namespace is released again, and a fully joined shutdown closes it
  alongside staging. A closed manager refuses further reservations,
  publications, retention passes and temp retries. A transient lock-release
  failure is retryable: the manager (and the runner) retain the lock handle
  instead of discarding it.
- Legacy pre-namespace cache archives are NO LONGER deleted automatically.
  The per-runner namespace lock cannot prove a pre-namespace process is
  dead, so a rolling upgrade could delete a still-running old runner's cache
  archives. Once every pre-namespace runner has drained, reclaim them
  explicitly with
  `kiwi storage migrate-runner-cache-layout --dir <CacheRoot>/cache [--force]`
  (interactive confirmation; non-interactive runs without `--force` remove
  nothing).
- Lease-committing metadata writes (cache manifests, snapshots, artifacts)
  now evaluate lease expiry against the live database clock AFTER the job
  row lock, not the transaction-start timestamp. A commit that was blocked
  on another transaction's row lock while the lease expired is now rejected
  with `ErrLeaseLost` instead of publishing durable metadata after lease
  authority ended.

- A failed cache-namespace release at shutdown now leaves a retained CLOSED
  manager, and the next Run with identical configuration retries the release
  and installs a fresh open manager instead of returning early and running
  with a manager that rejects every cache operation. `Close` is serialized
  under the manager mutex, so concurrent/idempotent callers cannot race the
  lock handle.
- `kiwi storage migrate-runner-cache-layout` now resolves its default
  directory with the runner's two-level semantics:
  `KIWI_RUNNER_CACHE_LAYOUT_ROOT` names the legacy directory itself, while
  `KIWI_CACHE_ROOT` names the runner base and resolves to its `/cache`
  subdirectory. The confirmation prompt prints both.

- Lease lifetime is now database-clock authoritative in DB mode. Initial
  claims store `clock_timestamp() + TTL`, heartbeat renewal uses the same
  clock and refuses to renew a lease that already expired at it, recovery
  discovery/application compare against a post-lock `clock_timestamp()`, and
  handler-side expiry checks ask the store for database-clock liveness
  (`LeaseLive`) instead of consulting the replica clock (a DB store without
  that capability is refused with 503 rather than falling back to
  replica-clock liveness), completion re-checks the locked lease against a
  post-lock `clock_timestamp()` and stamps its lifecycle with the same
  database timestamp, and heartbeat responses carry the store-returned
  expiry directly (no second read or app-clock fallback). The legacy
  absolute-time heartbeat is bounded by a 24-hour horizon. Log ingestion is
  intentionally not lease-fenced (late-log grace: log lines carry no
  lifecycle authority and batch receipts are generation-scoped); every
  behavior-affecting runner mutation is commit-time fenced.
  Cross-replica application-clock skew can no longer
  extend, prematurely reject, prematurely recover, or prematurely complete
  a lease; the previous NTP synchronization *requirement* for lease safety
  is gone (NTP remains recommended hygiene).
- Runner heartbeats no longer read-modify-write the whole runner row
  (`GetRunner` -> `UpsertRunner`). A heartbeat that read the runner before a
  concurrent admin disable/drain/profile edit could write the pre-change
  snapshot back and silently undo the admin action. Heartbeat now uses the
  narrow `RunnerHeartbeatStore.TouchRunnerLastSeen`
  (`UPDATE runners SET last_seen=clock_timestamp()` in PostgreSQL) and
  touches nothing else; stores without the capability skip the advisory
  refresh instead of falling back to the whole-row write. `last_seen` is
  likewise no longer a profile field: `mergeRunnerProfile` preserves the
  committed instant across every profile/admin write, and registration
  explicitly touches it after the profile write, so a re-registration,
  drain or enable from a stale snapshot can never move it backward.
- Test-report uploads are now lease-fenced. Test history drives future
  shard assignment, duration balancing, the test manifest and flaky
  classification, so the delivery/report/fold transaction locks the job row,
  re-validates runner/generation and `lease_expires_at > clock_timestamp()`
  after the lock, and refuses a report whose lease expired while the request
  (or a row-lock wait) was in flight with the same 409 as an expired upload,
  committing nothing. The report's canonical `(created_at,id)` ordering
  instant is the fence's own database timestamp, so replica clock skew cannot
  reorder test history, and the 201/200 body returns the canonical stored
  report (including that instant). A DB store without
  `LeaseTestReportStore` is refused with 503 rather than committing
  unfenced history. Replay semantics are explicit: an identical delivery is
  acknowledged idempotently only while the lease is still live; after the
  lease has ended the retry is refused with 409 (the first commit stays
  durable and folded exactly once).
- The runner cache default root moved from the user-global cache root to the
  identity-local one (`<IdentityDir>/cache/<instance id>`) so two runner
  processes or identities sharing an account cannot contend for one
  namespace. An enrolled runner without an explicit `CacheRoot` now detects
  the old `<user cache root>/<instance id>` namespace at cache-manager
  configuration and warns with the exact reclaim command
  (`kiwi storage migrate-runner-cache-layout --dir <old namespace> --force`);
  the old tree is deliberately not deleted automatically, because only the
  operator can confirm every pre-upgrade process has drained.
- Cache-manifest retention now runs entirely in the database clock domain:
  `cache_manifests.created_at` (the ranking and age-pruning authority) is
  stamped with `clock_timestamp()` on insert and replacement by BOTH the
  plain and the lease-fenced writers, and the age cutoff is computed in SQL
  (`clock_timestamp() - interval`) instead of from the pruning replica's
  application clock. The signed payload keeps the producer instant as
  provenance. A skewed replica can therefore no longer age a fresh entry
  instantly, pin a stale one, or change which entry the per-repository
  entry/byte quotas evict.
- Deployment creation is now genuinely idempotent across replicas and
  restarts: `DeploymentStore.InsertDeploymentOnce` inserts with
  `ON CONFLICT (id) DO NOTHING` and returns the canonical STORED record with
  `created=false` on replay (a conflicting run/job/environment fails closed
  with `ErrDeploymentIdentityConflict`). The server caches only the stored
  record and emits `deployment.started` exactly once, so HA replicas and
  restarts converge on one durable row and one audit event.
- `POST /api/v1/jobs/{id}/deployments` now records a deployment only for a
  job that is actually RUNNING and derives `StartedAt` from the job's
  authoritative `StartedAt` instead of the request time; queued,
  waiting-approval, blocked and terminal jobs are refused with 409.
- `SwitchToDB` now also requires `DeploymentStore`: a DB store without the
  contract is refused at startup instead of silently degrading deployment
  lifecycle state to the process-local mirror.
- Enrollment-grant lifetimes are now store-clock authoritative:
  `EnrollGrantStore.PutEnrollGrantWithTTL` takes a duration and derives
  `expires_at` in the database (`clock_timestamp() + TTL`), the DB-mode gate
  asks the store for liveness (`EnrollGrantLive`, no application-clock expiry
  decision), and `ConsumeEnrollGrant` locks the grant row FIRST, samples
  `clock_timestamp()` after the lock and only then evaluates expiry (a
  single-statement `expires_at > clock_timestamp()` would evaluate before a
  row-lock wait and wrongly admit the consumer). A skewed replica can
  therefore neither extend nor pre-expire an enrollment credential, and a
  consumer that waits past expiry loses.
- Outbox claim leases now run entirely in the database clock: the due
  predicate (`next_attempt_at`), the claim cutoff
  (`claimed_at < clock_timestamp() - OutboxClaimTTL` computed in SQL) and the
  `claimed_at = clock_timestamp()` stamp carry no application timestamp, so a
  clock-ahead leader cannot steal another replica's live claim and a
  clock-behind one cannot strand a dead owner's claim. The claim time is also
  post-wait rather than transaction-start (`now()`).
- OIDC id_token issuance now takes a TTL, not absolute `iat`/`exp`: the
  commit returns `OIDCIssuanceResult{IssuedAt, ExpiresAt}` derived from its
  own commit clock (PostgreSQL: the post-lock `clock_timestamp()`), and the
  JWT and the durable `oidc.issued` audit both use those values, so the
  credential window can never disagree with the lease predicate that
  authorized it.
- DB-mode schedule due evaluation uses the shared database clock
  (`storage.ClockStore.Now`); a missing capability or a failed clock read
  SKIPS the tick instead of falling back to the leader's wall clock, so two
  leaders with opposite skew agree on the same due set and an ahead leader
  cannot fire an occurrence early.
- Non-Unix staging ownership release is retryable: a transient lock-file
  unlink failure no longer clears ownership, and `Budget.CloseWithContext`
  only finalizes/unregisters/closes its hand-off channel AFTER the ownership
  release succeeds, so a retry can complete the hand-off and a successor
  never starts while the directory may still be owned.
- Runner log-journal cleanup is now debt-based. A failed ack-time unlink no
  longer drops the journal's knowledge of the file: a (path, size) cleanup
  entry stays charged against the per-(job, generation) disk budget and is
  retried on later flushes, and a watermark-covered record whose unlink fails
  at startup is charged the same way instead of being silently ignored — so
  the advertised `asyncJournalBytes` physical bound stays truthful after
  crash/restart. Terminal removal separates logical closure from physical
  removal: `closed` releases the in-memory payload, `removed` is set only
  after `RemoveAll` AND the parent-directory fsync succeed, and a
  terminal-cleanup marker lets the next journal open (or the following job)
  sweep a stranded directory, so a transient EBUSY/EPERM cannot leak it
  across jobs or restarts.
- The OIDC preliminary lease gate now shares the runner gate's database-clock
  liveness authority (`LiveLeaseStore`): a skewed replica can neither reject
  a database-live lease before the commit, nor let a database-expired lease
  drive signer/key-ring/rotation work.
- Deployment start/finish state and audit are transactional:
  `StartDeployment` commits the record and its `deployment.started` audit in
  one transaction (an audit failure rolls the record back; replays append
  nothing), and `FinishDeploymentOnce` commits the finish marker and
  `deployment.completed` together exactly once across concurrent replicas and
  retries.
- Pipeline-controlled child output can no longer bypass the runner's resource
  budgets: service healthchecks are captured through a bounded drain
  (`executil.CaptureBounded`, 64 KiB retained, the rest discarded while the
  pipe keeps draining) with the error reporting `[output truncated]`; the
  executor's docker/tart helpers, repository-controlled git clone/checkout,
  prewarm pulls and the workspace `git status` probe all use the same bounded
  capture, so a hostile or wedged child cannot OOM the host or block on a
  full pipe.
- Retry policies now have finite central caps (`MaxStepRetries=20`,
  `MaxServiceRetries=100`, `MaxInfraRetries=20`) enforced at admission
  (defaults/job/step/service, including `math.MaxInt`, which previously
  wrapped the attempt arithmetic) and clamped again in the executor and in
  storage recovery for persisted legacy payloads. `retry.max: 0`,
  `services[].retries: 0` and `infra_retries: 0` are now EXPLICIT zero
  budgets (no retries / one healthcheck attempt / never requeue) instead of
  silently inheriting the defaults; presence is recorded at YAML parse time
  and included in the compiled-hash canonical form.
- An XFS project-ID assignment failure is treated as an AMBIGUOUS side
  effect: Kiwi removes the ID-named assignment first and releases the ID only
  when cleanup proves the removal, otherwise the ID stays allocated
  (quarantined). A workspace can therefore never share a project ID with a
  workspace that still carries it.
- Webhook replay handling is now both earlier and authenticated: the delivery
  fast path runs immediately after signature verification and event parsing,
  BEFORE any pipeline/changed-files fetch or trigger evaluation, and the
  SHA-256 of the authenticated body is stored as a body receipt so the same
  signed payload delivered under a fresh delivery header maps to the original
  run. A reused delivery ID with different content fails with 409, and the
  delivery header is mandatory for GitHub/GitLab/Forgejo webhooks. DB mode
  persists the body receipt transactionally with the enqueue.
- Pipeline YAML is rejected by an O(bytes) structural pre-decode budget
  (100k structural indicators) before yaml.v3 allocates its node tree, and
  the post-decode node cap is lowered to 100k, closing the
  input-byte-cap-vs-parser-memory gap for pathological compact documents.
- `generate.max_jobs`/`generate.max_depth` are enforced: the effective
  fragment ceiling is the global cap tightened by the parent's declared
  envelope, read from the persisted compiled parent job (and re-checked
  against the locked parent row), so a `max_jobs: 1` parent cannot be handed
  128 children.
- Container teardown is now a proven-gone state machine: `CloseJob` retains
  the container identity until `docker rm -f` succeeds or docker positively
  reports the container absent, and it does NOT restore workspace ownership or
  remove the XFS project quota while the runtime object may still exist (a
  live bind-mounted container must not outlive the quota that bounds its
  workspace). A failed removal leaves the job retryable; only proven absence
  advances to teardown. Tart clone deletion follows the same rule (the clone
  name is cleared only after `tart delete` succeeds or reports absence, and
  per-job SSH state is kept while a delete is retryable).
- Workspace quota/ownership cleanup callbacks are cleared ONLY on success:
  a failed XFS cleanup (for example one that correctly quarantined its project
  ID) stays retryable instead of leaking the allocation forever, and a partial
  ownership restore cannot leave the checkout under the workload uid.
- Webhook replay receipts now cover terminal no-run outcomes: a no-trigger
  delivery persists an IGNORED receipt (delivery + authenticated-body digest),
  so replays perform zero forge API work and return the same 204. The
  delivery/body receipts remain the successful-run dedupe path.
- A current-format compiled parent job whose generation envelope cannot be
  decoded (missing/invalid effective job) now fails generated-child admission
  closed instead of falling back to the wider global caps; only genuinely
  legacy records keep the documented global fallback.
- The remaining unbounded stderr paths are bounded: container ReadFile keeps a
  64 KiB diagnostic prefix from `docker exec cat` stderr, and Tart ReadFile
  bounds guest SSH stderr the same way. The S3 list reader now reads limit+1
  and rejects an over-limit response instead of accepting a truncated prefix,
  with a defensive cap on the parsed key count.
- Runner crash recovery is now immediate instead of a 24-hour GC wait: each
  runner process has a fresh instance ID, job containers, service containers
  and services networks carry `kiwi.runner`/`kiwi.instance` labels, and a
  restarted runner reconciles its OWN stable runner ID's previous-incarnation
  (or legacy unlabelled) resources BEFORE leasing new work. A SIGKILLed
  runner's detached runtimes can no longer keep touching a workspace while
  the replacement takes work; resources of other runners sharing the daemon
  are never touched, and the age-based GC remains a backstop.
- XFS project IDs are restart-safe: before allocating, the pool asks the
  filesystem (`xfs_quota -x -c 'report -p -n'`) for every project ID already
  present and permanently reserves them. A restarted runner can therefore
  never hand out an ID a previous process left assigned, and a report failure
  fails the quota capability closed instead of treating the ID space as
  empty.
- `RequireNonRoot` policy is enforced: `pipeline.Sandbox` gained `NonRoot`,
  the effective policy propagates it, the container backend pins the
  workload to `65534:65534` on rootful daemons (provisioning the workspace),
  the documented rootless meaning is the userns-mapped container UID 0 (which
  cannot map to host root), and native/tart runtimes are refused when the
  requirement cannot be enforced.
- A current-format compiled parent whose `EffectivePolicy` is missing or
  malformed now refuses generated children instead of falling back to trust
  defaults (which could be broader than the parent's actual enqueue-time
  capabilities); only genuinely legacy payloads keep the documented
  fallback.
- Ignored webhook receipts carry the authenticated payload digest in every
  store, so reusing a delivery ID with different signed content is a 409 for
  ignored outcomes too (it previously short-circuited as a 204).
- Production mode requires `KIWI_WEB_SESSION_SECRET` (a shared 32-byte hex
  key): without it each replica minted its own dashboard session/CSRF key and
  sessions broke on failover or restart.
- Lease scheduling applies bounded aging: waiting time buys up to 8 priority
  points at one point per 10 minutes, so a continuous stream of fresh
  high-priority jobs can no longer starve an eligible low-priority job
  indefinitely; downstream-depth priority remains the primary signal.

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
  and masking a stale worker). The required Docker lane builds its
  digest-pinned test image locally from `ci/image/Dockerfile`
  (Go + git + Docker CLI + certs + make/gcc) instead of pulling one
  from a registry; see
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

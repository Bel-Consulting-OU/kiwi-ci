# Production deployment

This document covers running the Kiwi CI control plane in production:
PostgreSQL, HA leader election, TLS, the config file, and runner
enrollment. Dev mode (in-memory state, single instance) is fine for
local testing and is not covered here beyond the basics.

## Server modes

- `dev` — in-memory state; a `--data-dir` adds filesystem persistence
  (state snapshot plus lease/OIDC keys).
- `production` — enforced startup contract:

  - `--database-url` (PostgreSQL) is required;
  - distinct `--admin-token` and `--runner-token` are required unless
    `--allow-shared-token` acknowledges a shared credential;
    `--allow-shared-token` only acknowledges reusing one value for both
    tokens — it does not re-enable the shared token on the runner tier;
  - runner traffic must have an actual per-runner mechanism: enforced
    runner mTLS (`--runner-ca-cert`/`--runner-ca-key` with
    `--runner-require-client-certs`) or provisioned per-runner bearer
    credentials (`--runner-tokens-file`, or rows already present in
    `runner_bearer_tokens`). The runner PKI is initialized BEFORE this
    check (an explicit CA is installed into the shared cluster key store,
    an enrollment token materializes the shared CA), and the decision uses
    the ACTUAL initialized state, because the credentials may already be
    provisioned in the database and the CA only exists once the cluster
    key store is reachable. The shared `--runner-token` is dev/bootstrap
    compatibility only: the server clears it at startup and production
    refuses runner traffic authenticated with it;
  - `--external-url` starting with `https://` is required (the OIDC
    issuer always serves in production);
  - `--tls-cert`/`--tls-key` are required.

```bash
kiwi server \
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

`/etc/kiwi/runner-tokens.json` maps runner IDs to SHA-256 token digests
(`{"<runner-id>": "<sha256-hex>"}`); the server provisions them into
`runner_bearer_tokens` at startup. The mTLS alternative replaces
`--runner-tokens-file` with `--runner-ca-cert`/`--runner-ca-key` (plus
enrollment) and keeps `--runner-require-client-certs` at its default.

## PostgreSQL

The durable SQL store (`internal/storage/postgres.go`, migrations in
`internal/storage/migrations/`) holds runs, jobs, leases, completion
receipts, runners, artifacts, test reports, logs, audit events, and
webhook deliveries. The server auto-migrates at startup when a database
URL is set; `kiwi database migrate` and `kiwi database status` do the
same explicitly.

Hot-path columns (status, lease, counters, timestamps) are relational
columns; the full model struct is a jsonb payload. Job completion is a
single transaction: lock the job, verify generation and runner, insert
the completion receipt idempotently, update counters, recompute
dependents and the run, and append the audit event.

## HA leader election

Exactly one instance may lease jobs, recover expired leases, or run
background maintenance. Leadership is a session-level PostgreSQL
advisory lock (`kiwi-scheduler`) held on a dedicated connection with a
soft renewal TTL (default 15 seconds). A standby instance serves reads
and polls for promotion (`Server.Maintain`). See [ha.md](ha.md) for the
full leader-duty list.

Run at least two instances behind a load balancer. Each instance needs
the same database URL, tokens, and external URL. Signing material must
be SHARED, not node-local: in DB mode the server uses the database-backed
cluster key store (`cluster_keys`, created on first start), so replicas
share the lease HMAC key, OIDC ring, provenance key, cache signing key,
web session secret and runner CA through PostgreSQL. An explicit
`--cluster-key-dir` on shared storage is the alternative; a store rooted
at the per-node `--data-dir` is refused in production/DB mode, because
two replicas with separate data dirs would each pass a naive readiness
check while holding different keys. When a data dir exists, its existing
key files are migrated into the shared store on first use, so upgrading a
single-node deployment keeps its OIDC/provenance/runner-CA trust roots.

The runner CA obeys the same one-trust-root rule: `--runner-ca-cert`/
`--runner-ca-key` is atomically installed-or-compared against the shared
cluster key store (create-if-absent; the stored material wins). An explicit
CA whose bytes disagree with the already-installed cluster CA fails startup
with a "configured runner CA disagrees with cluster runner CA" error instead
of silently trusting a node-local CA the other replicas reject. A CA
generated from an enrollment token is created through the same
install-or-load primitive, so replicas that race to enroll converge on ONE
CA rather than minting one each.

OIDC key rotation is fenced across replicas: a due rotation takes a
PostgreSQL advisory lock, reloads the shared ring, re-checks that rotation
is still due, rotates once and persists, then releases. A replica that
cannot take the fence within its bound keeps serving the current
published key instead of activating a key no peer can verify. The JWKS
endpoint reloads the shared ring before serving, so a non-issuing replica
always advertises a peer's freshly rotated key.

## TLS

Set `--tls-cert`/`--tls-key` (or `server.tls_cert`/`server.tls_key` in
the config file) to serve HTTPS. `--external-url` must match the public
base URL: it is advertised as the OIDC issuer and used for forge
statuses. In production, external URL must be `https://`. The listener
serves TLS only: clients, probes, load balancers, and backend services
must use `https://` (or terminate TLS in front of the instance), because
a plaintext request to a TLS listener fails.

## Configuration file

`kiwi server --config kiwi.toml` loads the TOML file described by
`kiwi.example.toml`. Precedence: CLI flags > `KIWI_*` environment
variables > config file > defaults. `kiwi config check --config
kiwi.toml` validates a file. Sections: `server`, `database`,
`runner_pki`, `blob`, `staging`, `github`, `gitlab`, `forgejo`,
`policy`, `observability`, `rate_limit`, `auth`, `quota`,
`secret_broker`, `components`.

The `staging` section bounds the scratch space for large runner uploads
(job cache entries and workspace snapshots) before they reach the shared
CAS. **Production mode refuses to start** without a bound: `staging.dir`
(a shared ROOT) and `staging.max_bytes` (a positive per-replica byte
budget) are all-or-nothing and both required. `dir` is a root, not the
directory bytes land in — each replica stages inside
`<dir>/<instance_id>`, so replicas sharing a root MUST set distinct
`staging.instance_id` values (optional: when unset the first process
generates one and persists it, and a second replica without its own id is
refused at startup). Dev mode falls back to a bounded default under the
server data dir when the section is unset.

The `quota` section also carries the untrusted resource ceilings
(`untrusted_cpu_ceiling`, `untrusted_memory_ceiling`,
`untrusted_disk_ceiling`, `untrusted_pids_ceiling`; memory/disk in bytes),
which admission enforces before a run is signed or persisted. The defaults
(2 CPU, 4 GiB, 10 GiB, 256 PIDs) are deliberately conservative production
values: raise them per deployment only when untrusted jobs legitimately
need more, because each raise widens the resources a fork pipeline can
consume on a runner host — see
[pipeline-reference.md](pipeline-reference.md#untrusted-ceilings). Raising
them at runtime via the flags/environment variables does not require a
config-file change.

## Blob storage

Artifact bytes live in the `blob` backend: `fs` (local data directory,
default) or `s3` (endpoint, bucket, region, access key, secret key).
S3 requires all three coordinates. The content-addressed CAS layer
verifies digests on write and read regardless of backend. The endpoint
is parsed and the endpoint/bucket combination validated at startup:
virtual-hosted addressing (the default) needs a DNS endpoint host with
no path prefix, while IP endpoints, gateway path prefixes and non-DNS
bucket names require `s3_path_style = true`. Production refuses an
`http://` endpoint (SigV4 credentials must not travel in plaintext)
unless `s3_allow_plaintext = true` explicitly acknowledges a trusted
network.

## Runners and enrollment

Register a runner with a bearer token:

```bash
kiwi runner --server https://ci.example.com \
  --token "$RUNNER_TOKEN" --labels linux,x64
```

The runner bearer token is a SHARED credential: every runner presents the
same token, so it authenticates "some registered runner" but is not a
per-runner identity and cannot distinguish runners. It is dev/bootstrap
compatibility only. Production disables it and refuses to start unless at
least one actual per-runner mechanism exists:

- **per-runner bearer credentials** — `--runner-tokens-file` maps each
  runner ID to the SHA-256 digest of its own token (provisioned into
  `runner_bearer_tokens`), or the rows are provisioned out of band; the
  server rejects the shared token as soon as per-runner credentials exist;
- **enforced runner mTLS** — `--runner-ca-cert`/`--runner-ca-key` plus
  runner certificates (see below), with `--runner-require-client-certs`
  at its default. The CA is installed into the shared cluster key store
  and must agree with the CA every other replica already trusts.

If the per-runner credential store is unavailable at request time, the
runner tier answers 503 and never falls back to the shared token.

For mTLS identity binding, create a runner CA once:

```bash
openssl req -x509 -newkey ed25519 -keyout runner-ca.key -out runner-ca.crt \
  -subj "/CN=kiwi-runner-ca" -days 3650 -noenc
```

Then start the server with `--runner-ca-cert`/`--runner-ca-key` (or
`--runner-enroll-token` to persist a generated CA in the shared cluster key
store: PostgreSQL in DB mode, which needs NO node-local `--data-dir`; the
FS cluster key store under `--data-dir`/`--cluster-key-dir` in file mode),
and enroll runners:

```bash
kiwi runner --server https://ci.example.com \
  --runner-enroll-token "$ENROLL_TOKEN" --runner-mtls
```

The runner generates its key locally, the server signs a certificate
with a server-synthesized `spiffe://kiwi/runner/<id>` identity (CSR
identity fields are discarded), and all subsequent traffic is mutually
authenticated. Keep the enrollment token short-lived; it is the
bootstrap credential for runner identities. Enrollment also supports
single-use grants (`CreateEnrollGrant`) with expiry and optional label
binding for automated runner provisioning.

When a runner CA is configured, the shared HTTPS listener verifies
client certificates when presented (`VerifyClientCertIfGiven`), and
runner-tier routes demand a valid runner certificate
(`--runner-require-client-certs`, default on); admin, forge and
enrollment traffic stays reachable on the same listener.

## Health and metrics

- `GET /readiness` — ready to serve traffic. DB mode checks the store. In
  fs mode (data-dir snapshot store) a failed snapshot write degrades the
  control plane: `/readiness` answers 503 with `X-Kiwi-State: degraded` and a
  fixed body (the raw error stays in the server logs), new runner leases are
  refused with 503 so no capability is issued for state the snapshot does not
  contain, and heartbeats answer 503 without extending the stored lease
  expiry, so a runner self-cancels at its last acknowledged deadline instead
  of running on an unrecorded extension. The state self-heals on the next
  successful persist and is cleared when the server switches to DB mode (the
  abandoned snapshot is no longer authoritative). Configure probes and load
  balancers to stop routing traffic to an instance while `/readiness` answers
  503, and alert on the degraded state so a persistent snapshot-write failure
  is not masked. Probe over HTTPS when the server runs with
  `--tls-cert`/`--tls-key`, e.g.
  `curl -fsS https://ci.example.com/readiness` (a plaintext probe against a
  TLS listener fails).
- `GET /liveness` — process is up.
- `GET /metrics` — Prometheus-style metrics, optionally on a separate
  `observability.metrics_listen` address.

## Web UI

The embedded dashboard listens on the server address (`GET /`). Admin
login uses the admin token (`POST /api/v1/login`) with HMAC-signed
session cookies and CSRF protection.

## Production capabilities

- Server-side schedules: cron-parsed, leader-gated firing with
  exactly-once nominal occurrence claims (`schedule_occurrences`).
- OIDC signing-key rotation: active + previous verification keys with
  retire-after windows — see [oidc.md](oidc.md).
- OpenTelemetry export: OTLP/HTTP traces for requests, forge intake,
  enqueue, lease, and completion spans.
- Deployment and snapshot records persist durably (PostgreSQL or
  data-dir state file); scheduling semantics are enforced either way.


## CI (Woodpecker) server requirements

Kiwi's CI runs entirely on Woodpecker (`.woodpecker/` multi-workflow layout).
The Woodpecker instance hosting it must be configured so CI reflects reality:

- `WOODPECKER_FORCE_IGNORE_SERVICE_FAILURE=false` — otherwise a dead
  PostgreSQL service is ignored and the `integration-coverage` workflow
  passes without exercising the real database.
- Commit-status contexts use Woodpecker's canonical
  `ci/woodpecker/<event>/<workflow>[/<axis>]` form, with the `pull_request`
  event mapped to the literal `pr`, so branch protection names look like
  `ci/woodpecker/pr/linux-amd64` (the flat pre-event form can never be
  satisfied). `scripts/gh-branch-protection.sh` (invoked by
  `make protect-branch`) installs exactly three contexts as required checks:
  `ci/woodpecker/pr/linux-amd64`, `ci/woodpecker/pr/linux-arm64` and
  `ci/woodpecker/pr/integration-coverage`. The native macOS/Windows
  workflows run on trusted events only, so their `push/` contexts are not
  required for pull requests.
- Agents labelled `platform=linux/amd64`, `platform=linux/arm64`,
  `capability=docker`, `platform=windows/amd64` and `platform=darwin/arm64`
  matching the workflow label sets.
- `docker-workspace-diagnostic` is a trusted, push/manual/tag-only job: it
  mounts the agent host's Docker daemon socket in its steps. Woodpecker gates
  host volumes on the repository-level Trusted flag alone -- there is no
  per-event or fork gating -- so a `pull_request` run would execute
  PR-authored code with host-daemon control (host-root equivalent). It is
  deliberately non-blocking (`failure: ignore` on every step) and is not a
  required PR or push context; re-gating pull requests needs a socket-less
  variant of the lane. It also cannot run its invariant on the current
  Woodpecker topology at all: the docker backend exposes the pipeline
  workspace as a named volume, so the test's own-workspace bind mounts
  resolve on the daemon host where that path does not exist. The job reports
  a missing daemon or that topology mismatch and skips; a compatible backend
  (or a rewritten, bind-mount-free invariant) must be promoted to a required
  push context in `scripts/gh-branch-protection.sh` when it exists. The
  script lists the `push/*` variants of the runnable lanes only so an
  operator can require them instead for direct pushes (`KIWI_PUSH_CONTEXTS`),
  and does not install them as required checks.
- The clone plugin and every workflow image are pinned by OCI digest.

### Required-check governance

Woodpecker publishes one commit status per workflow and event, not one per
step, so branch protection on `main` requires the three pull-request workflow
contexts (`ci/woodpecker/pr/<workflow>`), not individual lanes. This is the
intended required-check set and where each lane is enforced:

| Intended check | Enforced by | Gate |
| --- | --- | --- |
| unit-linux-amd64 | `unit` step, `linux-amd64` | PR-gating via `ci/woodpecker/pr/linux-amd64` |
| unit-linux-arm64 | `unit` step, `linux-arm64` | PR-gating via `ci/woodpecker/pr/linux-arm64` |
| race | `race`/`race-double` (linux-amd64), `race` (linux-arm64) | PR-gating via both contexts |
| postgres-integration | `integration-postgres` step, `integration-coverage` | PR-gating via `ci/woodpecker/pr/integration-coverage` |
| adversarial | `adversarial` step, `linux-amd64` | PR-gating via `ci/woodpecker/pr/linux-amd64` |
| coverage-floor | `coverage` step, `integration-coverage` | PR-gating via `ci/woodpecker/pr/integration-coverage` |
| staticcheck | `staticcheck` step, `linux-amd64` | PR-gating via `ci/woodpecker/pr/linux-amd64` |
| govulncheck | `govulncheck` step, `linux-amd64` | PR-gating via `ci/woodpecker/pr/linux-amd64` |
| non-root | `unit-nonroot` steps, `linux-amd64` and `integration-coverage` | PR-gating via both contexts |
| release-reproducibility | `repro` step, `linux-amd64` | PR-gating via `ci/woodpecker/pr/linux-amd64`; re-run by release promotion on the tag |
| windows | `native-windows` workflow | Post-merge/release only: push/manual/tag, never a required PR check |
| macos | `native-macos` workflow | Post-merge/release only: push/manual/tag, never a required PR check |
| docker-integration | `docker-workspace-diagnostic` workflow | Non-blocking diagnostic only (push/manual/tag, `failure: ignore`): the current Woodpecker topology cannot run the invariant, so it reports and skips instead of gating every HEAD red |

Only the three `pr/*` contexts are installed as required checks. The native
and Docker-socket jobs are deliberately unrequirable: a fork PR never
schedules them, so requiring them would leave every fork PR waiting forever,
and the docker workspace lane additionally cannot satisfy its environment
invariant on the current topology. When no compatible Windows agent is
attached, the `native-windows` push context may remain pending indefinitely:
that is a platform-availability signal, not a required gate, and it must not
be added to `CONTEXTS`/`PUSH_CONTEXTS` unless a Windows agent is guaranteed
to pick it up. The context list in `scripts/gh-branch-protection.sh` is validated
against each workflow's `when` events by `go test ./internal/workflowguard/`.

Apply or refresh protection with repository-admin credentials:

```bash
make protect-branch          # = ./scripts/gh-branch-protection.sh
```

It targets `Bel-Consulting-OU/kiwi-ci@main` by default; override with
`KIWI_REPO` and `KIWI_BRANCH`. The script refuses to install any context it
has not observed on a recent commit, so a Woodpecker status-format drift
cannot silently weaken (or brick) protection. Do not run it against the live
repository without the operator's intent: it rewrites the branch-protection
rule.

## Native and local CI agents

The native macOS and Windows workflows run on Woodpecker's local backend,
which executes the workflow commands directly on the worker host as the
agent user, with no container boundary. These hosts are part of the
trusted build boundary; provision them on that basis:

- **One-shot, ephemeral workers.** Destroy or reimage the host after every
  run. Never point the native labels at a long-lived interactive machine.
- **Dedicated low-privilege user.** Run the Woodpecker agent as a
  dedicated user (never root/administrator) whose only durable state is
  the Go toolchain and the per-run checkout.
- **No persistent credentials.** Keep release signing keys, forge tokens,
  and cloud/SSH keys off the host. The only secret that may exist is the
  Woodpecker agent secret, scoped to that agent and rotated.
- **Never run fork code.** The native workflows accept trusted events only
  (`push`, `manual`, `tag`). Fork pull requests run in the Docker-backend
  lanes; the socket-mounting `docker-workspace-diagnostic` job is push-only
  (see above), so only the container-isolated Docker lanes run on PRs. Do not add
  `pull_request`/`pull_request_*` events to a local-backend workflow or a
  host-volume workflow; `internal/workflowguard` fails the build if either
  reappears.
- **Agent selection and shell.** Select `platform=darwin/arm64` +
  `backend=local` for macOS and `platform=windows/amd64` + `backend=local`
  for Windows. On the local backend `image` names the shell (`bash`,
  `pwsh`) rather than a container image, so the shell must exist on the
  worker's `PATH`, as must Go 1.27.x (`GOTOOLCHAIN=local` prevents Go from
  downloading a toolchain and masking a stale worker).

## CI test image

The `docker-workspace-diagnostic` job needs a Docker CLI and must not
depend on a registry image. Its first step builds
`ci/image/Dockerfile` locally on the agent's daemon as
`kiwi-ci-test:go1.27`; the diagnostic step uses `pull: false`, so it runs
those local layers. The image is based on the same digest-pinned Go 1.27 and
Docker CLI images as the other workflows and adds git, CA certificates,
make, gcc, and libc6-dev, each probed at build time. Bump the base
digests deliberately (re-resolve with `docker buildx imagetools inspect`)
and re-run the job to validate the result. The `ci/image/Dockerfile` header
and CI image pin comments still use the historical lane name
(`docker-workspace`); the file itself is unchanged by the diagnostic rename.

## Time authority and clock skew (lease records)

In **DB mode the database clock is the authority for a lease's lifetime**:

- **Initial claim** stores `clock_timestamp() + TTL` inside the claim
  transaction (`LeaseClaim.TTL`), so a replica's application clock cannot
  shorten or lengthen the real lease; the returned expiry is the stored one.
- **Heartbeat renewal** writes `clock_timestamp() + TTL` and only matches
  while the stored lease has not already expired at that clock, so a delayed
  heartbeat can never resurrect a recoverable lease.
- **Recovery discovery and application** compare against
  `clock_timestamp()` sampled after the row lock, so a recovery replica whose
  application clock is hours ahead cannot prematurely reclaim a live lease,
  and one that is hours behind can still recover an expired lease.
- **Completion** re-checks the locked lease against a post-lock
  `clock_timestamp()` before applying any lifecycle transition: an expired
  runner cannot complete a job ahead of recovery, and one database timestamp
  stamps the completion's finished_at, runner counters and effect intents.
- **The HTTP runner gate** (`authorizeRunnerLease` and the artifact-commit
  re-check) asks the store for liveness in the database clock domain
  (`LeaseLive` → `clock_timestamp()`), so a skewed serving replica can
  neither reject a database-live lease nor admit a database-expired one.
  Only the single-process dev/memory store falls back to the application
  clock, where skew is not a concept; a DB store that does not implement
  `LiveLeaseStore` is refused with 503 rather than silently downgrading to
  replica-clock liveness.
- **Test-report ingestion is lease-fenced; only log ingestion is deliberate
  late-log grace.** Test reports commit through `LeaseTestReportStore`, which
  locks the job row, re-validates runner/generation and
  `lease_expires_at > clock_timestamp()` after the lock, and stamps the
  canonical `(created_at,id)` ordering instant from that same database clock —
  because test history drives future shard assignment, duration balancing,
  the test manifest and flaky classification. A report whose lease expired
  while the request (or a row-lock wait) was in flight is refused with 409
  and commits nothing. The 201/200 body is the canonical stored report,
  including that database-clock instant, so a create response can never
  disagree with an immediate read. A dropped-response replay is idempotent
  only while the lease is still live; after the lease has ended the retry is
  refused with 409 (the first commit stays durable). Log lines/batches pass
  the same database-clock gate at request start but are deliberately NOT
  transactionally lease-fenced: log lines carry no lifecycle, authority or
  accounting meaning, and batch receipts are generation-scoped, so a late
  batch can never collide with a re-leased generation. Every
  behavior-affecting runner mutation (completion, heartbeat, test reports,
  cache/artifact/snapshot publication, generated jobs, OIDC, secrets) is
  commit-time fenced.
- **Durable cache retention is database-clock authoritative.** The
  `cache_manifests.created_at` used for age pruning and entry/byte ranking is
  stamped with `clock_timestamp()` by both writers, and the prune cutoff is
  computed in SQL, so a skewed publishing or pruning replica cannot evict a
  fresh entry, pin an old one, or reorder quota eviction. The signed payload
  keeps the producer instant as provenance only.
- **Deployment creation is idempotent across replicas and restarts.**
  `StartDeployment` inserts with `ON CONFLICT (id) DO NOTHING`, returns the
  canonical stored record on replay (a conflicting run/job/environment fails
  closed), and commits `deployment.started` in the SAME transaction — an
  audit failure rolls the record back. `FinishDeploymentOnce` likewise
  commits the finish marker and `deployment.completed` together, exactly
  once. The server caches only the stored record. The explicit record endpoint
  requires an actually running job and derives `StartedAt` from the job, and
  `SwitchToDB` refuses a store without the deployment contract at startup.
- **Enrollment grants, outbox claims, OIDC lifetimes and DB schedules share
  the database clock.** Grant creation takes a TTL and stores
  `clock_timestamp() + TTL`, the DB gate asks the store for liveness, and
  consumption locks the row before sampling the clock; outbox claim due/cutoff
  predicates and the `claimed_at` stamp are all `clock_timestamp()`
  (TTL in SQL); the OIDC commit derives the JWT `iat`/`exp` and the audit
  instant from its commit clock; and DB-mode schedule due evaluation reads
  `ClockStore.Now`, skipping the tick rather than using the leader's wall
  clock. A skewed replica can neither extend a credential or claim, steal a
  live claim, nor fire or postpone a due schedule.
- **Pipeline-controlled child output is captured under a hard bound.** Service
  healthchecks retain a 64 KiB diagnostic prefix and drain (discarding) the
  rest, and every executor/git/prewarm capture is bounded, so a hostile
  healthcheck cannot grow the runner heap or block on a full pipe.
- **Runner crash recovery is closed and fail-closed.** Reconciliation errors
  (discovery or removal) block leasing; Tart clones carry runner/instance
  ownership tags and are reaped like Docker resources; each `Run()` gets a
  fresh incarnation ID; a durable runtime ledger reclaims crashed workspaces
  and artifact scratch; one stable runner identity is protected by a lifetime
  lock so a duplicate process cannot reap the live process's workloads; XFS
  allocation is serialized across processes with a host-global lock and
  re-reads the filesystem on every allocation, with crashed assignments AND
  job cgroups reclaimed from the durable ledger on the next run; runner identity
  persistence is atomic and pair-verified (Windows: protected owner-only
  DACL); and each registration issues a session incarnation that supersedes
  older polling, heartbeat and completion sessions (409). Scheduler aging is uncapped and capacity
  metrics count effective schedulable slots.
- **Runner crashes are reconciled immediately.** Every runner process has an
  instance ID; containers/services/networks are labelled with
  `kiwi.runner`/`kiwi.instance`, and a restarted runner reaps its own
  predecessor's runtimes BEFORE leasing. XFS project IDs already present on
  the filesystem are discovered and reserved before allocation, so a restart
  cannot reuse a live assignment. Production also requires a shared
  `KIWI_WEB_SESSION_SECRET`, set `sandbox.non_root` is enforced (or the
  runtime is refused), corrupt current-format parent policy metadata fails
  generated children closed, and lease scheduling ages waiting jobs so
  low-priority work cannot be starved.
- **Runtime teardown is proven-gone before workspace protections are
  removed.** `CloseJob` keeps the container/clone identity until removal
  succeeds or the runtime is positively absent, never restores workspace
  ownership or drops the XFS project quota while the runtime object may still
  exist, and keeps quota/ownership cleanup callbacks retryable until they
  succeed. Failed webhook deliveries from an ignored terminal outcome (no
  trigger match) persist an ignored receipt, so replays perform no forge
  work. A corrupt current-format generation envelope fails child admission
  closed.
- **Retry budgets are capped and zero is explicit.** Step retries cap at 20,
  service healthcheck retries at 100 and infrastructure retries at 20,
  enforced at admission and clamped in the executor/recovery; explicit
  `0` values mean zero retries / one healthcheck attempt / never requeue
  rather than inheriting the defaults.
- **Webhook replays are suppressed before any forge work and bound to the
  signed body.** The delivery + authenticated-body-digest fast path runs
  before pipeline/diff fetches, the body receipt suppresses the same signed
  payload under a fresh delivery header, a reused delivery ID with different
  content is a 409, and the delivery header is required.
- **Heartbeats touch only `last_seen`.** The runner liveness refresh is a
  narrow `RunnerHeartbeatStore.TouchRunnerLastSeen`
  (`UPDATE runners SET last_seen=clock_timestamp()`), never a whole-row
  read-modify-write: a heartbeat that read the runner before a concurrent
  admin disable/drain/profile edit can no longer write the stale snapshot
  back and undo the admin action. Profile/admin writes likewise never own
  `last_seen` (the guarded merge preserves the committed instant, and
  registration touches it explicitly afterwards), so a re-registration,
  drain or enable from a stale snapshot cannot move it backward.

The in-memory/dev store is single-process and keeps a monotonic application
clock, where skew is not a concept. Queue deadlines are one-shot instants
recorded at admission; their expiration is compared against the database
clock at sweep time, so skew can at most shift a deadline by the admission
replica's offset (the same magnitude as any NTP deviation), not accumulate
over a lease's lifetime.

Consequently, DB-mode HA no longer depends on cross-replica wall-clock
synchronization for lease safety; keeping hosts NTP-synchronized remains good
operational hygiene, but a skewed replica can no longer extend, prematurely
reject, or prematurely recover a lease.


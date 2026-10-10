# Core Invariants

This document is the authoritative mapping of Kiwi's core correctness
invariants to the code that enforces them and the tests that prove them. It is
the contract an audit, a reviewer, or a future contributor checks against.

**How to use this document.** Every change that touches a core subsystem MUST
update the affected invariant's mapping (enforcement points and/or regression
tests) in the same change. If the mapping is not updated, the invariant is
ASSUMED BROKEN, not assumed intact: reviewers treat a stale row as a defect and
the surface is treated as unproven until the mapping is repaired. Statuses must
describe the tree as it is, never aspirations; a gap is listed explicitly and
may only be marked closed once the enforcing code and its regression test both
exist.

Line numbers are a convenience for the tree at the time of writing and drift
quickly; the named symbol is the stable reference. PostgreSQL is the canonical
store (the only one with transactional ledgers); filesystem/memory stores mirror
its behavior but are explicitly non-canonical unless stated otherwise.

## Status legend

| Status | Meaning |
|---|---|
| enforced+tested | Enforcing code exists and at least one regression test fails when it is removed. |
| enforced+test-pending | Enforcing code exists; the regression test for the exact claim is landing in a named wave. |
| gap | Known hole; no enforcing code (yet). Listed with the residual risk. |
| pre-committed, surface absent | The invariant is committed as a requirement for a feature that does not exist yet in this tree. |

## Status summary

| ID | Invariant | Status |
|---|---|---|
| I1 | One terminal outcome per job/run | enforced+tested |
| I2 | State transition + ledger emission atomically | enforced+tested (canonical PG); fs best-effort by design |
| I3 | Stale lease never mutates authoritative state | enforced+tested |
| I4 | Scoped consumers recover exactly their authorized view | enforced+tested |
| I5 | Exact replay cannot add external effects or work unless authorized | enforced+tested |
| I6 | Graph mutation cannot invalidate committed history | enforced+tested |
| I7 | Speculative execution has a single winner | pre-committed, surface absent |
| I8 | Cancellation/terminal monotonicity (idempotent cancel/approve) | enforced+tested |
| I9 | Credentials never exceed the execution that requested them | enforced+tested |
| I10 | Untrusted execution cannot populate a trusted cache namespace | enforced+tested |

---

## I1 — One terminal outcome

**Statement.** A job and a run reach at most one terminal outcome. A repeated
completion of the same `(job, lease generation)` is acknowledged from its
durable receipt when the content matches and is refused (`409`) when it
conflicts; a commit that lost a race can never overwrite the recorded outcome.
A run's aggregate status is derived only from its jobs, becomes terminal only
when every job is terminal, and a cancelled run is frozen.

**Enforcement points.**
- `model.Status.Terminal()` — the closed terminal set (success, failure,
  cancelled, skipped, blocked): `internal/model/model.go:22`.
- `(*PostgresStore).CompleteJob` — per-`(job, generation)` receipt replay:
  same digest is an idempotent ack, different digest is `ErrCompletionConflict`:
  `internal/storage/postgres.go:2393` (conflict gate ~:2446-2584).
- `(*Server).completionReplayReadyLocked` / completion receipt matching
  (fs/memory mirror of the same rule): `internal/server/completion_digest.go`.
- `recomputeRunStatus` — terminal only when `terminal == total`; a
  `cancelled` run returns unchanged: `internal/storage/postgres.go:2904`
  (freeze at :2911). In-memory mirror `refreshRunLocked`:
  `internal/server/server.go` (`refreshRunLocked`), same early return for
  `StatusCancelled`.
- Terminal runs stay terminal for cancel requests (I8).

**Regression tests.**
- `TestCompletionReplayV2RuntimeEvidence`,
  `TestCompletionLegacyV1ReceiptComponentReplayDBFake`,
  `TestCompletionLegacyV1ReceiptComponentReplayFS`,
  `TestCompletionReceiptsSurviveRestartReplay`,
  `TestCompletionEffectsReceiptReplayExactlyOnce`
  (`internal/server/completion_*_test.go`).
- `TestCompletionReceiptReplayMatchesVersionMatrix`
  (`internal/storage/completion_digest_test.go`).
- `TestPostgresIntegrationCompleteJobReceiptHashConflict`,
  `TestPostgresIntegrationCompleteJobInsertConflictHash`
  (`internal/storage/postgres_completion_conflict_it_test.go`).
- `TestPostgresIntegrationServerCompletionRaceDifferingResults`
  (`internal/server/crash_race_pg_test.go`).

**Status.** enforced+tested.

---

## I2 — State transition and ledger emission commit atomically

**Statement.** In the canonical (PostgreSQL) store, every state mutation that
has a semantic ledger event commits the mutation and the event in ONE
transaction: a failed or blocked ledger append rolls the mutation back (fail
closed), so a committed transition can never be missing its event and an event
can never describe a transition that did not commit. The filesystem/memory
stores append the event next to the mutation but are explicitly
`canonical: false`; their journal append is best-effort and the API reports it
as such.

**Enforcement point (the funnel).** `appendExecutionEventTx`
(`internal/storage/execution_events.go`) appends inside the caller's
transaction, under the event-cursor row lock, so the commit order equals the
cursor order.

**Same-transaction append sites.**

| Mutation | Event | Site |
|---|---|---|
| Atomic lease claim | `attempt.created` | `(*PostgresStore).AcquireLeaseAtomic` — `internal/storage/postgres.go:2118` |
| Environment approval | `approval.granted` | `(*PostgresStore).ApproveJob` — `internal/storage/postgres.go:1740` |
| Artifact publication | `artifact.published` | `(*PostgresStore).InsertArtifactOnceForLease` — `internal/storage/lease_commit.go:453` |
| Workspace checkpoint | `checkpoint.published` | `(*PostgresStore).InsertSnapshotForLease` — `internal/storage/lease_commit.go:402` |
| Deployment start/finish | `deployment.started` / `deployment.completed` | `StartDeployment` / `FinishDeploymentOnce` — `internal/storage/postgres.go:4725`, `:4779` |
| Dynamic fragment commit/replay | `graph.mutation_committed` / `graph.mutation_replayed` | `InsertGeneratedFragmentTx` — `internal/storage/postgres.go:5133`, `:5252` |
| Secret delivery | `secret.issued` | `(*PostgresStore).CommitSecretIssuance` — `internal/storage/postgres_secret_issue.go:387` |
| OIDC issuance | `oidc.issued` | `(*PostgresStore).CommitOIDCIssuance` — `internal/storage/postgres_oidc_issue.go:518` |
| Execution attestation | `execution.attested` | `(*PostgresStore).CommitExecutionAttestation` — `internal/storage/attestations.go:60` |

**Regression tests (rollback).**
- `TestPostgresIntegrationSemanticEventAppendFailureRollsBack`
  (`internal/storage/execution_events_semantic_pg_it_test.go:247`): with the
  event append blocked by a trigger, the artifact row is absent and the
  approval stays `waiting_approval` with no `approval.granted`; both succeed
  after the block is lifted.
- `TestPostgresIntegrationExecutionAttestationCommitOnce`
  (`internal/storage/attestations_pg_it_test.go:18`).
- `TestIntegrationLeaseCommitPredicatesLive` /
  `TestIntegrationLeaseCommitPredicatesRevoked`
  (`internal/storage/lease_commit_it_test.go`).
- memStore parity (`approval`, artifact/checkpoint, graph mutation,
  deployments): `internal/storage/execution_events_semantic_test.go`.
- fs best-effort semantics (failed journal append fails closed while blocked,
  reports `canonical:false`): `TestEventsAppendFailureSemantics`,
  `TestEventsFSBestEffortCanonicalFalse` (`internal/server/events_test.go`,
  `internal/server/events_retention_test.go`).

**Status.** enforced+tested for canonical PostgreSQL. The fs/memory path is
best-effort by documented design, not a gap against this invariant.

---

## I3 — A stale lease never mutates authoritative state

**Statement.** A durable mutation performed under a lease must re-validate the
lease against the store's own clock and locked row at commit time. A lease
whose holder, generation or token changed — or that expired while the request
waited — commits nothing and is refused as a stale lease (HTTP `409`), even
when the request passed the authentication gate earlier.

**Fencing matrix.**

| Mutation class | Commit-time fence | Enforcement | Tests |
|---|---|---|---|
| Artifact / snapshot / checkpoint commits | Job row locked; status, holder, generation, token hash and DB-clock expiry re-validated | `storage.ErrLeaseLost`; `internal/storage/lease_commit.go` (`InsertArtifactOnceForLease`, `InsertSnapshotForLease`); server `leaseLostAtCommit`/`leaseCommitRefused` maps 409 (`internal/server/lease_commit.go`) | `TestIntegrationLeaseCommitPredicatesLive/Revoked`, `TestIntegrationLeaseCommitConcurrentCancel`, `TestIntegrationLeaseCommitRejectsLeaseThatExpiresWhileWaitingForLock`, `TestLeaseLostAtCommitMaps409Not500` |
| Test report + history fold (DB) | Same lease predicate inside the single delivery/history transaction | `(*PostgresStore).InsertTestReportWithHistoryDeliveryForLease` — `internal/storage/postgres_test_reports.go`; server maps `ErrLeaseLost` at `internal/server/testintel.go` | `TestIntegrationLeaseCommitPredicatesRevoked`, `TestFlowSnapshotMemoryCommitLeaseLost` |
| Test report + history fold (memory/fs) | Live-lease re-validation under `s.mu` (the in-memory store's transaction) immediately before the report and its history fold are written; a mismatch persists nothing and answers 409, including replays of an already-persisted delivery | `(*Server).uploadTestReport` memory/fs branch (`validActiveLease` before `s.reports[...] =` and `persistCheckedErrLocked`) — `internal/server/testintel.go:214` | `TestTestReportMemoryCommitFenceRejectsExpiredAtCommit` |
| DB log append (batch + single line) | Job row locked and the live-lease predicate re-evaluated inside the same schema-fenced transaction as the receipt/lines (batch) or the commit-ordered seq allocation + insert (single); the predicate runs BEFORE the batch receipt dedupe, so a superseded generation is `ErrLeaseLost` even for an identical replay. The memory/fs branch re-checks the lease and performs the append under the SAME `s.mu` critical section | `(*PostgresStore).AppendLogBatch` — `internal/storage/logbatch.go:163`; `(*PostgresStore).AppendLogForLease` (`storage.LeaseLogStore`) — `internal/storage/postgres.go:3870`; identity binding `bindLogLeaseIdentity` (`internal/storage/logbatch.go:124`); server `log`/`logBatch` map `leaseCommitRefused` to 409 and fail closed (503) without the capability — `internal/server/server.go:4622`, `:4644`, `:4775`, `:4796`, `internal/server/lease_commit.go:82` | `TestPostgresIntegrationAppendLogBatchLeaseFence`, `TestPostgresIntegrationAppendLogForLeaseFence`, `TestMemAppendLogBatchLeaseFence`, `TestMemAppendLogForLeaseFenceAndIdentity`, `TestLogBatchPerLineFallbackRefused` (no unfenced fallback) |
| Secret issuance | Full issuance predicate (holder/generation/token/expiry/declaration) on the locked job | `(*PostgresStore).CommitSecretIssuance` — `internal/storage/postgres_secret_issue.go:294` | `TestSecretGenerationChangedBeforeCommitReturns409`, `TestSecretRevokedDuringBrokerResolveReturns409`, `TestSecretExpiredDuringBrokerResolveReturns409` |
| OIDC issuance | Same predicate, plus audience allowlist and locked-identity claims | `(*PostgresStore).CommitOIDCIssuance` — `internal/storage/postgres_oidc_issue.go:427` | `TestOIDCIssuanceGenerationChangedBeforeCommitReturns409`, `TestOIDCIssuanceRevokedBetweenAuthAndCommitReturns409`, `TestOIDCIssuanceLeaseExpiresDuringCommitStallReturns409`, `TestOIDCIssuanceIdentityChangedBetweenAuthAndCommitReturns409` |
| Completion | `(job, generation)` receipt comparison under the job lock | `(*PostgresStore).CompleteJob` — `internal/storage/postgres.go:2393` | `TestPostgresIntegrationCompleteJobReceiptHashConflict`, `TestPostgresIntegrationServerCompletionRaceDifferingResults` |
| Dynamic fragment | Parent row locked; `ValidateGeneratedParentLease` re-checks {running, runner, generation, token, storage-clock expiry} before the slot receipt; every refusal wraps `ErrLeaseLost`, so a lease superseded between the request gate and the transaction maps to 409 (never a 400 validation error) | `ValidateGeneratedParentLease` — `internal/storage/store.go:1008`; `InsertGeneratedFragmentTx` — `internal/storage/postgres.go`; server `leaseCommitRefused` mapping at `internal/server/dynamic.go:149` | `TestGeneratedFragmentStaleGenerationCannotReplay`, `TestGeneratedFragmentRacedLeaseLossMaps409Not400`, `TestGeneratedFragmentInsertionPredicateParity` |
| Runner incarnation | Registration session must still be current for OIDC/secrets/artifact/snapshot/cache | `runnerIncarnationCurrent` / `requireCurrentRunnerIncarnation` — `internal/server/server.go:3856`, `:3905` | `TestCompletionRefusedForSupersededIncarnation`, `TestModernHeaderlessRefusedAfterSupersession`, `TestIntegrationRegisterRevokesPredecessorIncarnation` |
| Leader-only mutations | Leadership epoch fence (`ErrStaleLeader`) on every leader-owned transaction | `beginFencedTx` (`internal/storage`) | `TestIntegrationLeaderFence...` (`internal/server/leader_fence_it_test.go`), scheduler epoch tests |

**Rolling-upgrade protocol floor (I3 / rolling upgrade).** A runner whose
negotiated WIRE-SEMANTIC protocol is below `model.JobRequiresProtocol` never
receives a new lease: `/next` answers HTTP `409 RUNNER_PROTOCOL_UNSUPPORTED`
before any claim or reservation mutation — enforced identically in the
memory path (`(*Server).next`) and the DB path (`(*Server).nextDB`) through
`writeRunnerProtocolUnsupported`/`effectiveRunnerProtocol` — while
heartbeat, logs and completion for already-claimed work stay governed by the
SAME generation-based commit fences in the matrix above. Registration
refuses a runner below the configured floor
(`server.min_runner_protocol`, default `model.RunnerProtocolVersion`) with
`400` and stores nothing; the negotiated version is persisted additively on
the runner payload (`model.Runner.ProtocolVersion`; absent = legacy v1), and
every leased task advertises the required `protocol_version`. Regression
tests: `TestNextRefusesLegacyRunnerButDrainsClaimedWork`,
`TestRegisterRefusesLegacyProtocolByDefault`,
`TestRegisterLegacyDuringUpgradeWindow`, `TestLeaseAdvertisesProtocolVersion`
(`internal/server/runner_protocol_test.go`),
`TestCheckServerProtocol`, `TestCheckTaskProtocol`,
`TestRegisterRefusesIncompatibleServerResponse`,
`TestNextRefusesTaskRequiringNewerProtocol`
(`internal/runner/runner_protocol_test.go`),
`TestMinRunnerProtocolDefault`, `TestMinRunnerProtocolValidation`,
`TestMinRunnerProtocolTOMLRoundTrip` (`internal/config/runner_protocol_test.go`),
`TestRunnerProtocolConstants`, `TestRunnerProtocolVersionAdditiveJSON`
(`internal/model/runner_protocol_test.go`). Procedure:
`docs/production-deployment.md#rolling-upgrades-and-the-runner-protocol-floor`.

**Closure of GAP-1/GAP-2 (this change).**

- **GAP-1 — closed. DB log append has a commit fence.**
  `(*PostgresStore).AppendLogBatch` (`internal/storage/logbatch.go`)
  now locks the job row and evaluates the live-lease predicate
  (`lockedLeaseJobTx`: status running, holder = runnerID, generation,
  unexpired lease at the post-lock database clock) in the SAME transaction
  as the batch receipt and the lines; it runs BEFORE the per-identity
  receipt dedupe, so a retry of a still-live batch stays an idempotent 204
  while a superseded/revoked/expired generation is `ErrLeaseLost` and
  commits nothing. The single-line path is
  `(*PostgresStore).AppendLogForLease` (`storage.LeaseLogStore`,
  `internal/storage/postgres.go`), which re-asserts the same predicate in
  the same transaction as the commit-ordered seq allocation + insert.
  Server `log`/`logBatch` map commit-time lease refusals to the standard
  409 (`leaseCommitRefused` / `writeLeaseAuthError`), and the per-line
  fallback now requires the transactional capability: a DB store without
  `LeaseLogStore` fails closed with 503 instead of an unfenced append.
  The former late-log grace contract is REMOVED: a superseded generation is
  unconditionally rejected, and only a live generation can replay a batch
  idempotently. In memory/fs mode the lease re-check and the store append now
  run in the same `s.mu` critical section in both handlers (batch and
  single-line), so a revocation cannot interleave between them there either.
- **GAP-2 — closed. Test-report memory/fs commit is lease-fenced.**
  `(*Server).uploadTestReport` (`internal/server/testintel.go`) now
  re-validates the identical `validActiveLease` predicate under `s.mu`
  (the memory store's transaction) immediately before the report row, the
  history fold and the durable persist path run; a lease that was
  superseded, revoked or expired between the request gate and the commit
  persists nothing and answers 409 — including a replay of a delivery that
  another live generation already persisted, mirroring the DB fence's
  predicate-before-replay precedence.
- **Chaos matrix.** `TestLeaseFenceChaosMatrixStaleGenerationRejected`
  (`internal/server/lease_fence_chaos_test.go`) claims a job at generation
  1, loses the lease through the store recovery path (token cleared, job
  requeued), has a second runner claim generation 2 and complete
  successfully, then replays every generation-1 request runner A can still
  make — heartbeat, single log, log batch, artifact, snapshot, cache
  manifest, secret, OIDC, test report, completion, generated fragment —
  and asserts each is rejected 409/403 (OIDC answers 401 from the cleared
  credential) with the entire authoritative state byte-identical, including
  B's completion receipt/link and the absence of any generation-1 row/event.

**Deliberate residual (documented, not a gap).** The transactional lease
predicates (`lockedLeaseJobTx`, `LeaseCommitStore`, `LeaseLogStore`,
`ValidateGeneratedParentLease`) deliberately do NOT re-verify the presented
token hash: the predicate is runner id + generation + status + database
clock, and token possession is proven once at request start
(`authorizeRunnerLease`). Re-hashing the token inside every metadata
transaction would add a second credential path with no additional authority
(revocation clears the token hash AND the holder/generation/status, so the
predicate already fails closed). The OIDC endpoint is the one exception
because its wire credential IS the raw lease token.

**Status.** enforced+tested. The former GAP-1 and GAP-2 are closed by the
commit fences and regression tests above; no open gaps remain for this
invariant.

---

## I4 — Scoped consumers can always recover exactly their authorized view

**Statement.** An execution-event consumer reads under a scope (global, one
repository, or one run). Authorization is enforced before any store read; the
cursor is bound to the scope it was issued for (a cursor cannot be replayed
against a different repository/run); retention prunes per scope so a scoped
consumer's unread frontier is never silently deleted, and once the scope's
frontier does advance past a cursor the read answers `410 cursor_expired`
with the frontier and latest cursor instead of silently truncating.

**Enforcement points** (the landed scope-correct retention change).
- Scope types and per-scope frontier: `storage.ExecutionEventScope`
  (`Kind`: global/repo/run), `ExecutionEventRetentionReadStore` and
  `ExecutionEventScopedRetentionStore` (`ScopedRetainedFrom`) in
  `internal/storage/execution_events.go`; migration
  `0056_execution_event_repo_scope.sql` stores the owning repository and
  scope columns.
- Typed cursor binding: the wire cursor is
  `xe1:<seq>:<scope fingerprint>`, where the fingerprint hashes the scope key
  (`global` / `repo:<repoID>` / `run:<repoID>/<runID>`);
  `buildExecutionEventCursor`, `executionEventScopeFingerprint` and
  `parseEventCursor(w, r, scope)` in `internal/server/events.go`. A cursor
  replayed under a different scope, or a legacy bare numeric cursor under a
  non-global scope, is refused with `409 cursor_scope_mismatch` before any
  store read; responses carry `scope_fingerprint` and `resume_status`.
- Scope filtering: `filterExecutionEventsInScope` drops any event whose
  owning repository/run is outside the authorized scope even if a store
  returned it.
- Authorization before store access: `requireExecutionEventsRead`
  (`internal/server/events.go`) — global reads require a global capability,
  repo/run reads require the matching repository grant.
- Expiry decision from the SCOPED frontier, never a defaulted 0:
  `storage.ExecutionEventCursorExpired`, `writeCursorExpired`
  (`internal/server/events.go`).

**Regression tests.**
- Scope isolation, scoped resume matrix, stream scope, cursor binding
  (`409 cursor_scope_mismatch`), retention racing scoped pagination, repo
  access loss, fs execution snapshot scope:
  `TestEventsRepoScopeIsolationAndScopedResumeMatrix`,
  `TestEventsStreamRepoScopeNeverEmitsOtherRepos`,
  `TestEventsCursorScopeBinding`, `TestEventsRetentionRacingScopedPagination`,
  `TestEventsRepoAccessLossForbidden`, `TestExecutionSnapshotFSRepoScope`
  (`internal/server/events_scope_test.go`).
- Scoped frontiers / retention: `TestMemStoreScopedRetention`,
  `TestRepositoryScopedRetentionPersistsFrontier`,
  `TestFaultyStoreForwardsScopedFrontier`
  (`internal/storage/execution_events_scope_test.go`),
  `TestPostgresIntegrationExecutionEventScopedRetentionFrontier`
  (`internal/storage/execution_events_scope_pg_it_test.go`).
- Cursor validity and watermark monotonicity:
  `TestEventsCursorExpiredList`, `TestEventsCursorExpiredStream`,
  `TestEventsMaintenancePrunesAndExpires`
  (`internal/server/events_retention_test.go`),
  `TestEventsRetentionReadFailureFailsClosed`,
  `TestEventsLatestCursorNeverRegressesUnderPrune`
  (`internal/server/events_atomic_test.go`).
- Base endpoint shape/authorization: `TestEventsEndpointAdminOnlyAndPagination`,
  `TestEventsFSLifecycleParity` (`internal/server/events_test.go`),
  `TestControllerCapabilityEventScope` (`internal/server/capability_routes_test.go`).

**Status.** enforced+tested.

---

## I5 — Exact replay cannot add external effects or work unless authorized

**Statement.** `kiwi replay` reconstructs a recorded job and re-executes it
locally. It can never add external effects or work to the world unless the
operator explicitly authorizes the gated surfaces: it cannot schedule child
jobs, submit runs, enqueue outbox work, or upload a generated fragment. The
only path that could turn a recorded `generate:` fragment into control-plane
work — `executor.Options.GenerateUpload` — is deliberately never wired by
replay; step-declared effects (deployment phases, secrets, OIDC) are refused
unless `--allow-external-effects` is passed, and the residual undeclared-effect
risk is always warned about. Exact replay also never silently reinterprets a
record produced under a different execution-engine semantics: see
"Reproducibility boundary" below.

**Enforcement points.**
- Replay never sets `GenerateUpload`; a replayed generator executes its step
  locally, reads the declared fragment for validation, and uploads nothing:
  `internal/app/replay.go` (invariant comment at the execution site),
  executor read/upload split at `internal/executor/executor.go:1049-1091`
  (upload only when the hook is non-nil; the runner wires it at
  `internal/runner/runner.go:1655`).
- Declared-effect gate: `replayDeclaredEffects` + `--allow-external-effects`:
  `internal/app/replay.go`.
- Reproducibility boundary: `replayExecutionSemanticsCheck` refuses to
  reinterpret a record stamped with a different non-empty execution semantics
  (see "Reproducibility boundary" below); empty pre-stamp records warn and
  proceed.
- Control-plane access is read-only: the replay client issues only GETs
  (recorded pipeline, snapshot pages, snapshot archive).

**Regression tests.**
- `TestReplayExactGeneratorNeverSchedulesChildren`
  (`internal/app/replay_generator_invariant_test.go`): exact replay of a
  recorded generator job succeeds (the step produced `fragment.json` locally),
  the recorded control-plane traffic is all GET and contains no `/generated`
  call.
- `TestReplayExactRefusesDeclaredExternalEffects`,
  `TestReplayExactAllowsDeclaredEffectsWithFlag`,
  `TestReplayExactWarnsAboutUndeclaredEffects`,
  `TestReplayExactExecutionSemanticsDecisionTable`
  (`internal/app/replay_exact_test.go`).
- `TestReplayExactIgnoresLocalPipelineFile`,
  `TestReplayExactRefusesMismatchedPayload`
  (`internal/app/replay_exact_test.go`).

**Status.** enforced+tested.

---

## Reproducibility boundary — execution semantics vs wire schema

**Statement.** Every run and job Kiwi creates carries an explicit
EXECUTION-ENGINE SEMANTIC version: `model.ExecutionSemanticsVersion`
(`kiwi.execution.v2`). It is deliberately not the wire/serialization schema
(`model.RunnerProtocolVersion` plus the per-record `schemaVersion` fields):
two builds may exchange the same fields while INTERPRETING durable state or a
compiled job differently. The stamp is durable state; it travels into the
signed evidence (the execution attestation's canonical digest and the artifact
provenance statement) and into workspace snapshot records, and exact replay
refuses to reinterpret a record produced under a different non-empty version
under the current engine.

**Bump rule.** Any change to how the scheduler, the runner or the executor
interprets durable state or compiled jobs — a changed MEANING of existing
state, not a field addition the existing semantics safely ignore — MUST bump
`model.ExecutionSemanticsVersion` and document the new semantics on the
constant. Records persisted before stamping existed carry the empty string;
exact replay assumes the current semantics for them and prints a warning.

**Enforcement points.**
- Constant and stamp fields: `model.ExecutionSemanticsVersion`,
  `model.Run.ExecutionSemantics`, `model.Job.ExecutionSemantics` and
  `model.SnapshotRecord.ExecutionSemantics` (`internal/model/model.go`).
- Enqueue stamping: every ingress (submit, webhook, rerun, schedule,
  downstream dispatch) funnels through `(*Server).enqueueID`
  (`internal/server/server.go`), which stamps the run and copies the run's
  value to every job; dynamically generated children inherit the parent run's
  stamp (`processGeneratedFragment`, `internal/server/dynamic.go`). A rerun or
  a downstream child is a NEW run and is stamped with the semantics in effect
  when it is created.
- Snapshot records: both upload paths stamp `j.ExecutionSemantics`
  (`internal/server/snapshots.go`).
- Evidence binding: `provenance.ExecutionAttestation.ExecutionSemantics` is
  part of `ExecutionAttestationDigest` (attestation `schemaVersion` 3), and
  `provenance.Statement.ExecutionSemantics` is set by `ArtifactStatement`
  from `server.artifactProvenanceInput`; both are covered by the DSSE
  signature. `kiwi verify` prints the verified value and enforces the
  optional `--execution-semantics` constraint.
- Exact replay decision table: `replayExecutionSemanticsCheck`
  (`internal/app/replay.go`) — equal to the current version: proceed; EMPTY
  (pre-stamp legacy record): warn that current semantics are assumed, then
  proceed; any OTHER value: refuse naming the recorded and current versions,
  unless the forensic `--allow-unknown-semantics` escape hatch is passed
  (loud warning; `--debug-rerun` is exempt because it never claims to
  reproduce the recorded execution).
- Attempt identity: the replay export carries the job's stamp
  (`runJobPipeline.ExecutionSemantics`, `exportRunJobPipeline`) and the
  replay client reads it from the recorded data.

**Related.** Exact replay (I5) and the constrained graph-mutation algebra
([graph-mutations.md](graph-mutations.md)): a graph mutation may only ADD
nodes to its run (`AddNode`/`AddDependency`/`ExpandFanout`), so it can never
introduce a job stamped with semantics different from its run's.

**Regression tests.**
- `TestExecutionSemanticsConstants`, `TestExecutionSemanticsAdditiveJSON`
  (`internal/model/runner_protocol_test.go`).
- `TestEnqueueStampsExecutionSemanticsMemory`,
  `TestEnqueueStampsExecutionSemanticsDBFake`,
  `TestRerunStampsExecutionSemantics`,
  `TestGeneratedFragmentInheritsExecutionSemantics`
  (`internal/server/enqueue_test.go`, `internal/server/rerun_trusted_test.go`,
  `internal/server/dynamic_receipt_test.go`).
- `TestAttestationEffectBindsDurableEvidence`,
  `TestArtifactUploadProvenanceCarriesFullIdentity`,
  `TestSnapshotUploadStampsAttemptIdentityMemory`,
  `TestSnapshotUploadStampsAttemptIdentityDB`,
  `TestExportRunJobPipelineRequiresAdminMemory`,
  `TestExportRunJobPipelineDB` (`internal/server/attestation_test.go`,
  `internal/server/blobs_provenance_identity_test.go`,
  `internal/server/replay_pipeline_test.go`).
- `TestExecutionAttestationBindsExecutionSemantics`,
  `TestArtifactStatementCarriesExecutionSemantics`,
  `TestExtendedFieldsRoundTrip`, `TestExecutionAttestationConstraints`
  (`internal/provenance/attestation_test.go`,
  `internal/provenance/provenance_test.go`): the version is digest-bound and
  tampering with it fails verification.
- `TestReplayExactExecutionSemanticsDecisionTable`
  (`internal/app/replay_exact_test.go`).
- `TestVerifyFlagsPlumbedToVerifyWith`, `TestVerifyPrintsExecutionSemantics`
  (`internal/app/verify_test.go`, `internal/app/verify_attestation_test.go`).
- `TestPostgresIntegrationExecutionSemanticsRoundTrip`
  (`internal/storage/postgres_roundtrip_it_test.go`): payload-additive in
  PostgreSQL, legacy payloads read back empty.

**Status.** enforced+tested.

---

## I6 — Graph mutation cannot invalidate committed history

**Statement.** A dynamic pipeline fragment may only add jobs to its run. It
cannot rewrite or shadow a committed job row: the `(parent job, mutation slot)`
key admits exactly one winning fragment per slot, an idempotent replay returns
the recorded receipt, a different fragment for the same slot is refused, and a
child key that collides with an existing run job (run-scoped logical identity)
is refused before any insert. Committed history is therefore stable under any
late, duplicated, or racing graph mutation.

**Constrained algebra.** The mutation surface is defined as a deliberately
limited operation algebra — AddNode, AddConditionalNode, AddDependency,
ExpandFanout, CancelPendingSubgraph, SealSubgraph — with explicit legality
rules (queued-only insertion, no rewrite of a committed node's prerequisite
set, fragment-confined edges, acyclic graphs, depth/count caps,
slot-idempotent replay, run-scoped key uniqueness) and explicit non-goals
(remove edge, replace node, arbitrary fan-outs, mutation of committed nodes).
Each rule is mapped to enforcement and tests in
[graph-mutations.md](graph-mutations.md).

**Enforcement points.**
- Mutation-slot winner: `(parent_job_id, mutation_slot)` unique index
  (migration `0047`); `InsertGeneratedFragmentTx` resolves the slot under the
  parent job lock and refuses conflicts with `ErrGeneratedMutationConflict`
  (`internal/storage/postgres.go:5133`, `:5252`, lookup at `:5267`).
- Run-scoped job key identity: `UNIQUE(run_id, key)` (migration `0048`),
  shared admission check `storage.CheckGeneratedJobKeyConflicts`, server
  `409 GENERATED_JOB_KEY_CONFLICT` (`internal/server/dynamic.go`).
- Replay idempotency: committed receipt returned for the same
  `(parent, slot, fragment)`, and the lease generation recorded at commit is
  re-checked before a replay (`TestGeneratedFragmentStaleGenerationCannotReplay`).

**Regression tests.**
- `TestDynamicFragmentReplayIdempotent`,
  `TestDynamicFragmentDifferentIDConflicts`,
  `TestGeneratedFragmentInsertionPredicateParity`,
  `TestGeneratedFragmentConcurrentCapRaceParity`,
  `TestGeneratedFragmentStaleGenerationCannotReplay`,
  `TestRestoreGeneratedFragmentsSlotConflictKeepsNewest`
  (`internal/server/dynamic_receipt_test.go`).
- Operation/legality algebra pinning (queue-only insertion, implicit parent
  edge, fragment-confined dependencies, cycles, conditional children,
  committed-node immutability, completion/cancel sealing):
  `TestGraphMutationAddNodeQueuesChildWithParentEdge`,
  `TestGraphMutationAddDependencyStaysInsideFragment`,
  `TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges`,
  `TestGraphMutationRejectsCycle`,
  `TestGraphMutationConditionalChild`,
  `TestGraphMutationNeverMutatesCommittedNodes`,
  `TestGraphMutationCompletedParentSealsGeneration`,
  `TestGraphMutationCancelRunSealsPendingSubgraph`
  (`internal/server/graph_mutation_algebra_test.go`; mapped in
  [graph-mutations.md](graph-mutations.md)).
- `TestGeneratedFragmentChildKeyCollidesWithExistingRunJob`,
  `TestGeneratedFragmentChildKeyCollidesAcrossFragments`,
  `TestGeneratedFragmentMatrixKeysStayDistinct`
  (`internal/server/dynamic_key_conflict_test.go`).
- `TestCheckGeneratedJobKeyConflicts`,
  `TestMemStoreGeneratedFragmentChildKeyConflict`
  (`internal/storage/run_key_identity_test.go`).
- `TestPostgresIntegrationGeneratedFragmentChildKeyCollidesWithExistingRunJob`,
  `TestPostgresIntegrationGeneratedFragmentChildKeyCollidesAcrossFragments`,
  `TestPostgresIntegrationUpgradeWithDuplicateRunKeysSkipsUniqueIndex`
  (`internal/storage/postgres_run_key_conflict_it_test.go`).

**Status.** enforced+tested.

---

## I7 — Speculative execution has a single winner

**Statement (pre-committed).** When speculative execution of a job is added,
at most one speculative attempt may commit the outcome for a given
`(job, lease generation)`; losing speculators must be cancelled and must
commit nothing (no completion, no ledger event, no external effect). The
winner is decided by the same compare-and-commit fence every other lease-owned
mutation uses (I3/I1).

**Surface in this tree.** ABSENT. There is no speculation scheduler, no
speculative lease class, and no speculative outcome handling; the repository
contains only `ROADMAP.md` prewarming (image/VM prewarming, which executes no
jobs). Grep for `speculat` finds no execution surface.

**Enforcement points.** None (surface absent). Any future implementation MUST
reuse the per-`(job, generation)` commit fence and the single-terminal-outcome
receipts (I1) and update this section with enforcement points and tests.

**Status.** pre-committed, surface absent — explicitly NOT a claim about
existing behavior.

---

## I8 — Cancellation and terminal monotonicity

**Statement.** A run or job never leaves a terminal state, and repeating a
cancel or approve request produces ONE logical transition:
- `POST /runs/{id}/cancel` on an already-terminal run (success, failure,
  cancelled, skipped, blocked) returns `200` with the current run and performs
  no state change, no second `run.cancelled` audit row and no forge status
  republish. The first cancel is unchanged: audit row, single transactional
  job/run cancellation, forge publication.
- `POST /jobs/{id}/approve` on an already-approved, non-terminal job returns
  `200` with the current job and performs no second `job.approved` audit row,
  no second `approval.granted` event and no approver rewrite: the FIRST
  approver (`ApprovedBy`, and `ApprovedAt` when set) is preserved. Terminal
  jobs still answer `409`, jobs that do not require approval still answer
  `409`, and the first approval is unchanged.
- Terminal jobs are skipped by the cancellation sweep, and a cancelled run is
  frozen against later aggregation.

Note on the run surface: there is no distinct non-terminal "cancelling" state
(no `StatusCancelling`, no `CancelledAt`) in this tree. The durable record of a
cancel is exactly the terminal `cancelled` outcome, so "already recorded" is
the terminal branch. Concurrent duplicate cancels are serialized by the
store's transactional `CancelRunJobs` (exactly one transition); the
evidence-first audit ordering means a loser of that race can still have placed
its audit row before observing the winner — a documented, bounded residual
(the transition itself is single).

**Enforcement points.**
- Memory cancel: `(*Server).cancelRun` — `internal/server/server.go:6031`
  (terminal replay before audit/persist/forge).
- DB cancel: `(*Server).cancelRunDB` — `internal/server/server.go:6111`
  (terminal replay before audit/scheduler/forge).
- Cancellation transition (skips terminal jobs, freezes the run):
  `(*Server).cancelRunLocked` — `internal/server/server.go:6171`;
  transactional DB mirror `(*PostgresStore).CancelRunJobs` —
  `internal/storage/postgres.go:3205`.
- Memory approve: `(*Server).approveJob` — `internal/server/server.go:5677`.
- DB approve: `(*Server).approveJobDB` — `internal/server/server.go:5767`.
- Store-level approve idempotency under the row lock (no second
  `approval.granted`, first approver kept): `(*PostgresStore).ApproveJob` —
  `internal/storage/postgres.go:1685`; memStore mirror —
  `internal/storage/faultstore.go:2567` (FaultyStore wrapper at `:369`).
- Run aggregation freeze: `recomputeRunStatus` —
  `internal/storage/postgres.go:2904`.

**Regression tests.**
- `TestCancelRunIdempotentMemory`, `TestCancelRunIdempotentDB`,
  `TestApproveJobIdempotentMemory`, `TestApproveJobIdempotentDB`
  (`internal/server/idempotent_cancel_approve_test.go`): double cancel = one
  audit row + one forge publish (+ one scheduler call in DB mode);
  cancel-after-success stays success with no audit/forge; double approve = one
  audit row + one event with the first approver kept; 409 refusals unchanged.
- `TestMemStoreApproveJobIdempotentReplay`
  (`internal/storage/approve_idempotency_test.go`).
- `TestPostgresIntegrationApproveJobIdempotentReplay`
  (`internal/storage/postgres_approve_idempotency_it_test.go`).
- `TestSqueezeCancelBranches` (terminal job untouched by the cancel sweep),
  `TestCancelRunReleasesRunnerSlotMemory/DBFake`
  (`internal/server/lease_claim_test.go`).
- `TestPostgresIntegrationCancelRunJobs` (re-cancelling a terminal run is a
  no-op) — `internal/storage/postgres_integration_test.go`.
- `TestExecutionEventTerminalStatusesIncludeBlocked`
  (`internal/storage/execution_events_test.go`).

**Status.** enforced+tested.

---

## I9 — Credentials never exceed the execution that requested them

**Statement.** A credential is issued only to the execution that was
authorized to request it, for exactly what that execution declared, and it is
bound to the attempt that requested it:
- OIDC: the requested audience must be in the job's enqueue-time capability
  allowlist; claims are derived from the locked job identity (run, job,
  attempt) and audience; issuance and its audit event commit in one
  transaction under a full commit-time lease predicate (holder, generation,
  token hash, DB-clock expiry), replay of the same `(job, generation, name)`
  returns the recorded delivery.
- Secrets: only step/policy-declared names are issued; the value is sealed to
  the runner's ephemeral key with AAD binding runner/job/generation/name and
  the claim is single-use; a replay of the same `(job, generation, name)`
  converges on the recorded envelope; a lease that changed or expired before
  commit gets nothing.

**Enforcement points.**
- OIDC issuance gates: audience allowlist + lease token + live lease +
  incarnation + schema fence — `(*Server).issueOIDC`
  (`internal/server/oidc.go:727`, audience gate ~`:799`); commit-time
  predicate `(*PostgresStore).CommitOIDCIssuance`
  (`internal/storage/postgres_oidc_issue.go:427`), typed refusals
  `ErrOIDCIssuanceGeneration/Runner/Token/Expired`.
- Secret issuance gates: declaration and lease checks — `(*Server).issueSecret`
  (`internal/server/secret.go:659`); commit-time predicate
  `(*PostgresStore).CommitSecretIssuance`
  (`internal/storage/postgres_secret_issue.go:294`), sealed delivery +
  receipt replay, single-use claims; AAD `secretAAD`
  (`internal/server/secret.go:135`).

**Regression tests.**
- `TestOIDCIssuanceGenerationChangedBeforeCommitReturns409`,
  `TestOIDCIssuanceIdentityChangedBetweenAuthAndCommitReturns409`,
  `TestOIDCIssuanceClaimsDerivedFromLockedIdentity`,
  `TestOIDCIssuanceNeverReturnsJWTWithoutDurableAudit`,
  `TestOIDCIssuanceAudienceChangedBeforeCommitReturns403`
  (`internal/server/oidc_lease_commit_test.go`).
- `TestOIDCTokenClaimsBoundToJobAndLease`,
  `TestOIDCIssuanceDenialMatrixMemoryAndDB`
  (`internal/server/oidc_scope_test.go`).
- `TestSecretGenerationChangedBeforeCommitReturns409`,
  `TestSecretConcurrentRequestsOnlyOneReturnsEnvelope`,
  `TestSecretNoEnvelopeWithoutDurableAudit`
  (`internal/server/secret_lease_commit_test.go`).
- `TestSecretAADContextBinding`,
  `TestIssueSecretClaimSingleUseAcrossReplicas`,
  `TestSecretScopeUsesCanonicalRepositoryID`
  (`internal/server/secret_scope_test.go`).
- `TestIntegrationLeaseCommitPredicatesRevoked` (artifact/snapshot/report
  commit fence) — `internal/storage/lease_commit_it_test.go`.

**Status.** enforced+tested.

---

## I10 — Untrusted execution cannot populate a trusted cache namespace

**Statement.** A cache entry's namespace is derived server-side from the
LEASED job's canonical repository identity and trust domain, never from client
headers or client-supplied names; an untrusted job therefore reads and writes
only the `untrusted` namespace of its repository, cannot observe or poison the
`trusted` namespace, and namespace/trust headers on cache requests are
rejected. Cache publication is additionally lease-fenced (I3), and cache
pruning is trust-domain isolated.

**Enforcement points.**
- Namespace derivation: `cacheNamespace` (canonical repo + trusted/untrusted)
  and `cacheFileKey` (sha256 over repo, trust, logical key) —
  `internal/server/blobs.go:1142`, `:1155`; used by both upload and download
  (`uploadJobCache`, `downloadJobCache`).
- Client namespace headers rejected: `internal/server/blobs.go:1166`.
- Lease-fenced manifest publish: `writeCacheManifest` (requires
  `LeaseCommitStore` in DB mode; `PutCacheManifestForLease` returns
  `ErrLeaseLost` without a live lease) — `internal/server/blobs.go:1453`,
  `internal/storage/lease_commit.go`.

**Regression tests.**
- `TestJobCacheLeaseNamespacedPutGet`,
  `TestJobCacheRejectsNamespaceHeaders`,
  `TestCacheManifestCarriesServerDerivedNamespace`
  (`internal/server/jobcache_test.go`).
- `TestPruneCacheManifestsTrustDomainIsolationFS`
  (`internal/server/cache_prune_test.go`),
  `TestPruneCacheManifestsTrustDomainIsolation`
  (`internal/storage/cache_prune_test.go`).
- `TestMemStoreLeaseCommitTrustedCacheNamespace`
  (`internal/storage/lease_commit_count_test.go`).
- `TestCacheNamespaceSeparatesSameNameAcrossForges`
  (`internal/server/repoidentity_test.go`).

**Status.** enforced+tested.

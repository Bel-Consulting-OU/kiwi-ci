# Dynamic Graph Mutations: A Constrained Algebra

Kiwi's dynamic pipeline generation is **not** arbitrary DAG editing. There is
exactly one mutation surface — the runner uploads a *pre-expanded fragment* of
new child jobs — and everything else a graph editor would normally do (remove
an edge, replace a node, rewire a committed job) is deliberately absent. This
document defines the operation algebra and the legality rules that bound it,
each mapped to the code that enforces it and the tests that prove it. It is
the companion to [INVARIANTS.md](INVARIANTS.md) invariant **I6 (graph mutation
cannot invalidate committed history)**; a change that adds an operation or
loosens a rule MUST first extend the invariant analysis (I1/I2/I6) and update
this mapping in the same change.

Line numbers are a convenience for the tree at the time of writing; the named
symbol is the stable reference.

## The one mutation surface

| Item | Where |
|---|---|
| Wire endpoint | `POST /api/v1/jobs/{id}/generated` — `internal/server/server.go:1235`, handler `(*Server).generateJobs` `internal/server/dynamic.go:91` |
| Wire type | `v1.GeneratedFragment` (`fragment_id`, `jobs`, `deps`) — `internal/api/v1/generated.go:23` |
| Content address | `(*v1.GeneratedFragment).Digest` — sha256 hex of the canonical `{jobs, deps}` — `internal/api/v1/generated.go:34`; the server recomputes it and rejects a missing/mismatching id before any admission (`processGeneratedFragment`, `internal/server/dynamic.go:320-329`) |
| Admission | `(*Server).processGeneratedFragment` — `internal/server/dynamic.go:319` (shape, deps, `pipeline.Validate`, capability inheritance, caps, ID allocation) |
| Transactional commit | `InsertGeneratedFragmentTx` — `internal/storage/postgres.go:5133` (PostgreSQL), `(*dbFakeStore).InsertGeneratedFragmentTx` (server DB-fake mirror), memory critical section `internal/server/dynamic.go:615-709` |
| Idempotency receipt | `generated_fragments` table keyed `(parent_job_id, mutation_slot)` (migration `0047_generated_fragment_mutation_slot.sql`); memory map keyed by `generatedFragmentKey` `internal/server/dynamic.go:722` |
| Run-scoped node identity | `UNIQUE(run_id, key)` (migration `0048_run_scoped_job_key_identity.sql`) with shared admission `storage.CheckGeneratedJobKeyConflicts` — `internal/storage/store.go:885` |

The generating job is the **implicit prerequisite of every child**: the server
builds each child's `Needs` as `[parent job ID] ++ deps[child]`
(`internal/server/dynamic.go:530-537`) and writes `Status: queued`,
`DynamicDepth: parent.DynamicDepth + 1` (`internal/server/dynamic.go:544-545`).
The fragment's own `deps` map carries the fragment-internal edges. A `needs`
field inside a fragment job body is **cleared, never honored**
(`internal/server/dynamic.go:378`): edges are expressed only through `deps`.

## Operations

The complete named operation set. An operation not in this table does not
exist on the surface (see [Non-goals](#non-goals)).

| Operation | Semantics | Enforcement (symbol) | Tests |
|---|---|---|---|
| **AddNode** | Add one pre-expanded child job (a `jobs` entry) to the generating job's run. The child is a real queued job row with the parent as its implicit prerequisite. | `processGeneratedFragment` shape check and construction: `internal/server/dynamic.go:374-380`, `:538-556`; insert `InsertGeneratedFragmentTx` `internal/storage/postgres.go:5246-5250` | `TestDynamicGenerateHappyPath`; `TestGraphMutationAddNodeQueuesChildWithParentEdge` |
| **AddConditionalNode** | Give a new child a job-level `if:` condition. The condition gates the child at scheduling time; it does not create or remove edges. | Condition validated by `pipeline.Validate` → `validateCondition` (`internal/pipeline/validate.go:829`, called at `internal/server/dynamic.go:406`) and persisted as `Job.Condition` from `cj.Job.If` (`internal/server/dynamic.go:541`) | `TestGraphMutationConditionalChild` |
| **AddDependency** | Declare a fragment-internal edge `deps[child] = [dep...]` among the fragment's own keys. Every child also receives the server-generated implicit parent edge. | `deps` key/value membership, self-edge and duplicate-edge checks `internal/server/dynamic.go:381-398`; implicit parent edge `:530-537`; cycle check `pipeline.Validate` `internal/pipeline/validate.go:147,220`; insertion-time graph recheck `verifyGeneratedFragmentGraph` `internal/server/dynamic.go:174` | `TestGraphMutationAddNodeQueuesChildWithParentEdge`; `TestGraphMutationAddDependencyStaysInsideFragment`; `TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges`; `TestFlowDynamicFragmentShapeErrors` |
| **ExpandFanout** | A generated child that itself declares `generate:` may emit a further fragment at runtime. Nesting is bounded, never unbounded. | Child inherits the parent's compiled `generate` envelope; `childDepth := parent.DynamicDepth + 1` and the effective depth cap `internal/server/dynamic.go:330,365-371,278`, rechecked at insertion `:174-188`; global `maxDynamicDepth = 2` `:35` | `TestDynamicGenerateDepthLimit`; `TestFlowDynamicFragmentHonorsParentGenerateEnvelope`; `TestDynamicGenerateHappyPath` (depth 1 child) |
| **CancelPendingSubgraph** | Terminate pending generated work. There is **no targeted per-node cancel**: the only cancellation primitive is run-scoped (`POST /api/v1/runs/{id}/cancel`) and cancels every non-terminal job of the run — queued generated children included — voiding their leases. After cancellation no further generation is possible (the lease is gone). | Run route `internal/server/server.go:1207`; memory funnel `cancelRunLocked` `internal/server/server.go:6212`; DB `CancelRunJobs` selects `NOT (status IN terminal set)` `internal/storage/postgres.go:3205,3216`; I8 semantics | `TestGraphMutationCancelRunSealsPendingSubgraph`; I8 tests in `internal/server/idempotent_cancel_approve_test.go` |
| **SealSubgraph** | Complete a job and emit nothing further. Completion voids the lease; the mutation surface then refuses every upload (new or replay) for that parent, and the run aggregates toward its terminal outcome. Sealing is automatic — it requires no separate operation. | `validLeaseIdentity` requires `StatusRunning` `internal/server/runner_lease.go:65-73`; `generateJobs` authorization gate `internal/server/dynamic.go:100-104`; commit-time predicate `ValidateGeneratedParentLease` `internal/storage/store.go:1008`, `internal/storage/postgres.go:5173`; I1/I8 aggregation | `TestGraphMutationCompletedParentSealsGeneration`; `TestGeneratedFragmentStaleGenerationCannotReplay`; `TestGeneratedFragmentInsertionPredicateParity` ("not running") |

## Legality rules

Each rule states what must hold for **any** admitted fragment, the enforcing
code, and the test that fails if the enforcement is removed.

### L1 — Only QUEUED nodes may ever be added

Every child written by the fragment path is constructed with
`Status: model.StatusQueued` (`internal/server/dynamic.go:544`) under the
parent's live lease; there is no code path that inserts a child in any other
state. The memory commit runs the assignment, the graph recheck, the
key-conflict check and the snapshot persist inside one `s.mu` critical section
(`internal/server/dynamic.go:615-709`); the PostgreSQL commit inserts the
children and the receipt in one transaction (`internal/storage/postgres.go:5246-5279`).

Boundary: the storage layer treats `GeneratedFragmentRequest.Jobs` as already
admitted compiled jobs and does not itself re-force the status. The server is
the sole production caller of `InsertGeneratedFragmentTx`, and the queue-only
property is pinned by test rather than by a storage-side assertion.

Tests: `TestGraphMutationAddNodeQueuesChildWithParentEdge` (every child queued,
depth incremented), `TestDynamicGenerateHappyPath`.

### L2 — No mutation may alter the prerequisite set of a Running/Succeeded/Failed/Cancelled node

`InsertGeneratedFragmentTx` only INSERTs new job rows and dependency rows for
those new IDs (`internal/storage/postgres.go:5246-5258`); it never updates an
existing job's `Needs`, `Status` or any other column. The server builds edge
sets exclusively for the newly created children. A fragment therefore cannot
rewire a node that already has history.

Tests: `TestGraphMutationNeverMutatesCommittedNodes` (all pre-existing run jobs
are byte-identical after an admission, including the generating parent);
`TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges`.

### L3 — A newly introduced prerequisite may only target an unstarted (queued) node

Every edge introduced by a fragment ends at a node created by that same
fragment, which is queued by L1. The generating parent gains no new
prerequisites; fragment-internal edges point only at fragment keys. Targeting a
running or terminal node is not expressible: every `deps` key and every
dependency value must be a declared fragment key, and a name outside the
fragment (including the parent's own key or any existing run job) is refused
whole.

Tests: `TestGraphMutationNeverMutatesCommittedNodes`,
`TestGraphMutationAddDependencyStaysInsideFragment`,
`TestFlowDynamicFragmentShapeErrors`.

### L4 — Fragment edges are confined to the fragment (plus the implicit parent) and never reference existing job keys

`processGeneratedFragment` rejects a `deps` key that is not a fragment job and
a dependency that is not a fragment job, with the whole fragment refused
`400` and nothing inserted (`internal/server/dynamic.go:381-398`). The only
non-fragment reference permitted is the server-generated implicit parent edge.
A fragment job body's `needs` field is cleared before validation
(`internal/server/dynamic.go:378`), so it cannot smuggle an edge to an existing
job either.

Tests: `TestGraphMutationAddDependencyStaysInsideFragment` (dep on the parent
key and on an injected existing run job both rejected),
`TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges`,
`TestFlowDynamicFragmentShapeErrors`.

### L5 — Graphs stay acyclic

The fragment is compiled into a synthetic spec and validated by
`pipeline.Validate`, whose `findCycle` rejects any cycle
(`internal/pipeline/validate.go:147,220`; called at
`internal/server/dynamic.go:406`). Self-dependency is rejected earlier with a
dedicated error (`internal/server/dynamic.go:390`). A cycle through the
implicit parent edge is impossible: the parent is not a fragment node and no
fragment node is ever added to the parent's prerequisite set (L2).

Tests: `TestGraphMutationRejectsCycle`, `TestFlowDynamicFragmentShapeErrors`
(self dependency).

### L6 — Depth and size caps are enforced per fragment, per parent envelope and per run

| Cap | Value | Enforcement |
|---|---|---|
| Fragment upload bytes | 256 KiB | `maxGeneratedFragmentBytes` `internal/server/dynamic.go:28`; `decodeLimit` `:93` |
| Jobs per fragment | 128 global, tightened by the parent's declared `generate.max_jobs` | `maxGeneratedJobsPerFragment` `internal/server/dynamic.go:30`; `effectiveGeneratedJobsLimit` `:264`; authoritative payload decoder `parentGenerateEnvelope` `:218`; insertion recheck `verifyGeneratedFragmentGraph` `:174-195` |
| Generation depth | 2 global (`maxDynamicDepth`), tightened by the parent's declared `generate.max_depth` | `:35`; `childDepth` `:330`; `effectiveGeneratedDepthLimit` `:278`; insertion recheck `:182-188` |
| Total jobs per run | 4096 | `maxJobsPerRun` `:33`; handler pre-check `:444`; commit-time check `internal/storage/postgres.go:5238-5244` + `:196-198` |

An unreadable current-format parent policy payload fails closed instead of
widening the cap (`parentGenerateEnvelope` `internal/server/dynamic.go:218-259`).

Tests: `TestDynamicGenerateDepthLimit`, `TestDynamicGenerateRejectsFragmentTooLarge`,
`TestFlowDynamicFragmentShapeErrors`, `TestFlowDynamicFragmentHonorsParentGenerateEnvelope`,
`TestGeneratedFragmentInsertionPredicateParity` (cap exceeded),
`TestGeneratedFragmentConcurrentCapRaceParity`.

### L7 — Same `(parent, mutation slot)` with the same digest replays; a different digest conflicts

The logical mutation slot is server-side state, never client-supplied:
`GeneratedFragmentMutationSlotDefault = "generated"` (`internal/storage/store.go:801`)
is the only slot today (`internal/server/dynamic.go:335`). The receipt identity
is `(parent_job_id, mutation_slot)` — the lease generation authorizes the
upload but never defines the mutation. The same digest replays the original
children with `200`; a different digest in the committed slot is refused with
`*storage.GeneratedMutationConflictError` → `409 GENERATED_MUTATION_CONFLICT`
(`internal/server/dynamic.go:117-124`; DB `internal/storage/postgres.go:5181,5278`;
memory `internal/server/dynamic.go:643-659`).

Tests (already covered — not duplicated):
`TestDynamicFragmentReplayIdempotent`, `TestDynamicFragmentDifferentIDConflicts`,
`TestGeneratedFragmentReplaysAcrossInfrastructureRetry`,
`TestGeneratedFragmentNondeterministicRetryConflict`,
`TestRestoreGeneratedFragmentsSlotConflictKeepsNewest`,
`TestGeneratedFragmentStaleGenerationCannotReplay`,
`TestGeneratedFragmentReplaysAcrossFSRestart`.

### L8 — Run-scoped key uniqueness forbids a new logical node colliding with an existing one

`model.Job.Key` is the run-scoped logical node identity (matrix/shard suffix
included); `UNIQUE(run_id, key)` (migration `0048`) is the database backstop,
and the shared admission `storage.CheckGeneratedJobKeyConflicts`
(`internal/storage/store.go:885`) runs on every path: server memory
`internal/server/dynamic.go:669`, DB transaction under the run advisory lock
`internal/storage/postgres.go:5205-5236`. A collision refuses the whole
fragment with `409 GENERATED_JOB_KEY_CONFLICT` and inserts nothing
(`internal/server/dynamic.go:128-134`). On a database that already contained
duplicate `(run_id, key)` rows the unique index is deliberately not created
(migration `0048`), and the admission check remains authoritative.

Tests: `TestGeneratedFragmentChildKeyCollidesWithExistingRunJob`,
`TestGeneratedFragmentChildKeyCollidesAcrossFragments`,
`TestGeneratedFragmentMatrixKeysStayDistinct`,
`TestCheckGeneratedJobKeyConflicts`, `TestMemStoreGeneratedFragmentChildKeyConflict`,
plus the PostgreSQL integration twins in `internal/storage/postgres_run_key_conflict_it_test.go`.

### L9 — Generation is lease-authorized and commit-time fenced

A mutation requires the parent's live lease: authorization runs before the
receipt lookup so a stale generation or token can never observe committed
children (`authorizeRunnerLease` `internal/server/runner_lease.go:42`), and the
store re-evaluates the complete predicate `{running, runner, generation, token,
storage-clock expiry}` on the locked parent inside the insertion transaction
(`ValidateGeneratedParentLease` `internal/storage/store.go:1008`;
`internal/storage/postgres.go:5173`; memory `internal/server/dynamic.go:628`).
Every refusal wraps `ErrLeaseLost` and maps to `409`, never a misleading `400`
(`internal/server/dynamic.go:149`).

Tests: `TestGeneratedFragmentStaleGenerationCannotReplay`,
`TestGeneratedFragmentRacedLeaseLossMaps409Not400`,
`TestGeneratedFragmentInsertionPredicateParity`.

## Determinism note

Mutation is **content-addressed**, **slot-idempotent** and
**generation-authorized**:

- Content address: `fragment_id` is the sha256 of the canonical `{jobs, deps}`
  (`internal/api/v1/generated.go:34`), recomputed by the server. Identical
  emissions produce the identical id and converge; the runner retry path
  re-sends the same body (`internal/runner/runner.go:2808`).
- Slot idempotence: `(parent job, mutation slot)` admits exactly one digest;
  an identical re-emission under any later lease generation replays the
  original children, while a nondeterministic re-emission (different digest)
  fails closed `409`.
- Generation authorization: the presented lease generation must still be live
  at both the request gate and the commit-time predicate, but it never becomes
  part of the mutation identity — an infrastructure retry of the same logical
  parent under a new generation replays rather than duplicates.

## Non-goals

These are deliberately absent. Implementing any of them requires a new
invariant analysis (I1/I2/I6) and an updated mapping in this document and
INVARIANTS.md **before** the surface changes.

| Non-goal | Rationale |
|---|---|
| **Remove edge** | A committed dependency edge is durable scheduling input (I1/I2). Deleting it could admit a consumer before its producer committed — the exact history-invalidation I6 exists to prevent. No removal endpoint or store method exists. |
| **Replace node** | `(run, key)` identity plus insert-only commit make replacement inexpressible: a colliding key is refused `409` (L8) and a different key is a different logical node. No upsert path exists. |
| **Arbitrary split/join fan-outs** | Fragments are pre-expanded: a fragment job declaring `matrix:` is rejected (`internal/server/dynamic.go:375`), and there is no multi-parent join primitive beyond declaring several fragment-internal `deps`. |
| **Mutate dependency conditions of running nodes** | `if:` is only ever written when a child is created (`Job.Condition` from the fragment; L1/L2). No update path touches an existing job's condition. |
| **Mutate resources/capabilities of committed nodes** | Children inherit (or reduce) the parent's effective capabilities (`generatedChildCapabilities` `internal/server/dynamic.go:836`, intersection at `:852-862`); the canonical admission path `admitCompiledSpec` `:424` applies that ceiling. Nothing rewrites a committed job's policy. |
| **Mutate after partial execution of the target** | Every edge and node introduced by a fragment is created before any of it starts; there is no way to name, pause or edit an already-running generated node. |
| **Targeted per-node cancel/delete** | Cancellation is run-scoped only (see `CancelPendingSubgraph`); a single queued descendant cannot be cancelled or deleted independently. |

## Status

All operations and legality rules above are **enforced and tested** in the
tree. The new pinning tests live in
`internal/server/graph_mutation_algebra_test.go`. Two boundaries are documented
rather than claimed as enforcement:

1. Queue-only insertion (L1) is enforced by the admission path that constructs
   the jobs; the storage layer accepts already-admitted compiled jobs and does
   not re-assert the status.
2. Run-scoped key uniqueness (L8) has a database index backstop that is
   intentionally skipped on pre-existing dirty `(run_id, key)` databases
   (migration `0048`); the admission check remains authoritative there.

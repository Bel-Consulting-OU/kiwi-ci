# Formal model — Kiwi lease/commit protocol

`kiwi_lease.tla` is a tiny, bounded TLA+ model of Kiwi's job/lease/commit
protocol: one logical run, a bounded set of jobs, 1–2 runners, per-job
generations, cancellation and infrastructure retry. It states the fencing
invariants that the implementation enforces at commit time, so the design can
be checked independently of Go and kept in sync with the executable evidence
(property tests and the chaos matrix). It is NOT a reimplementation of the
server: it abstracts clocks, tokens, storage and HTTP away so the state space
stays small enough for exhaustive model checking.

Files:

| File | Purpose |
|---|---|
| `kiwi_lease.tla` | The TLA+ module: variables, actions (`Lease`, `Complete`, `StaleAttempt`, `Retry`, `CancelRun`), state invariants and temporal properties. Hand-written TLA+; no PlusCal toolchain is required. |
| `kiwi_lease.cfg` | TLC configuration: the bounded instance (`Jobs = {"job-a","job-b"}`, `Runners = {"runner-1","runner-2"}`, `MaxGen = 3`) and the invariant/property list. |

## Running TLC

TLC is not installed by this repository and is not part of the default build
or CI. To check the model locally:

1. Download `tla2tools.jar` from the official TLA+ releases:
   <https://github.com/tlaplus/tlaplus/releases> (any recent stable release;
   requires Java 11+).
2. From the repository root:

   ```bash
   java -jar /path/to/tla2tools.jar \
       -config formal/kiwi_lease.cfg \
       formal/kiwi_lease.tla
   ```

   TLC prints the number of distinct states explored and a violation trace if
   any invariant or property fails. The Toolbox GUI and the VS Code TLA+
   extension accept the same two files.

The bounded instance is intentionally small (2 jobs × 2 runners × 3
generations): exhaustive checking finishes in seconds. Raising `MaxGen` or the
constant sets grows the state space quickly; that is a deliberate limit, not a
claim that larger instances are equivalent.

## Invariants

State predicates (checked with `INVARIANT`):

| Invariant | Meaning |
|---|---|
| `TypeOK` | Every variable stays in its domain (bounded generations, known statuses, well-formed commit/refusal records). |
| `NoTwoWinners` | At most ONE authoritative successful completion per job across every retry and cancellation. |
| `StaleOwnerCannotCommit` | A commit refused by the fence (recorded as a stale attempt) can never later appear in the committed ledger, and committed generations never exceed the issued generation. |
| `OneCommitPerGeneration` | One attempt `(job, generation)` commits at most one outcome. |

Temporal properties (checked with `PROPERTY`):

| Property | Meaning |
|---|---|
| `TerminalityMonotonic` | The committed ledger only grows; a `success` outcome is absorbing, so a terminal record is never rewritten. |
| `CancelCannotResurrect` | Cancellation is terminal at both the run and job level: once cancelled, never running or committed again. |

## What the model intentionally does NOT cover

These are the abstraction boundaries; each has its own executable evidence
(see the mirror mapping below) and none of them weakens the model:

- **Time and lease expiry**: there is no clock; a lease never expires in the
  model. Real expiry/recovery is covered by the scheduler property lane and
  the store recovery paths (`TestExpiredLeaseRequeued`,
  `TestPropertySchedulerModelMachine` requeue statistics).
- **Token possession and rotation**: the model's holder is an abstract runner
  id. Token hashes, bearer credentials and mTLS identity are outside it
  (I3's commit predicates and the lease-fence chaos matrix cover them).
- **Crash/restart durability**: the model's `commits`/`refused` are
  write-once; real crash consistency and receipt replay are covered by the
  completion-receipt and restart tests (I1).
- **Concurrency and transactions**: TLA+ interleaving is sequential in this
  model; real row locks and one-transaction atomicity are covered by the PG
  integration tests (`TestPostgresIntegrationCompleteJobReceiptHashConflict`,
  `TestPostgresIntegrationSemanticEventAppendFailureRollsBack`) and the
  scheduler model property test.
- **Runner capacity/slots, retry budgets, dependency ordering**: not modeled;
  covered by the scheduler property lane and `SCH-*` rows of
  `ADVERSARIAL_TEST_MATRIX.md`.
- **Dynamic graph mutations**: not modeled; I6 and the fragment-admission
  property/fuzz targets cover them.
- **Speculative execution (I7)**: the surface does not exist in this tree, so
  there is nothing to model yet. Adding a speculation scheduler REQUIRES
  extending this model with a speculative-attempt variable and a
  single-winner invariant before the surface merges.
- **Multiple runs**: one logical run; reruns create new runs in Kiwi and are
  deliberately out of the model's scope.

## Mirror mapping: model → implementation → tests

The model stays aligned with the implementation through this table. Any change
to lease, commit, retry or cancel semantics MUST update the model and the
mirrored tests in the same change (the rule in
[`docs/INVARIANTS.md`](../docs/INVARIANTS.md): an invariant without a
randomized or fault-injected test is assumed unenforced).

| Model element | Implementation | Executable mirror |
|---|---|---|
| `Lease` (new generation per claim) | `(*PostgresStore).AcquireLeaseAtomic`; `internal/scheduler` claim paths | `TestPropertySchedulerModelMachine` (one holder per running job, generation monotonicity, claim == model winner) |
| `Complete` (commit-time fence: status + holder + generation) | `storage.ValidateGeneratedParentLease`, `lockedLeaseJobTx`, completion receipts (I1/I3) | `TestPropertySchedulerModelMachine` (completion == model outcome), `TestPostgresIntegrationCompleteJobReceiptHashConflict`, `TestCompletionReceiptsSurviveRestartReplay` |
| `StaleAttempt` (late owner refused, nothing changes) | every commit-time lease predicate; `ErrLeaseLost`/409 mapping | `TestPropertySchedulerStaleGenerationRefused`, `TestLeaseFenceChaosMatrixStaleGenerationRejected`, `TestGeneratedFragmentRacedLeaseLossMaps409Not400` |
| `Retry` (only from `failure`; new generation) | infra retry budget + generation bump in the scheduler/store recovery | `TestPropertySchedulerModelMachine` (requeues), `TestExpiredLeaseRequeued`, `TestGeneratedFragmentStaleGenerationCannotReplay` |
| `CancelRun` (terminal; voids leases) | `(*Server).cancelRunLocked`, `(*PostgresStore).CancelRunJobs`, `recomputeRunStatus` freeze (I8) | `TestCancelRunIdempotentMemory`, `TestCancelRunIdempotentDB`, `TestPostgresIntegrationCancelRunJobs` |
| `NoTwoWinners` | per-`(job, generation)` receipt compare-and-commit | `TestCompletionReceiptReplayMatchesVersionMatrix`, `TestPostgresIntegrationServerCompletionRaceDifferingResults` |
| `CancelCannotResurrect` | terminal status is absorbing; terminal jobs skipped by the cancel sweep; success frozen | `TestCancelRunIdempotentMemory/DB`, `TestSqueezeCancelBranches`, `TestExecutionEventTerminalStatusesIncludeBlocked` |

The executable property lane is `internal/scheduler/model_property_test.go`
(`TestPropertySchedulerModelMachine`); the deterministic stale-owner pin is
`TestPropertySchedulerStaleGenerationRefused`; the full-surface replay matrix
is `internal/server/lease_fence_chaos_test.go`
(`TestLeaseFenceChaosMatrixStaleGenerationRejected`). The mapping also appears
as the evidence-map row for I1–I3/I8 in
[`docs/INVARIANTS.md`](../docs/INVARIANTS.md).

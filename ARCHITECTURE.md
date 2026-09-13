# Kiwi CI architecture

Kiwi deliberately separates **orchestration** from **execution** while keeping one pipeline compiler for local and remote use.

## Components

1. `cmd/kiwi` — one binary: local CLI, control plane, and runner.
2. `internal/pipeline` — YAML parser, validation, matrix expansion, conditions, interpolation, DAG compiler.
3. `internal/executor` — DAG scheduler and execution backends.
4. `internal/cache` — content-addressed cache archives with path traversal protection.
5. `internal/artifact` — first-class artifact capture.
6. `internal/secrets` — execution-time providers and log masking. Secret values are not compiled into pipeline plans.
7. `internal/server` — small control plane/API/dashboard plus verified GitHub webhook intake.
8. `internal/policy` — admission rules that prevent untrusted fork code from requesting secrets or native host execution.
9. `internal/runner` — pull-based worker. The current v0.1 task boundary is one full pipeline run; the executor still parallelizes its DAG locally.
10. `internal/provenance` — in-toto/SLSA-shaped signed build provenance primitive.
11. `internal/testintel` — JUnit parser foundation for flaky-test history and test splitting.

## Why the v0.1 remote task is a whole pipeline

A pipeline-run lease gives Kiwi a reliable, useful first implementation with correct local/remote parity and avoids pretending cross-runner artifact/workspace semantics are solved when they are not. The planned distributed scheduler promotes compiled jobs to individually leased execution units only when artifact CAS, workspace snapshotting, and runner-to-runner security invariants are enforced.

## Execution trust modes

- `native`: fastest. Executes directly on the host. Only use for trusted repositories.
- `container`: Docker-isolated Linux jobs.
- `tart`: disposable Apple-Silicon macOS/Linux VMs. Intended for untrusted or highly reproducible macOS jobs.

A future backend interface can add Kubernetes, Firecracker, Vetu, Windows Sandbox, remote-execution APIs, or organization-specific executors without changing pipeline syntax.

## Scheduling guarantees

The compiler rejects cycles and unknown dependencies before execution. A job becomes runnable only after all dependencies reach success or skip. Dependency failures block downstream jobs. Cancellation uses context propagation and process-group termination in native mode.

## Security invariants

- Webhook handlers must authenticate before state mutation (planned GitHub App module).
- Runner tokens authenticate runner-control-plane traffic.
- Secrets resolve only on the runner at execution time.
- Log masking occurs at source and again at display sinks.
- Cache extraction rejects traversal outside the workspace and only restores declared roots.
- Untrusted macOS PRs should use Tart, not `native`.
- Container jobs should be rootless by default in the production backend.
- Production control planes should replace the v0.1 in-memory store with PostgreSQL and use mTLS + short-lived runner identity certificates.

## v1 distributed scheduler

The job-level scheduler should use a lease model:

`compiled job -> ready queue -> capability match -> lease -> heartbeat -> execute -> CAS artifacts -> result -> unlock dependents`

A lease has an expiry and generation number. Completion is idempotent. Lost runners cause the same lease generation to be retried only when the job retry policy allows infrastructure retries.

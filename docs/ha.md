# High availability

The PostgreSQL-backed control plane elects one leader among its
instances. This document describes the lock, the leader's duties, and
failover behavior.

## Advisory lock

Leadership is a session-level PostgreSQL advisory lock:

- lock key: `kiwi-scheduler` (`scheduler.DefaultLeaderKey`);
- held on a dedicated connection for the lifetime of the session;
- soft renewal TTL: 15 seconds by default.

`TryAcquireLeadership` renews the claim and reports ownership. On
startup the scheduler attempts to acquire the lock once: winning makes
the instance leader; losing to a live leader starts it as a standby. A
hard store failure is surfaced via `InitErr` and must refuse startup.

## Leader duties

Only the leader may:

- lease jobs (`Lease` is leader-only);
- recover expired leases (`RecoverExpired` is leader-only);
- run background maintenance (GC, outbox flush, heartbeat sweeps).

The `Server.Maintain` loop polls `IsLeader`; a standby that observes
promotion takes the lock, reconciles expired leases, and becomes ready.

Standbys serve read traffic: run/job/log/artifact listings, the
dashboard, health, and metrics.

## Lease semantics

- Default lease duration: 45 seconds.
- Each lease carries a generation counter; acquisition is a single
  conditional update (`WHERE status='queued' AND (lease_expires_at IS
  NULL OR lease_expires_at < now())`), so two leaders can never both
  lease the same job.
- Heartbeats extend the lease; a heartbeat conflict that surfaces a
  concurrent cancellation tells the runner to stop.
- Completion is one transaction: verify generation + runner + running
  status, insert the completion receipt idempotently, update job and
  runner counters, recompute dependents and the run status, append the
  audit event.
- Server restarts preserve unexpired leases; jobs are not force-
  requeued while a lease is still valid.

## Expired-lease recovery

`RecoverExpired` finds running jobs whose leases expired and requeues
them while the attempt count is within the job's infrastructure retry
budget (`infra_retries`); past the budget the job fails with
`runner lease expired and infrastructure retry budget exhausted`.
Dependents are re-evaluated and run statuses recomputed. Because
runners self-cancel when they lose contact past the lease deadline,
recovery does not create duplicate concurrent executions.

## Failover checklist

1. Run two or more instances behind a load balancer with the same
   `database.url`, tokens, `external_url`, and shared key material.
2. Watch `GET /readiness` per instance; a standby is ready but will
   reject leader-only mutations.
3. On leader loss, a standby promotes within the TTL window. Jobs
   running under the old leader's leases are unaffected until their
   leases expire; runners fail over to the new leader's lease service.
4. Keep the database as the source of truth; do not restore instance
   memory state from backups (see
   [disaster-recovery.md](disaster-recovery.md)).

## Current limitations

The dev-mode in-memory scheduler is single-instance by design; HA
requires the PostgreSQL store. In DB mode, deployments persist through
`DeploymentStore`, snapshots through `SnapshotStore` (bytes stored
through the shared CAS), check-run mappings through `check_runs`,
schedule occurrences through `schedule_occurrences`, and completion
receipts/idempotent effect intents through the outbox — replicas
converge from PostgreSQL rather than sharing process memory. Advisory
locks (scheduler leadership, CAS digest fences, check publication,
collector lease) live on a dedicated lock pool so they never consume
the operational connections.

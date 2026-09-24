# Disaster recovery

This document describes what state exists, how to back it up, and how
to restore a Kiwi CI deployment.

## State inventory

| State | Location | Notes |
|---|---|---|
| Runs, jobs, leases, runners, receipts, artifacts metadata, logs, audit, deliveries | PostgreSQL | Durable SQL control plane (production). |
| Dev/persistent mode snapshot | `<data-dir>/state.json` | Atomically replaced JSON snapshot plus append-only log/audit files (filesystem `Repository`). |
| Lease HMAC key | `<data-dir>/lease.key` (fs mode) or `cluster_keys` table (DB mode) | Must survive restarts or lease tokens cannot be verified. |
| OIDC signing key | `<data-dir>/oidc-keyring.json` (fs mode) or `cluster_keys` table (DB mode) | Must survive restarts or issued tokens become unverifiable. Legacy `<data-dir>/oidc-ed25519.key` migrates into the ring on load. |
| Runner CA | `<data-dir>/runner-ca.*` (fs mode), `cluster_keys` table (DB mode), or operator-provided PEM | Must survive or enrolled runners lose trust. |
| Artifact/cache payload bytes | blob backend (`fs` path or S3 bucket) | The CAS layer stores `sha256/<first-2>/<full-digest>` objects. |
| Forge outbox | `<data-dir>/outbox.jsonl` + `outbox.done.jsonl` | Unflushed forge-status intents. |

## PostgreSQL backups

Standard Postgres tooling applies:

- `pg_dump` the `kiwi` database on a schedule (nightly minimum).
- Use PITR (`archive_command` + WAL shipping) for tighter RPO on
  production deployments.
- Test restores periodically; a backup that has never been restored is
  a rumor.

Hot-path job state (status, leases, counters) is relational; the full
model payload is a jsonb column, so a logical dump restores everything.

## Key material

The lease key, OIDC key, and runner CA are files, not rows. Back them
up out-of-band with restricted access. Losing them:

- **lease.key** — running leases become unverifiable; cancel all runs
  and restart clean. A new key is generated on next start.
- **oidc-keyring.json** — issued tokens become unverifiable; providers
  must be reconfigured for the new keys (see [oidc.md](oidc.md) for the
  rotation model).
- **runner CA** — enrolled runners fail mTLS; re-enroll or reload the
  CA from backup.

## Blob store

- `fs` backend: back up the blob path; digests make objects immutable
  and deduplicable, so `rsync` is safe and cheap.
- `s3` backend: enable bucket versioning or replication.

CAS integrity is verified on write and read, so a silent corruption
surfaces as a digest mismatch rather than a poisoned payload.

## Restore procedure

1. Restore PostgreSQL to a point in time.
2. Restore the key files and data directory (or regenerate and
   re-enroll).
3. Restore the blob store; verify digests.
4. Start a single instance, run `kiwi database migrate`/`database
   status` to confirm the schema version.
5. Bring up remaining instances and runners.

## Replay semantics

Several subsystems are explicitly replay-safe:

- **Completion receipts**: runner completions carry a generation-bound
  receipt; replaying a completion is a no-op for the same generation.
- **Webhook deliveries**: forge delivery IDs are deduplicated, so
  re-delivered events return the original run.
- **Outbox**: unflushed forge-status intents are replayed on startup
  and are idempotent by external ID.
- **Expired leases**: recovered only within the job's infrastructure
  retry budget; runners self-cancel on lost contact, so replay cannot
  duplicate concurrent execution.

## RPO/RTO guidance

- RPO: nightly `pg_dump` gives 24h worst case; PITR shrinks it to
  minutes. Blob store backups can lag further without data loss for
  immutable objects.
- RTO: minutes with a warm standby instance and automated restore;
  budget for `pg_dump` restore time plus digest verification for large
  blob stores.

## Dev-mode caveats

`state.json` mode is a local/development convenience: one writer, no
transactions across files. Do not build a production recovery story on
it; migrate to PostgreSQL before going multi-instance.

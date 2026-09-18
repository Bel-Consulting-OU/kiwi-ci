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

## Rollback

Rolling back the server binary is safe as long as the database schema
is compatible: new columns are additive. If a release contained a
breaking migration, roll back by restoring the database snapshot and
redeploying the old binary plus its data directory files.

## Behavioral compatibility notes

- Unrunning jobs carry their pipeline text, so a control plane
  restarted on a new version recompiles deterministically against the
  new compiler; test canary pipelines before rolling upgrades across
  large fleets.
- Lease and completion semantics (generation-bound receipts, HMAC-only
  tokens) are stable across restarts within protocol v3.
- Deployment and snapshot records are memory-backed; treat them as
  ephemeral across upgrades until their persistence lands.
- fs-mode `/readiness` is now durability-aware: when a data-dir snapshot
  write fails, it answers 503 with `X-Kiwi-State: degraded` and a fixed body
  (the raw error is only logged), new leases are refused until a later
  persist succeeds, and switching the server to DB mode clears the state.
  Operators upgrading an fs-mode deployment must make probes and load
  balancers stop routing to a degraded instance; a healthy `/liveness` does
  not mean the instance can accept new work.

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

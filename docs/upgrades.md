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

## Dependency upgrade policy

- Dependabot opens weekly pull requests for Go modules (`gomod`,
  commit prefix `deps`) and GitHub Actions (`github-actions`, commit
  prefix `ci`), capped at 5 open PRs per ecosystem
  (`.github/dependabot.yml`). A full CI matrix runs on every
  dependency PR; merge only when it is green.
- CI tooling versions are pinned, not floating:
  - `staticcheck` `honnef.co/go/tools/cmd/staticcheck@v0.6.1`
    (staticcheck 2025.1.1): the latest release compatible with the
    repository's Go 1.23 toolchain. Newer releases require Go 1.25+;
    when the module's `go` directive is bumped, move the pin forward
    in `.github/workflows/ci.yml` and re-run the baseline.
  - `govulncheck` `golang.org/x/vuln/cmd/govulncheck@v1.1.4`: the
    latest release compatible with Go 1.23, used both in CI and as a
    release gate.
  - Workflow actions are pinned to full commit SHAs; a tag move
    cannot change what CI runs. When upgrading an action, resolve the
    new tag to its commit SHA (`gh api repos/<owner>/<repo>/commits/<tag>`)
    and update the tag→SHA comment next to the step.
- Upgrading the Go toolchain (the `go` directive in `go.mod` and the
  `go-version` inputs in the workflows) must happen before bumping
  the staticcheck/govulncheck pins, and is a separate PR from
  dependency bumps so bisection stays clean.
- Docker base images are digest-pinned in the `Dockerfile`; re-resolve
  digests (`docker buildx imagetools inspect <image>`) whenever the
  image tag is bumped.
- Release signing is mandatory: `scripts/release.sh` fails closed
  without `KIWI_RELEASE_SIGNING_KEY`. Unsigned releases are only
  possible through an explicit `allow_unsigned` workflow dispatch
  (`KIWI_ALLOW_UNSIGNED_RELEASE=1`) and must be treated as a
  disaster-recovery exception, never the norm.

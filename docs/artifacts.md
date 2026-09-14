# Artifacts

Artifacts are first-class pipeline outputs: deterministic tar.gz
archives captured from the workspace, with sidecar manifests,
retention, provenance, and download contracts between jobs.

## Declaration

```yaml
artifacts:
  - name: app
    paths: [dist/**]
    if: success()
    retention: 7d
```

- `paths` — workspace-relative globs captured (symlinks and special
  files are never captured).
- `if` — condition over the job status; artifacts can be captured on
  failure for diagnostics.
- `retention` — Go duration or `forever`/`infinite`/`never`. Expired
  artifacts are removed by the server's garbage collector.

## Contracts

At enqueue the server persists the job's expected artifact names. The
upload endpoint (`PUT /api/v1/jobs/{id}/artifacts/{name}`) accepts only
declared artifacts from a runner holding the active lease. Uploads are
idempotent per (job, lease generation, name): a retried upload with the
same digest returns the existing artifact; a different digest is
rejected rather than silently stored twice.

Downloads are declared and validated:

```yaml
downloads:
  - from: build
    name: app
    path: .
```

`from` must be a declared `needs` dependency, and the download path is
confined to the workspace. Validation rejects downloads from
non-dependencies and unknown jobs.

## Manifests

Every artifact gets a sidecar manifest (`internal/artifact/manifest.go`):
version, name, run/job IDs, archive SHA-256, size, per-entry digests,
and creation time. The archive is deterministic: entries are sorted and
timestamps normalized.

## Provenance

The server can produce provenance statements for artifacts
(`GET /api/v1/artifacts/{id}/provenance`): in-toto/SLSA-shaped
statements bound to the artifact subject digest, signed with a
dedicated Ed25519 key. `kiwi verify` downloads an artifact and verifies
its DSSE signature against the server JWKS, binding the subject digest.

## Transport

Artifact bytes travel through `PUT /api/v1/jobs/{id}/artifacts/{name}`
with integrity hashes checked by the server, and are stored in the
blob backend (`fs` or `s3`). Wiring artifact transport through the
CAS layer (so a payload shared with cache entries is stored once) is a
known deferred item; today the artifact endpoint stores its own copy.

## Limits

- Artifact paths must be relative (no absolute paths, no `..`).
- Duplicate artifact names in a job are rejected.
- Extraction of downloaded artifacts is hardened via `internal/safefs`.

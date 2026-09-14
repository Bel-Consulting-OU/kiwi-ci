# Caching

Kiwi CI caches are content-addressed archive stores keyed by declared
inputs, with optional remote mirroring through the control plane.

## Declaration

```yaml
cache:
  - name: deps
    key: "go-${{ matrix.GO }}"
    hash_files: [go.sum]
    paths: [.kiwi/go-cache]
    restore_keys: [go-]
```

- `paths` — workspace-relative roots captured and restored.
- `key` — logical key base.
- `hash_files` — globs whose contents are folded into the key.
- `restore_keys` — fallback keys tried in order on a primary miss.

## Key computation

The stored key is
`sha256(namespace | key | GOOS | GOARCH | runtime | hashed files)`.
`hash_files` globs are hashed with workspace-relative path plus
content, mirroring the `hashFiles()` expression function.

## Namespaces

The executor prefixes every key with a cache namespace
(`CacheNamespace`; `local` when unset). The server scopes cache
namespaces per trust domain, so untrusted fork runs cannot populate
cache state later consumed by trusted runs.

## Restore and save

- Restore runs before the first step: the primary key, then each
  restore key. Extraction is hardened (`internal/safefs`): only regular
  files and directories, no symlink parents, duplicate entries, or
  path escapes, with archive/expanded/file size, entry count, depth,
  path length, and compression ratio limits, and only the declared
  roots are extracted.
- Save runs only when the job succeeds. Saves are atomic
  (write temp, rename) and enforce a maximum cache size.

## Remote protocol

When a runner's cache store has `RemoteURL` set, restore falls back to
`GET /api/v1/cache/{key}` and save mirrors to
`PUT /api/v1/cache/{key}` on the control plane, authenticated with the
runner credential. The server records cache uploads per job.

## Signed manifests

The blob/CAS layer adds signed cache manifests
(`internal/cache/manifest.go`): a `CacheManifest` binds a logical key
to an immutable `blob_sha256` payload digest plus size, repository,
trust domain, and producer run/job. Manifest envelopes are DSSE-shaped
and signed, so concurrent writers can race on the key-to-manifest
mapping while the payload itself can never be corrupted or mixed.

## Storage layout

Payloads live in the content-addressed blob store
(`internal/blob`): `sha256/<first-2>/<full-digest>`, with filesystem
or S3 backends. The CAS layer (`internal/cas`) verifies the digest on
write and read.

## Limits

- Max cache bytes is configurable per store.
- Cache paths must be relative (no absolute paths, no `..`).
- Untrusted jobs: cache read/write stays allowed but namespaced; all
  other capabilities are denied.

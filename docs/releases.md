# Releases and supply chain

This document describes how Kiwi CI release artifacts are produced, verified,
and reproduced: the release/snapshot gates, the Homebrew formula rendering, the
dependency SBOM, the SLSA builder identity, reproducible builds via
`SOURCE_DATE_EPOCH`, and the lifecycle of the Ed25519 release signing key.

Everything here is implemented by `scripts/release.sh` and
`cmd/release-tool`; `make release`, `make release-snapshot`, and
`make release-formula-test` are thin wrappers.

## 1. Release vs snapshot gating

`scripts/release.sh` has two build modes plus one internal helper. Release
mode is the default and fails closed: every check below must pass or the
script exits non-zero with a precise message and publishes nothing.

| Gate | release (default) | `--snapshot` |
| --- | --- | --- |
| Exact semver tag (`vX.Y.Z`) at `HEAD` | required | not required |
| `VERSION` matches the tag (without `v`) | required (`VERSION` may be omitted) | base version; `-snapshot+<short-sha>` appended |
| Tag points at `HEAD`, recorded commit = tagged commit | required | n/a |
| Recorded commit is the full 40-char lowercase SHA | required | short SHA (or explicit override) |
| Clean git tree | required | allowed; `.dirty` is appended to the version |
| Ed25519 signing key (`KIWI_RELEASE_SIGNING_KEY`) | required unless `--allow-unsigned` or `KIWI_ALLOW_UNSIGNED_RELEASE=1`; an explicit `--require-signing` overrides the env var | optional; unsigned snapshots are normal |
| `Formula/kiwi.rb` re-rendered from `Formula/kiwi.rb.tmpl` | every release, unconditionally | never; snapshot builds skip formula rendering rather than refusing |
| Bundle location | `dist/release/` | `dist/snapshot/`, with a `SNAPSHOT` marker file |
| `SOURCE_DATE_EPOCH` default | committer date of the tagged commit | current time unless set |

The tag is never inferred from a branch name: when `HEAD` is not an exact tag,
release mode refuses:

```
release: HEAD is not an exact tag; releases must be cut from a tagged commit
(use --snapshot for branch/dirty development builds)
```

Other release-mode refusals include a tag argument that is not the exact tag
at `HEAD`, a non-semver tag, a dirty tree, a `COMMIT` override that is not the
full 40-char SHA of the tagged commit, and a `VERSION` that does not match the
tag. Formula rendering has no flag: release mode always re-renders
`Formula/kiwi.rb`, and snapshot mode always skips it.

Signing policy precedence: an explicit `--require-signing` on the command line
wins over `KIWI_ALLOW_UNSIGNED_RELEASE=1`, which is only the default policy and
cannot neutralize the flag; `--allow-unsigned` is the explicit opt-out. When
both flags are given, the last one wins.

Invocation:

```sh
# Release (CI or a tagged workstation). KIWI_RELEASE_SIGNING_KEY may be the
# PEM itself or a path to it.
scripts/release.sh v1.2.3

# Development snapshot from any branch, clean or dirty.
scripts/release.sh --snapshot

# Force the fail-closed signing policy even if KIWI_ALLOW_UNSIGNED_RELEASE=1
# is set in the environment.
scripts/release.sh v1.2.3 --require-signing

# Disaster recovery only: unsigned release, loudly reported.
scripts/release.sh v1.2.3 --allow-unsigned
```

Snapshot versions look like `0.1.0-dev-snapshot+1a2b3c4` (or
`...+1a2b3c4.dirty`) and the bundle contains a `SNAPSHOT` marker file that
states the build is not a release. Snapshots are for testing; they are never
published as releases and never update the Homebrew formula.

## 2. Homebrew formula rendering

`Formula/kiwi.rb` is a generated file. `scripts/release.sh` renders it from
`Formula/kiwi.rb.tmpl` on every release with deterministic literal
substitution of three tokens: the version and the SHA256 digests of the
newly built `kiwi-darwin-arm64` and `kiwi-darwin-amd64` binaries. Rendering
always starts from the template, so it is independent of any previous content
of `Formula/kiwi.rb`, refuses to write output containing an unsubstituted
token, and refuses malformed digests.

The renderer is also exposed for tests and manual use:

```sh
scripts/release.sh --render-formula 1.2.3 <sha-arm64> <sha-amd64> [OUT]
scripts/release-formula-test.sh   # make release-formula-test
```

The test script renders `v1.2.3` and then `v2.0.0` over the same output file
and asserts that both times the version, both `/releases/download/v<version>/`
URLs, and both digests are exactly the new values, with no tokens and no
leftovers from the earlier rendering.

## 3. Dependency SBOM

For each built binary, `release-tool` writes `<binary>.sbom.cdx.json`, a
CycloneDX 1.5 document describing the **complete** Go dependency graph:

- `metadata.component` is the root component: the main module, type
  `application`, with the release version and
  `purl`/`bom-ref` = `pkg:golang/<module-path>@<version>`. `release-tool -name`
  overrides the component's display `name` (`scripts/release.sh` passes
  `-name kiwi`); without it the name is the module path, and the purl/bom-ref
  stay module-based either way.
- `components` contains every direct and transitive module, type `library`,
  each with `name` (module path), `version`, `purl`, and `bom-ref` (the purl).
  `replace` directives are followed, so the replacement module is reported.
  The artifact file itself is also listed as a `file` component carrying its
  SHA-256.
- `dependencies` contains one root entry whose `dependsOn` lists the
  `bom-ref` of every module, i.e. the root depends on all modules in the
  binary.
- `metadata.tools` records `kiwi-ci/release-tool@<version>`.

The graph comes from `debug/buildinfo.ReadFile` on the built binary. If build
info cannot be read, `release-tool` falls back to parsing the tab-separated
output of `go version -m <binary>` (including `=>` replacement lines); if
neither source yields a main module, the tool fails rather than emit an SBOM
with missing dependencies. Note that the SBOM is generated from the module
graph recorded in the binary, not from `go.sum`, so it reflects exactly what
was linked.

## 4. SLSA builder identity

Provenance is an in-toto statement with the SLSA provenance v1 predicate
(`https://slsa.dev/provenance/v1`) wrapped in a DSSE envelope and signed with
the release Ed25519 key. The standard predicate field
`predicate.runDetails.builder.id` is populated with the release-tool identity:

```
https://kiwi-ci.dev/builders/release-tool@<version>
```

The same value is mirrored in Kiwi's top-level `builder` extension field.
`release-tool -builder` can override it (useful for alternate release
infrastructure), and `kiwi verify --builder <id>` constrains verification to
exactly that identity; a wrong expected builder fails. The runner-driven
control-plane path is unchanged and keeps recording
`https://kiwi-ci.dev/runner/<runner-id>`.

## 5. Reproducibility and SOURCE_DATE_EPOCH

Artifact bytes are reproducible: builds use `-trimpath -buildvcs=false` and
the recorded `BuildDate` is pinned from `SOURCE_DATE_EPOCH`.

Flow in `scripts/release.sh` release mode:

1. If `BUILD_DATE` is set explicitly, it wins.
2. Else if `SOURCE_DATE_EPOCH` is set, it is converted to RFC3339 UTC.
3. Else `SOURCE_DATE_EPOCH` is derived from the tagged commit:
   `git log -1 --format=%ct <tag>`, then converted to RFC3339 UTC.
4. The RFC3339 value is baked into the binary as
   `internal/version.BuildDate` via `-ldflags`.

Snapshot mode honors an explicit `SOURCE_DATE_EPOCH`; without one it records
the current time. `make docker-build` converts `SOURCE_DATE_EPOCH` (default:
the `HEAD` commit date) to an RFC3339 `BUILD_DATE` on the host with a
BSD-then-GNU `date` fallback and passes it as a build arg, so the Dockerfile
never depends on the build-stage userland (BusyBox) understanding epoch
syntax. A direct `docker build` may pass `--build-arg BUILD_DATE=<RFC3339>`
itself; when only `SOURCE_DATE_EPOCH` is given, the Dockerfile converts it
with the Go toolchain in the image. `make` users can override the timestamp
with `DOCKER_BUILD_DATE`.

The distinction is deliberate:

- **Artifact bytes**: `BuildDate` is a build input, so pinning it via
  `SOURCE_DATE_EPOCH` makes `go build` output byte-identical and a rebuild
  reproduces the published digests.
- **Provenance and SBOM timestamps**: `predicate.runDetails.metadata.startedOn`
  / `finishedOn` and the SBOM `metadata.timestamp` always record the actual
  execution time (`time.Now`). They are evidence of when the release ran, not
  build inputs, and are intentionally *not* pinned: two reproducible artifact
  builds produce identical binaries but distinct, truthful provenance and SBOM
  timestamps.

Local check: `make repro-build` builds twice with fixed ldflags and compares
the binaries byte-for-byte.

## 6. Release signing key lifecycle

### 6.1 Key material and formats

- Algorithm: Ed25519.
- Private key: PKCS#8 PEM, supplied to `scripts/release.sh` through
  `KIWI_RELEASE_SIGNING_KEY` (either the PEM contents or a path to a file).
  It must never be committed; keep it in the release CI secret store, ideally
  backed by an HSM or a hardware token used by an offline signer.
- Public key: PKIX `PUBLIC KEY` PEM, published for verifiers and accepted by
  `kiwi verify --trusted-key`.
- The private key is **distinct** from the control plane's provenance key
  (`provenance.key`/`provenance.pub`): the release trust root must not live in
  server storage.

Generate a key pair:

```sh
openssl genpkey -algorithm ed25519 -out kiwi-release-signing-key.pem
chmod 600 kiwi-release-signing-key.pem
openssl pkey -in kiwi-release-signing-key.pem -pubout -out kiwi-release.pub
```

### 6.2 Publication and expected identifiers

Every release publishes the public key plus two identifiers so verifiers can
pin trust out of band:

- **KID** (expected `keyid` on the DSSE signature): the first 8 bytes of
  SHA-256 over the raw 32-byte Ed25519 public key, lowercase hex (16 chars).
  This is exactly what `release-tool` computes:

  ```sh
  openssl pkey -pubin -in kiwi-release.pub -outform DER | tail -c 32 \
    | shasum -a 256 | cut -c1-16
  ```

- **Fingerprint** (human comparison value): SHA-256 over the complete
  SubjectPublicKeyInfo DER of the public key:

  ```sh
  openssl pkey -pubin -in kiwi-release.pub -outform DER | shasum -a 256
  ```

Publish the public key, its fingerprint, and its KID in the GitHub release
notes and in the operations runbook, and record them in the repository's
trust-root documentation (see `SECURITY.md`). Rotate the published copy only
through the rotation procedure below.

### 6.3 Verification

The supported verification command is `kiwi verify` with the pinned release
key; `--trusted-key` replaces JWKS lookup with the exact published key:

```sh
kiwi verify --server https://kiwi.example \
  --trusted-key kiwi-release.pub \
  --builder https://kiwi-ci.dev/builders/release-tool@1.2.3 \
  --repository <repo> --commit <40-char-sha> --ref refs/tags/v1.2.3 \
  ARTIFACT_ID
```

`kiwi verify` prints the artifact SHA-256 and the signing `keyid`. Compare the
printed keyid with the published KID and the downloaded `kiwi-release.pub`
with the published fingerprint. A mismatch means the artifact was signed by a
different key; do not trust it.

### 6.4 Rotation

Rotate on a schedule (at least annually), on any suspicion of compromise, or
whenever the signer moves. Rotation is additive first:

1. Generate a new Ed25519 key pair (6.1) and store the private half in the
   release secret store.
2. Publish the new public key, fingerprint, and KID (6.2) in the release
   notes and trust-root documentation. Announce a rotation window and keep
   both keys verifiable during it.
3. Update the release pipeline secret (`KIWI_RELEASE_SIGNING_KEY`) to the new
   key; the next release is signed with the new KID. Releases are immutable:
   never re-sign old artifacts with the new key.
4. After the window closes, mark the old key as retired in the documentation.
   Old releases remain verifiable with the retired public key via
   `--trusted-key`; verifiers should pin both when validating historical
   releases.

### 6.5 Revocation

If a release key is compromised, is lost, or is suspected to be:

1. Remove it from the release secret store immediately; publish a revocation
   notice naming the KID and fingerprint, with the date and reason.
2. Mark the key revoked in the trust-root documentation and in the release
   notes of the next release; do not sign anything else with it.
3. Treat artifacts signed by the revoked key after the compromise window as
   untrusted. Where possible, rebuild and re-release from the same full commit
   SHA with a fresh key and a higher patch version; do not overwrite existing
   release assets.
4. Distribute the replacement key per 6.4 and require verifiers to update to
   the new pinned key.

### 6.6 Sigstore keyless signing (future)

The current root of trust is the static Ed25519 release key above. The DSSE
envelope, the in-toto statement, and the recorded builder identity are
designed so that Sigstore keyless signing (Fulcio certificates plus Rekor
transparency entries) can be layered on later without changing the statement
format: the predicate already carries the repository, ref, commit, and
builder identity, so a keyless signature can be added alongside or replace
the Ed25519 signature. Until that lands, `--trusted-key` verification against
the published release key is the supported path.

## Dependency licenses

Third-party licensing is gated by `scripts/license-check.sh`
(`make license-check`). The script scans the complete `go list -m -json all`
build list, skips the main module, follows `replace` directives, locates each
dependency's license file in the module cache (with a `vendor/` fallback),
and classifies it by canonical markers. The allowlist is Apache-2.0, MIT,
BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, PostgreSQL, Unlicense, and 0BSD;
composite identifiers such as `Apache-2.0/MIT` pass when every part is
listed. A dependency with a missing cache entry, no license file, or an
unrecognized or non-allowlisted license fails the gate with the module path
and the detected marker.

`make license-notice` regenerates `NOTICE` from the same scan (module,
version, and detected license per dependency). Commit the regenerated
`NOTICE` with any dependency change; the `license` lane in
`.woodpecker/linux-amd64.yml` regenerates it and fails on drift.
`./scripts/license-check.sh --selftest` exercises the classifier against
embedded fixtures without network access. The contributor-facing policy is
in [CONTRIBUTING.md](../CONTRIBUTING.md).

# The Kiwi Evidence Contract

This document is the public, neutral interface of Kiwi evidence: what the
signed evidence envelope contains, what each field is bound to, which schema
version carries it, what the execution-assurance classification ENFORCES, what
"exact replay" means precisely and — equally important — what Kiwi does not
guarantee in the presence of arbitrary executable code.

It is the assurance vocabulary referenced by [INVARIANTS.md](INVARIANTS.md)
and the replay section of the README. Code references name the stable symbol;
line numbers are a convenience for the tree at the time of writing.

The contract is **neutral**: a consumer verifies evidence by recomputing
digests and checking a signature against Kiwi's public key (JWKS or a pinned
key). No consumer needs to trust, run, or even understand Kiwi internals to
decide whether two pieces of evidence describe the same execution.

## 1. The evidence envelope

Every Kiwi evidence document is a DSSE envelope (`payloadType
application/vnd.in-toto+json`) whose payload is an in-toto v1 statement
(`_type https://in-toto.io/Statement/v1`) carrying exactly one subject and one
predicate:

| Document | Predicate type | Evidence block | Built by |
|---|---|---|---|
| Artifact provenance | `https://slsa.dev/provenance/v1` | top-level statement fields + SLSA `predicate` | `provenance.ArtifactStatement`, `internal/provenance/provenance.go` |
| Final execution attestation | `kiwi-ci/execution-attestation/v1` | the `attestation` block | `provenance.ExecutionAttestationStatement`, `internal/provenance/attestation.go` |

The subject binds the signed bytes: for an artifact it is the artifact name
and its SHA-256; for an execution attestation it is the canonical attempt
identity (`<jobID>:<leaseGeneration>`, `model.AttemptID`) and the canonical
digest of the attestation block (`provenance.ExecutionAttestationDigest`), so
a verifier can recompute the subject digest from the returned statement and
detect any field tampering independently of the signature.

The signature is Ed25519 over the DSSE pre-authentication encoding, using the
control plane's persistent provenance key; public keys are served through
`GET /api/v1/oidc/jwks` or pinned locally (`kiwi verify --trusted-key`).

## 2. Evidence envelope field map

The table maps every element of the neutral evidence contract to its
implemented carrier. "Attestation" is the `attestation` block of an execution
attestation; "artifact" is an artifact-provenance statement. All digests are
lowercase hex SHA-256 unless stated otherwise.

### Execution identity

| Contract element | Carrier | Notes |
|---|---|---|
| Repository identity | artifact `predicate.buildDefinition.externalParameters.repository` | `RepoID` (immutable canonical identity), not a display URL |
| Ref and commit | `externalParameters.ref`, `externalParameters.commit` | the recorded ref/SHA of the run |
| Run / job identity | artifact `predicate.runDetails.metadata.invocationId` (`<runID>/<attemptID>`); attestation `runId`, `jobId`, `jobKey` | `jobKey` is the run-scoped logical node key |
| Attempt identity | `attemptId` (`<jobID>:<leaseGeneration>`), `model.AttemptID` | the exact attempt, not "some run of this job" |
| Graph fingerprint | attestation `graphFingerprint` | canonical SHA-256 over the run's sorted (job key, needs) derived from the durable jobs at emission time (`provenance.GraphFingerprint`); changes when a node is added, removed or rewired |
| Graph causality | `model.Job.CreatedByNode`, `CreatedByMutation`, `ExternalContext`; `graph.mutation_*` event payload (`mutation`, `external_context_attached`, bounded `external_context`) | identifies which mutation created a generated node and carries the caller's bounded opaque correlation context; never interpreted |

### Inputs and computation identity

| Contract element | Carrier | Notes |
|---|---|---|
| Admitted computation | artifact + attestation `capsuleDigest` | canonical digest of the persisted `CompiledJobPayload` (`provenance.CapsuleDigest`) |
| Effective execution | artifact + attestation `executionCapsuleDigest` | canonical digest of the materialized `EffectiveExecution` (trust/resource/network/sandbox overlays), `execution.MaterializedCapsuleDigest` |
| Effective policy | attestation `policyDigest` | canonical digest of the payload's effective policy (`provenance.EffectivePolicyDigest`); empty when no policy is bound |
| Declared input files | artifact `materials[]` (`path`, `sha256`) | the statement shape reserves the field for callers that hash a material set; Kiwi's control plane does not populate it today, and the canonical computation identity remains the capsule digests |
| Pipeline / job digests | artifact `pipelineDigest`; payload `PipelineDigest`, `JobDigest` | deterministic compile identity (`pipeline.PipelineDigest`) |
| Compiler version | artifact `compilerVersion` | the compile-time binary version recorded in the payload |

### Outputs and artifact evidence

| Contract element | Carrier | Notes |
|---|---|---|
| Artifact bytes | subject `name` + `sha256`; attestation `artifacts[]` (`name`, `sha256`, `size`) | the subject digest is what the signature binds |
| Artifact sidecars | artifact record `provenance_sha256`, `sbom_*`, `sigstore_*`; bound into `evidenceRootSha256` | per-artifact references, digest-only |
| Evidence graph root | attestation `evidenceRootSha256` | canonical root over the full artifact-side graph (artifacts + sidecars + suite digests + snapshots), `provenance.ExecutionEvidenceRoot` |
| Test evidence | attestation `testReports[]` (`name`, `suiteDigest`, `generation`) | canonical digest over the ordered test cases (`provenance.TestReportSuiteDigest`); raw messages are never embedded |
| Terminal outcome | attestation `status`, `startedAt`, `finishedAt`, `completionResultDigest` | the v2 completion identity digest binds status/error/outputs/runtime by digest only (`storage.CompletionResultDigestV2`); raw output and error values are never embedded |
| Publication time | artifact `artifactPublishedAt` | publication time is never conflated with build completion (`finishedOn` is only a real terminal timestamp) |

### Runner, versions and assurance

| Contract element | Carrier | Notes |
|---|---|---|
| Runner identity | `runnerIdentity`, `predicate.runDetails.builder.id` | the lease-authorized runner that produced the artifact, or the durable completing runner of the attempt (`Job.AttemptRunnerID`); a client cannot declare it |
| Observed runtime | attestation `observedRuntime` (`os`, `arch`, `runtimeName`, `runtimeVersion`, `mainImage(+Digest)`, `serviceImages(+Digests)`, `components`) | executor-captured, omission over fabrication; components are server-owned |
| Trust | artifact `externalParameters.trusted` | the persisted trust state of the job |
| Execution-assurance level | attestation `executionAssurance` (`level`, `name`); artifact `executionAssurance` | see §4; the name is validated to match the level |
| External-effects class | attestation `externalEffects`; artifact `externalEffects` | `pure`, `kiwi_mediated` or `opaque_external`; see §4 |
| Execution semantics | `executionSemantics` (artifact + attestation) | `model.ExecutionSemanticsVersion` read from durable stamps; empty for records predating stamping |
| Runner transport protocol | not part of the signed evidence (it is a lease-admission gate) | `model.RunnerProtocolVersion`; see §3 |
| Dependency resolution | job `needs`/`needsOutputs` and the dependency-status records | `model.Job.Needs`, `NeedsOutputs`; involved in the graph fingerprint |
| Replay lineage | snapshots `id`, `phase`, `sha256`, `generation`; `leaseGeneration`, `attempts` | `pre_job` snapshot = materialized input state, `post_job` = outcome material; `model.SnapshotRecord` |
| Event-ledger frontier | attestation `eventFrontier` | latest commit-ordered event seq at emission time (`storage.ExecutionEventCursorStore.LatestExecutionEventSeq`); omitted when the store does not expose the cursor contract |
| Timestamps | `startedAt`, `finishedAt`, `artifactPublishedAt`, event `createdAt`, `observedRuntime.capturedAt` | all UTC; the attestation is built from durable terminal records |

### Signature and digest versions

| Contract element | Carrier |
|---|---|
| Canonical attestation digest | `provenance.ExecutionAttestationDigest`, tagged `kiwi-ci/execution-attestation-digest/v1` |
| Evidence-root encoding | `provenance.ExecutionEvidenceRoot`, tagged `kiwi-ci/execution-evidence-root/v1` |
| Capsule encodings | `kiwi-ci/capsule/v1` (compiled payload), `kiwi-ci/execution-capsule/v1` (effective execution) |
| Policy and graph encodings | `kiwi-ci/effective-policy-digest/v1`, `kiwi-ci/graph-fingerprint/v1` |
| Signature | DSSE Ed25519, key id + signature; `kiwi verify` checks the signature, then the statement's internal consistency (`provenance.VerifyExecutionAttestation`) |

## 3. Version dimensions

Six independent version dimensions exist. They are deliberately NOT collapsed
into one version: two builds can speak the same wire while interpreting the
same durable state differently, and vice versa.

| Dimension | Current value | Carrier | Bump rule |
|---|---|---|---|
| Runner transport protocol | `model.RunnerProtocolVersion = 2` | runner registration and `/next` negotiation; a runner below `JobRequiresProtocol` is refused with 409 `RUNNER_PROTOCOL_UNSUPPORTED` | any wire-shape change the negotiation must gate |
| Execution semantics | `"kiwi.execution.v2"` (`model.ExecutionSemanticsVersion`) | `Run.ExecutionSemantics`, `Job.ExecutionSemantics`, snapshot `execution_semantics`, artifact + attestation `executionSemantics` | any change to how the scheduler/runner/executor INTERPRET durable state, not additive fields the old semantics safely ignore |
| Event schema | `model.ExecutionEvent.SchemaVersion` (1) | PostgreSQL `execution_events` rows and the fs event journal | any change to event payload semantics |
| Snapshot schema | `snapshot.ManifestVersion = 1` | `model.SnapshotRecord.Version` | any change to the workspace manifest encoding |
| Graph / pipeline schema | pipeline `Spec.Version` (1) and `model.CompiledJobPayload.SchemaVersion` (1) | persisted pipelines, compiled payloads, fragment wire bodies | any change to pipeline or compiled-job semantics |
| Evidence schema | execution attestation `schemaVersion = 4`; artifact statements use in-toto v1 + SLSA v1 as-is | the signed blocks themselves | any field addition/change to the attestation block (the schema version is inside the digest preimage) |

Evidence-schema history: v2 added the completion identity and the evidence
root; v3 added execution semantics; **v4 added `executionAssurance`
(level + name), `externalEffects`, `policyDigest`, `eventFrontier` and
`graphFingerprint`.** An envelope signed under an earlier schema predates the
later fields and does not verify under the current digest: a v3 attestation is
refused with an explicit unsupported-schema error, not silently reinterpreted.
Because the schema version is part of the digest preimage, "same evidence,
older schema" is by construction a different statement.

## 4. Execution assurance and effect classes

`model.ExecutionAssurance` is a closed ladder stating what the named controls
are ENFORCED to do at execution time. It is a statement about Kiwi-enforced
controls, never about what an arbitrary command does inside them.

| Level | Name | Enforces |
|---|---|---|
| 0 | `uncontrolled` | no enforced execution boundary |
| 1 | `isolated_filesystem` | a container/Tart runtime sandbox, or an OS-level workspace quota installed before the workspace is populated |
| 2 | `no_ambient_credentials` | level 1 **plus** an explicitly empty (non-nil, deny-all) effective secret allowlist and no inherited host environment |
| 3 | `network_denied` | level 2 **plus** effective network none |
| 4 | `kiwi_mediated_authority` | level 2 **plus** every declared external effect (deployments, OIDC, artifacts, downloads) covered by a Kiwi capability. The network MAY be allowed: unauthenticated egress is then explicitly not constrained |
| 5 | `hermetic` | level 4 **plus** network none **plus** every declared image (container image, service images, Tart VM reference) digest-pinned |

Levels 3 and 4 are siblings above level 2: level 3 is the network-denied
branch, level 4 the mediated-authority branch (a level-4 job may hold allowed
egress). Level 5 requires both. The pure derivation
(`(*execution.EffectiveExecution).Assurance` / `.EffectsClass`) reports the
strongest satisfied control set under that rule, deterministically and
totally, from the persisted job + compiled payload + trust/policy records —
never from configuration that is not in the durable evidence.

`model.ExternalEffectsClass` classifies where a job's external effects come
from:

- **`pure`** — network none, explicitly empty secret allowlist, no OIDC
  declaration, no deployment phases. Only Kiwi-collected outputs remain.
- **`kiwi_mediated`** — not pure, no ambient credentials, and every declared
  external effect flows through a Kiwi capability. Unauthenticated egress
  (when the network is allowed) and arbitrary command side effects reachable
  with the granted authority are outside mediation and are not covered by
  replay/speculation guarantees.
- **`opaque_external`** — ambient credentials are possible: the effective
  secret allowlist is unrestricted (nil policy) or non-empty, the host
  environment is inherited, or the job runs on the native runtime with host
  authority (host filesystem, credential files, sockets). Such a job is
  classified honestly as not attributable to declared Kiwi capabilities.

Decision table (the derivation's behavior, pinned by
`internal/execution/assurance_test.go`):

| Execution shape | Effective secret allowlist | Network | Declared effects | Images | Level | Class |
|---|---|---|---|---|---|---|
| untrusted container | empty (deny-all) | none | none | pinned | 5 `hermetic` | `pure` |
| trusted container | unrestricted (trusted default) | allowed | — | — | 1 `isolated_filesystem` | `opaque_external` |
| trusted container | empty | allowed | deployment, granted | — | 4 `kiwi_mediated_authority` | `kiwi_mediated` |
| container | empty | none | deployment declared but NOT covered by the effective capability | — | 3 `network_denied` | `kiwi_mediated` |
| container | empty | none | none | unpinned | 4 `kiwi_mediated_authority` | `pure` |
| native (any) | — | — | — | — | ≤ 1 (0 without a workspace quota) | `opaque_external` |
| any | non-empty allowlist | — | — | — | ≤ 1 | `opaque_external` |

A record whose execution cannot be re-materialized (unparseable pipeline, a
payload that does not bind) is classified conservatively as
`uncontrolled` / `opaque_external`; unproven executions are never upgraded.
The event stream carries the same honesty: `graph.mutation_*` events record
the mutation identity and whether a bounded opaque external context was
attached (the context itself is caller-supplied correlation data, never
secrets, and is never interpreted).

## 5. Exact replay versus bit-reproducible execution

**Exact replay means exactly this**: the re-execution uses the SAME recorded
graph, the SAME recorded inputs and dependency resolution, the SAME recorded
policy semantics, the SAME execution-engine semantics, and the SAME recorded
declared environment.

Concretely (implemented in `internal/app/replay.go` and enforced by
`pipeline.VerifyCompiledJobBinding`):

- the recorded compiled job/payload is fetched from the control plane, its
  digests are re-verified against the recorded pipeline, and the recorded job
  is executed — never the local pipeline file;
- the workspace starts from the recorded `pre_job` snapshot when one exists
  (the materialized input state), not from a fresh checkout;
- the recorded network, sandbox and resource policy are re-applied; an
  attempt is addressed by `<jobID>:<leaseGeneration>` and falls back to the
  newest generation deterministically;
- a record stamped with a different non-empty `executionSemantics` is refused:
  a historical execution reproduced by a different interpreter is not the
  same execution;
- replay never schedules child jobs, submits runs, enqueues outbox work or
  uploads fragments; step-declared effects (deployment phases, secrets, OIDC)
  are refused unless the operator explicitly opts in
  (`--allow-external-effects`), and the residual undeclared-effect risk is
  always warned about.

**Bit-reproducible execution is NOT claimed.** Exact replay reproduces WHAT
is executed, not the observable result. Clocks, external services and their
state, network peers, hardware, kernel/runtime versions, parallelism and any
undeclared behavior inside the step script stay outside Kiwi's view: a re-run
can legitimately produce different bytes, different test outcomes and
different artifacts. Evidence binds the identity of the execution; it does
not prove output determinism, and no Kiwi signature should be read as such.

## 6. Evidence profiles and the redaction rule

All evidence is one canonical object; profiles are projections of it, ordered
by how much of the durable record they carry. They exist as an efficiency
roadmap: consumers should be able to request less evidence without inventing
a weaker trust story.

| Profile | Contents | Status |
|---|---|---|
| **minimal** | execution identity (repo/ref/commit, run/job/attempt), capsule digests, subject artifact digest, signature | available: the identities every statement already carries |
| **standard** | minimal + assurance level/name and effects class, policy digest, evidence root, completion digest, observed runtime, graph fingerprint, event frontier, snapshot/report/suite references | implemented: the current execution attestation block (schema v4) |
| **forensic** | standard + full event-ledger timeline reconstruction, artifact sidecar documents (provenance/SBOM/sigstore), report case digests, material hashes, retention watermarks | roadmap: the streams exist (`/api/v1/events`, artifact sidecar refs, suite digests) but are not yet materialized into one envelope |

**Redaction rule — projection → canonicalization → signature.** A profile is
a PROJECTION of durable evidence chosen BEFORE canonicalization. The
projected fields are canonicalized, hashed into the subject digest and signed;
what the signature covers is exactly what the profile declares. There is no
post-signature redaction: a statement with fields removed or altered is a
different statement and no longer verifies against the original subject
digest. A consumer that requires an unprojected field must fetch a richer
profile, not strip one.

**Non-goal: secret values are never recorded.** Evidence records references,
versions and digests — `secret.issued` carries the secret NAME and lease
generation only; OIDC issuance carries audience/kid/claim key names; sealed
envelopes, tokens, plaintext claims and host credentials never appear in any
event, attestation or provenance document. Step outputs are bound by the
completion result digest, never embedded; artifact contents are bound by
digest, never copied into evidence.

## 7. Interoperability roadmap (future work)

The neutral envelope is deliberately built on in-toto v1 + DSSE so standard
tooling can consume it; the following are explicitly FUTURE work, not current
claims:

- **SLSA**: artifact statements already use the SLSA v1 provenance predicate
  and a builder identity; a SLSA-level claim (build levels, hermeticity
  attestation) is not made.
- **in-toto layouts/attestation bundles**: single-statement DSSE envelopes are
  emitted today; multi-statement bundles and layout verification are future.
- **SBOM**: CycloneDX SBOM sidecars are published and referenced by digest;
  in-envelope SBOM predicates are future.
- **Sigstore**: sidecar references are recorded (`sigstore_path`,
  `sigstore_sha256`); transparency-log signing, Rekor inclusion proofs and
  keyless Fulcio identities are future. The current trust root is the
  control-plane Ed25519 key distributed via JWKS.

## 8. What Kiwi does not guarantee

Kiwi executes arbitrary commands; the evidence contract is precise about the
boundary of that execution:

- **Arbitrary command side effects are outside Kiwi mediation.** A step is a
  process. Whatever it does with the authority it has — network calls when the
  network is allowed, writes to surfaces the policy permits, calls to
  unauthenticated third parties — is not mediated by Kiwi and not covered by
  replay/speculation guarantees. Level 4 documents this explicitly:
  unauthenticated egress is not constrained when the network is allowed.
- **`opaque_external` jobs are classified honestly.** When credentials can
  reach a job (unrestricted/non-empty secret policy, inherited host
  environment, or native host authority) Kiwi says so; it does not claim that
  such effects are attributable to declared Kiwi capabilities.
- **Replay and speculation guarantees apply to Kiwi-mediated effects and
  declared surfaces only.** Exact replay cannot add child jobs, runs, outbox
  work or fragment uploads, and it refuses declared external effects unless
  explicitly authorized; it cannot promise that a step which declares nothing
  performs nothing outside the recorded policy.
- **Assurance levels are enforcement statements, not safety verdicts.** A
  hermetic attempt says every image was pinned and the network was off; it
  does not say the code was trustworthy, bug-free, or that its outputs are
  correct. `uncontrolled`/`opaque_external` are honest classifications of
  weaker enforcement, not failures to hide.
- **Evidence is not a proof of correctness.** Digests and signatures bind
  identity and integrity of the recorded surfaces; they say nothing about the
  semantic correctness of what the pipeline computed.

## 9. Verifying evidence

```sh
# Verify a served execution attestation against the server's public key.
kiwi verify --server https://kiwi.example.com --attestation <job-id>
# Verify a local envelope against a pinned key (offline).
kiwi verify --trusted-key provenance.pub --attestation-file attestation.json
# Verify artifact provenance by artifact ID and constrain the execution semantics.
kiwi verify --server https://kiwi.example.com --execution-semantics kiwi.execution.v2 <artifact-id>
```

`kiwi verify` prints the verified identity, the execution semantics and the
assurance classification (`execution assurance: level N (name)`, `external
effects: class`). Verification recomputes the canonical digest, refuses a
block whose fields disagree with its own subject digest, refuses an unknown
assurance level, a name that does not match its level, or an unknown effects
class, and never prints raw command output.

## See also

- [INVARIANTS.md](INVARIANTS.md) — the core invariant-to-code mapping.
- [graph-mutations.md](graph-mutations.md) — the constrained mutation algebra
  behind `graph.mutation_*` events and the causality stamp.
- [security-model.md](security-model.md) — the trust boundaries the assurance
  levels summarize.

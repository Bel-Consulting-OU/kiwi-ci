# Kiwi compatibility contract

Generated from `internal/version.ContractVersions` as the produces/consumes compatibility map.
Do not hand-edit compatibility.md — run `KIWI_GEN=1 go test ./internal/version -run TestGenerateCompatibilityDocs`.
The machine-readable twin is [`compatibility.json`](compatibility.json).

## Produces / consumes

| Contract | Produces | Consumes |
|---|---|---|
| `attestation_digest` | `kiwi-ci/execution-attestation-digest/v1` | `kiwi-ci/execution-attestation-digest/v1` |
| `compiled_job_schema` | `1` | `1` |
| `completion_result_hash` | `3` | `1`, `2`, `3` |
| `event_schema` | `1` | `1` |
| `evidence_root_digest` | `kiwi-ci/execution-evidence-root/v1` | `kiwi-ci/execution-evidence-root/v1` |
| `evidence_schema` | `6` | `4`, `5`, `6` |
| `execution_semantics` | `kiwi.execution.v3` | `kiwi.execution.v3` |
| `observed_runtime_digest_v1` | `kiwi-ci/observed-runtime/v1` | `kiwi-ci/observed-runtime/v1` |
| `observed_runtime_digest_v2` | `kiwi-ci/observed-runtime/v2` | `kiwi-ci/observed-runtime/v2` |
| `pipeline_schema` | `1` | `1` |
| `runner_api_protocol` | `3` | `3` |
| `runner_wire_semantic` | `2` | `2` |
| `snapshot_schema` | `1` | `1` |

`produces` is the encoding this build writes under the current identifier.
`consumes` lists every encoding this build still reads, oldest first; the
current value is always the last entry. An algorithm under an existing
identifier is frozen — a new encoding gets a new version (see
`testdata/compat/` and `testdata/contracts/` for the producer-byte corpora).

## Persisted-state schema floor

| Field | Value |
|---|---|
| `storage_schema` | `1` |
| `minimum_reader` | `1` |
| `minimum_writer` | `1` |

The floor is append-only: a writer never emits a schema an older reader
cannot decode, and this build reads state written at the floor. PostgreSQL
migrations are separately append-only (see `docs/upgrades.md`).

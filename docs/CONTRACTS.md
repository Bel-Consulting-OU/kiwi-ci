# Kiwi contract versions

Generated from `internal/version.ContractVersions` as the contract-version table.
Do not hand-edit `docs/CONTRACTS.md` — run `KIWI_GEN=1 go test ./internal/version -run TestGenerateContractVersionsDoc`.

| Contract | Version / tag |
|---|---|
| `attestation_digest` | `kiwi-ci/execution-attestation-digest/v1` |
| `compiled_job_schema` | `1` |
| `completion_result_hash` | `3` |
| `event_schema` | `1` |
| `evidence_root_digest` | `kiwi-ci/execution-evidence-root/v1` |
| `evidence_schema` | `6` |
| `execution_semantics` | `kiwi.execution.v3` |
| `observed_runtime_digest_v1` | `kiwi-ci/observed-runtime/v1` |
| `observed_runtime_digest_v2` | `kiwi-ci/observed-runtime/v2` |
| `pipeline_schema` | `1` |
| `runner_api_protocol` | `3` |
| `runner_wire_semantic` | `2` |
| `snapshot_schema` | `1` |

Algorithms under an existing identifier are frozen. Introduce a new
version instead of changing an old encoding (see the completion-hash v2/v3
split and the historical compatibility corpus in `testdata/contracts/`).

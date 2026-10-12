package version

import (
	"strconv"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ContractVersions is the canonical, append-only registry of every
// cryptographic or durable encoding Kiwi persists or speaks. An algorithm
// under an existing identifier MUST NOT change; introduce a new version
// instead (see storage.CompletionResultDigestV2/V3). Docs and CI generate
// or check public tables against this map.
//
// This file is the compatibility firewall: if a change here would rewrite an
// existing value, stop and add a new version.
//
// Every row is bound to the REAL producer constant — no copied numbers:
//
//   - runner API / pipeline / storage schema rows reference this package;
//   - runner wire-semantic, execution semantics, compiled-job and event
//     schema rows reference model (the producer stamps those constants);
//   - snapshot schema references snapshot.ManifestVersion;
//   - completion-result hash and observed-runtime digest tags reference
//     storage.
//
// The three provenance-owned rows (evidence_schema, attestation_digest,
// evidence_root_digest) cannot be referenced at compile time because
// provenance imports this package. They are the only literals here, and
// TestContractVersionsMatchProducers proves each equals the producer's
// exported getter, so a producer bump without a registry update fails CI.
var ContractVersions = map[string]string{
	"runner_api_protocol":        ProtocolVersion,
	"runner_wire_semantic":       strconv.Itoa(model.RunnerProtocolVersion),
	"execution_semantics":        model.ExecutionSemanticsVersion,
	"pipeline_schema":            PipelineSchemaVersion,
	"compiled_job_schema":        strconv.Itoa(model.CompiledJobPayloadSchemaVersion),
	"event_schema":               strconv.Itoa(model.ExecutionEventSchemaVersion),
	"snapshot_schema":            strconv.Itoa(snapshot.ManifestVersion),
	"evidence_schema":            "6",
	"completion_result_hash":     strconv.Itoa(storage.CurrentCompletionResultHashVersion),
	"observed_runtime_digest_v1": storage.ObservedRuntimeDigestV1Version,
	"observed_runtime_digest_v2": storage.ObservedRuntimeDigestV2Version,
	"attestation_digest":         "kiwi-ci/execution-attestation-digest/v1",
	"evidence_root_digest":       "kiwi-ci/execution-evidence-root/v1",
}

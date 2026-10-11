package version

// ContractVersions is the canonical, append-only registry of every
// cryptographic or durable encoding Kiwi persists or speaks. An algorithm
// under an existing identifier MUST NOT change; introduce a new version
// instead (see storage.CompletionResultDigestV2/V3). Docs and CI generate
// or check public tables against this map.
//
// This file is the compatibility firewall: if a change here would rewrite an
// existing value, stop and add a new version.
var ContractVersions = map[string]string{
	"runner_api_protocol":        ProtocolVersion,
	"runner_wire_semantic":       "2",
	"execution_semantics":        "v2",
	"pipeline_schema":            "1",
	"compiled_job_schema":        "1",
	"event_schema":               "1",
	"snapshot_schema":            "1",
	"evidence_schema":            "6",
	"completion_result_hash":     "3",
	"observed_runtime_digest_v1": "frozen",
	"observed_runtime_digest_v2": "current",
	"attestation_digest":         "1",
	"evidence_root_digest":       "1",
}

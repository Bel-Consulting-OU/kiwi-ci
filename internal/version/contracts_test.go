package version

import "testing"

// TestContractVersionsFrozenKeys pins the registry keys so a rename is a
// deliberate, reviewable act.
func TestContractVersionsFrozenKeys(t *testing.T) {
	want := []string{
		"runner_api_protocol", "runner_wire_semantic", "execution_semantics",
		"pipeline_schema", "compiled_job_schema", "event_schema",
		"snapshot_schema", "evidence_schema", "completion_result_hash",
		"observed_runtime_digest_v1", "observed_runtime_digest_v2",
		"attestation_digest", "evidence_root_digest",
	}
	for _, k := range want {
		if ContractVersions[k] == "" {
			t.Errorf("missing contract version key %q", k)
		}
	}
	if ContractVersions["completion_result_hash"] != "3" {
		t.Fatalf("completion_result_hash = %q, want 3 (v3 binds Control)", ContractVersions["completion_result_hash"])
	}
	if ContractVersions["evidence_schema"] != "6" {
		t.Fatalf("evidence_schema = %q, want 6", ContractVersions["evidence_schema"])
	}
}

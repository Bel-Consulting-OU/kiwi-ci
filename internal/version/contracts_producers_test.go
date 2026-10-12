package version_test

import (
	"strconv"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

// TestContractVersionsMatchProducers proves every ContractVersions row equals
// the REAL implementation constant that produces the corresponding durable
// bytes — the registry must never drift from the encodings it documents.
//
// The provenance-owned rows are checked against the package's exported
// getters (a compile-time reference from version would import-cycle because
// provenance imports version). Everything else is also bound at compile time
// in contracts.go; this test is the single place that walks the whole map so
// a new row without a producer pin is caught immediately.
func TestContractVersionsMatchProducers(t *testing.T) {
	want := map[string]string{
		"runner_api_protocol":        version.ProtocolVersion,
		"runner_wire_semantic":       strconv.Itoa(model.RunnerProtocolVersion),
		"execution_semantics":        model.ExecutionSemanticsVersion,
		"pipeline_schema":            version.PipelineSchemaVersion,
		"compiled_job_schema":        strconv.Itoa(model.CompiledJobPayloadSchemaVersion),
		"event_schema":               strconv.Itoa(model.ExecutionEventSchemaVersion),
		"snapshot_schema":            strconv.Itoa(snapshot.ManifestVersion),
		"evidence_schema":            strconv.Itoa(provenance.ExecutionAttestationSchemaVersion()),
		"completion_result_hash":     strconv.Itoa(storage.CurrentCompletionResultHashVersion),
		"observed_runtime_digest_v1": storage.ObservedRuntimeDigestV1Version,
		"observed_runtime_digest_v2": storage.ObservedRuntimeDigestV2Version,
		"attestation_digest":         provenance.ExecutionAttestationDigestVersion(),
		"evidence_root_digest":       provenance.ExecutionEvidenceRootVersion(),
	}
	if len(version.ContractVersions) != len(want) {
		t.Fatalf("ContractVersions has %d rows, want %d (add new rows to this test with their producer)", len(version.ContractVersions), len(want))
	}
	for key, producer := range want {
		got, ok := version.ContractVersions[key]
		if !ok {
			t.Errorf("missing contract version key %q", key)
			continue
		}
		if got != producer {
			t.Errorf("ContractVersions[%q] = %q, want producer value %q", key, got, producer)
		}
	}
	for key := range version.ContractVersions {
		if _, ok := want[key]; !ok {
			t.Errorf("ContractVersions has unbound key %q (no producer pinned in this test)", key)
		}
	}

	// Completeness guards on the producer side itself: the getters this test
	// pins must not be empty or zero, so a future refactor cannot silently
	// "match" the registry with a blank producer.
	if provenance.ExecutionAttestationSchemaVersion() <= 0 {
		t.Fatal("provenance.ExecutionAttestationSchemaVersion() must be positive")
	}
	if storage.CurrentCompletionResultHashVersion != storage.CompletionResultHashVersionV3 {
		t.Fatalf("CurrentCompletionResultHashVersion = %d, want CompletionResultHashVersionV3 (%d)", storage.CurrentCompletionResultHashVersion, storage.CompletionResultHashVersionV3)
	}
	if storage.ObservedRuntimeDigestV1Version != "kiwi-ci/observed-runtime/v1" {
		t.Fatalf("ObservedRuntimeDigestV1Version = %q — the FROZEN historical tag must not change", storage.ObservedRuntimeDigestV1Version)
	}
	if storage.ObservedRuntimeDigestV2Version != "kiwi-ci/observed-runtime/v2" {
		t.Fatalf("ObservedRuntimeDigestV2Version = %q — the current tag must not change without a digest bump", storage.ObservedRuntimeDigestV2Version)
	}
}

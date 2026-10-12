package provenance

// Contract-corpus generator. The fixtures under testdata/contracts/ are
// IMMUTABLE historical compatibility artifacts: this generator exists so the
// corpus can be reproduced from a known-good build when the audit requires a
// refresh, never to overwrite frozen bytes on a normal test run.
//
//	KIWI_GEN_CONTRACT_FIXTURES=1 go test ./internal/provenance -run TestGenerateContractFixtures -count=1
//
// Regenerating WITHOUT also updating the frozen golden constants in
// internal/storage/contract_corpus_test.go and internal/provenance/
// contract_corpus_test.go is expected to FAIL those tests — that is the
// firewall.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func contractFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "contracts")
}

// fixedContractObservedRuntime is the frozen observed-runtime evidence used
// by the completion-receipt corpus. It deliberately carries NO Control
// receipt: it is the N-2 producer shape observed-runtime/v1 binds.
func fixedContractObservedRuntime() *model.ObservedRuntime {
	return &model.ObservedRuntime{
		OS:              "linux",
		Arch:            "amd64",
		RuntimeName:     "docker",
		RuntimeVersion:  "25.0.3",
		MainImage:       "alpine:3.20",
		MainImageDigest: "sha256:" + strings.Repeat("c", 64),
		ServiceImages: map[string]string{
			"db": "postgres:16",
		},
		ServiceImageDigests: map[string]string{
			"db": "sha256:" + strings.Repeat("d", 64),
		},
		Components: map[string]string{
			"libfoo": strings.Repeat("e", 64),
		},
		CapturedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

type contractCompletionFixture struct {
	Comment     string                  `json:"comment"`
	HashVersion int                     `json:"hash_version"`
	Receipt     model.CompletionReceipt `json:"receipt"`
	Completion  struct {
		Status          string                 `json:"status"`
		Error           string                 `json:"error,omitempty"`
		Outputs         map[string]string      `json:"outputs,omitempty"`
		ObservedRuntime *model.ObservedRuntime `json:"observed_runtime,omitempty"`
	} `json:"completion"`
	Golden struct {
		ResultHash            string `json:"result_hash"`
		ObservedRuntimeDigest string `json:"observed_runtime_digest,omitempty"`
		ObservedRuntimeTag    string `json:"observed_runtime_tag,omitempty"`
	} `json:"golden"`
}

func TestGenerateContractFixtures(t *testing.T) {
	if os.Getenv("KIWI_GEN_CONTRACT_FIXTURES") != "1" {
		t.Skip("set KIWI_GEN_CONTRACT_FIXTURES=1 to regenerate testdata/contracts (fixtures are otherwise immutable)")
	}
	dir := contractFixtureDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	observed := fixedContractObservedRuntime()
	outputs := map[string]string{
		"artifact": "sha256:" + strings.Repeat("1", 64),
		"url":      "https://example.invalid/dist/app",
	}
	status := model.StatusSuccess
	errMsg := ""

	// --- completion_receipt_v1.json: legacy status/error/outputs hash ---
	var v1 contractCompletionFixture
	v1.Comment = "FROZEN legacy (hash v1) completion receipt contract fixture. Immutable historical compatibility corpus; do not regenerate without updating the golden constants in internal/storage/contract_corpus_test.go."
	v1.HashVersion = storage.CompletionResultHashVersionLegacy
	v1.Completion.Status = string(status)
	v1.Completion.Error = errMsg
	v1.Completion.Outputs = outputs
	v1.Completion.ObservedRuntime = nil
	v1.Receipt = model.CompletionReceipt{
		JobID:             "contract-fixture-job-v1",
		Generation:        1,
		RunnerID:          "contract-fixture-runner",
		ResultHash:        storage.CompletionResultDigestV1(status, errMsg, outputs),
		ResultHashVersion: storage.CompletionResultHashVersionLegacy,
	}
	v1.Golden.ResultHash = v1.Receipt.ResultHash
	writeContractFixture(t, filepath.Join(dir, "completion_receipt_v1.json"), v1)

	// --- completion_receipt_v2.json: frozen v2, observed-runtime/v1, no Control ---
	var v2 contractCompletionFixture
	v2.Comment = "FROZEN v2 completion receipt contract fixture (nested observed-runtime/v1, no Control). Immutable historical compatibility corpus; do not regenerate without updating the golden constants in internal/storage/contract_corpus_test.go."
	v2.HashVersion = storage.CompletionResultHashVersionV2
	v2.Completion.Status = string(status)
	v2.Completion.Error = errMsg
	v2.Completion.Outputs = outputs
	v2.Completion.ObservedRuntime = observed
	v2.Receipt = model.CompletionReceipt{
		JobID:             "contract-fixture-job-v2",
		Generation:        1,
		RunnerID:          "contract-fixture-runner",
		ResultHash:        storage.CompletionResultDigestV2(status, errMsg, outputs, observed),
		ResultHashVersion: storage.CompletionResultHashVersionV2,
	}
	v2.Golden.ResultHash = v2.Receipt.ResultHash
	v2.Golden.ObservedRuntimeDigest = storage.ObservedRuntimeDigestV1(observed)
	v2.Golden.ObservedRuntimeTag = storage.ObservedRuntimeDigestV1Version
	writeContractFixture(t, filepath.Join(dir, "completion_receipt_v2.json"), v2)

	// --- observed_runtime_v1.json: the bare ObservedRuntime wire bytes (no Control) ---
	writeContractFixture(t, filepath.Join(dir, "observed_runtime_v1.json"), observed)

	// --- attestation_v4/v5/v6.json: canonical statement bytes ---
	v4 := contractAttestationV4(t)
	v5 := contractAttestationV5(t)
	v6 := contractAttestationV6(t, observed, storage.CompletionResultDigestV2(status, errMsg, outputs, observed))
	for _, pair := range []struct {
		name string
		st   Statement
	}{
		{"attestation_v4.json", v4},
		{"attestation_v5.json", v5},
		{"attestation_v6.json", v6},
	} {
		raw, err := json.Marshal(pair.st)
		if err != nil {
			t.Fatalf("marshal %s: %v", pair.name, err)
		}
		path := filepath.Join(dir, pair.name)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		t.Logf("%s subject=%s statement_sha256=%s", pair.name, pair.st.Subject[0].Digest["sha256"], hex.EncodeToString(sum[:]))
	}
	t.Logf("completion_receipt_v1 result_hash=%s", v1.Golden.ResultHash)
	t.Logf("completion_receipt_v2 result_hash=%s observed_runtime_digest_v1=%s", v2.Golden.ResultHash, v2.Golden.ObservedRuntimeDigest)
	t.Logf("observed_runtime_v1 digest_v1=%s digest_v2=%s", storage.ObservedRuntimeDigestV1(observed), storage.ObservedRuntimeDigest(observed))
}

func writeContractFixture(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// contractAttestationV4 builds a schema-v4 statement exactly as the N-2
// producer issued it: level+name only under the frozen v4 name vocabulary,
// no facts block.
func contractAttestationV4(t *testing.T) Statement {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	att := ExecutionAttestation{
		SchemaVersion:          4,
		AttemptID:              model.AttemptID("contract-fixture-job-att-v4", 1),
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		RunID:                  "contract-fixture-run",
		JobID:                  "contract-fixture-job-att-v4",
		JobKey:                 "build[os=linux]",
		Status:                 "success",
		StartedAt:              &start,
		FinishedAt:             &finish,
		RunnerIdentity:         "contract-fixture-runner",
		ObservedRuntime:        fixedContractObservedRuntime(),
		Artifacts: []ExecutionAttestationArtifact{
			{Name: "dist", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 1},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "snap-pre", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 1},
		},
		WorkspaceRootSHA256: strings.Repeat("6", 64),
		MaterialRootSHA256:  strings.Repeat("7", 64),
		// v4 carried the assurance label only (frozen name vocabulary).
		ExecutionAssurance: ExecutionAssuranceEvidence{Level: 3, Name: legacyAssuranceNamesV4[3]},
		ExternalEffects:    model.EffectsKiwiMediated,
	}
	SortAttestationEvidence(&att)
	digest, err := ExecutionAttestationDigest(att)
	if err != nil {
		t.Fatal(err)
	}
	return Statement{
		Type:                   StatementType,
		Subject:                []Subject{{Name: att.AttemptID, Digest: map[string]string{"sha256": digest}}},
		PredicateType:          ExecutionAttestationPredicateType,
		AttemptID:              att.AttemptID,
		CapsuleDigest:          att.CapsuleDigest,
		ExecutionCapsuleDigest: att.ExecutionCapsuleDigest,
		RunnerIdentity:         att.RunnerIdentity,
		StartTime:              att.StartedAt,
		EndTime:                att.FinishedAt,
		Attestation:            &att,
	}
}

// contractAttestationV5 builds a schema-v5 statement under FROZEN v5
// semantics: network_mode=none is POLICY (derives network_denied), and
// workspace_quota_enforced means "configured" — never read as a v6 hard
// quota.
func contractAttestationV5(t *testing.T) Statement {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	facts := model.ExecutionFacts{
		Runtime:                   model.RuntimeFactContainer,
		FilesystemIsolated:        true,
		WorkspaceQuotaEnforced:    true, // frozen v5 meaning: configured/requested
		NetworkMode:               model.NetworkModeFactNone,
		DeclaredAuthorityMediated: false,
	}
	if !facts.ValidForSchema(5) {
		t.Fatalf("frozen v5 fixture facts not valid under schema 5: %+v", facts)
	}
	derived := model.DeriveAssuranceProfileSchema(5, facts)
	f := facts
	att := ExecutionAttestation{
		SchemaVersion:          5,
		AttemptID:              model.AttemptID("contract-fixture-job-att-v5", 1),
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		RunID:                  "contract-fixture-run",
		JobID:                  "contract-fixture-job-att-v5",
		JobKey:                 "build[os=linux]",
		Status:                 "success",
		StartedAt:              &start,
		FinishedAt:             &finish,
		RunnerIdentity:         "contract-fixture-runner",
		ObservedRuntime:        fixedContractObservedRuntime(),
		Artifacts: []ExecutionAttestationArtifact{
			{Name: "dist", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 1},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "snap-pre", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 1},
		},
		WorkspaceRootSHA256: strings.Repeat("6", 64),
		MaterialRootSHA256:  strings.Repeat("7", 64),
		ExecutionSemantics:  model.ExecutionSemanticsVersion,
		ExecutionAssurance:  ExecutionAssuranceEvidence{Level: int(derived), Name: derived.Name(), Facts: &f},
		ExternalEffects:     model.EffectsPure, // frozen v5: pure from POLICY none
		PolicyDigest:        strings.Repeat("8", 64),
		EventFrontier:       42,
		GraphFingerprint:    strings.Repeat("9", 64),
	}
	if err := model.ValidateExternalEffectsSchema(5, facts, model.EffectsPure); err != nil {
		t.Fatalf("frozen v5 pure classification refused: %v", err)
	}
	SortAttestationEvidence(&att)
	digest, err := ExecutionAttestationDigest(att)
	if err != nil {
		t.Fatal(err)
	}
	return Statement{
		Type:                   StatementType,
		Subject:                []Subject{{Name: att.AttemptID, Digest: map[string]string{"sha256": digest}}},
		PredicateType:          ExecutionAttestationPredicateType,
		AttemptID:              att.AttemptID,
		CapsuleDigest:          att.CapsuleDigest,
		ExecutionCapsuleDigest: att.ExecutionCapsuleDigest,
		ExecutionSemantics:     att.ExecutionSemantics,
		RunnerIdentity:         att.RunnerIdentity,
		StartTime:              att.StartedAt,
		EndTime:                att.FinishedAt,
		Attestation:            &att,
	}
}

// contractAttestationV6 builds a current (schema v6) statement through the
// real producer entry point so the fixture is byte-identical to what HEAD
// issues today.
func contractAttestationV6(t *testing.T, observed *model.ObservedRuntime, completionDigest string) Statement {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	obsWithControl := fixedContractObservedRuntime()
	obsWithControl.Control = &model.ExecutionControlReceipt{
		Runtime:                "docker",
		SandboxStarted:         true,
		NetworkEnforced:        model.ObservedNetworkNone,
		RootFilesystemReadOnly: true,
	}
	in := ExecutionAttestationInput{
		RunID:                  "contract-fixture-run",
		JobID:                  "contract-fixture-job-att-v6",
		JobKey:                 "build[os=linux]",
		Generation:             1,
		Status:                 "success",
		StartedAt:              &start,
		FinishedAt:             &finish,
		RunnerIdentity:         "contract-fixture-runner",
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		ObservedRuntime:        obsWithControl,
		Artifacts: []ExecutionAttestationArtifact{
			{Name: "dist", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 1},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "snap-pre", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 1},
		},
		WorkspaceRootSHA256:    strings.Repeat("6", 64),
		MaterialRootSHA256:     strings.Repeat("7", 64),
		CompletionResultDigest: completionDigest,
		EvidenceRootSHA256:     strings.Repeat("a", 64),
		ExecutionSemantics:     model.ExecutionSemanticsVersion,
		ExecutionAssuranceFacts: model.ExecutionFacts{
			Runtime:                   model.RuntimeFactContainer,
			FilesystemIsolated:        true,
			NetworkMode:               model.NetworkModeFactNone,
			NetworkAccessDenied:       true,
			ImagesDigestPinned:        true,
			DeclaredAuthorityMediated: true,
			Observed: &model.ExecutionControlReceipt{
				Runtime:                "docker",
				SandboxStarted:         true,
				NetworkEnforced:        model.ObservedNetworkNone,
				RootFilesystemReadOnly: true,
			},
		},
		ExternalEffects:  model.EffectsPure,
		PolicyDigest:     strings.Repeat("8", 64),
		EventFrontier:    42,
		GraphFingerprint: strings.Repeat("9", 64),
	}
	// The v6 fixture keeps the no-Control observed runtime OUT of the
	// completion digest computation above only as a stand-in; the completion
	// identity itself is the frozen v2 hash of the no-Control runtime, which
	// is what the historical receipt corpus records.
	_ = observed
	st, err := ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatalf("v6 statement: %v", err)
	}
	return st
}

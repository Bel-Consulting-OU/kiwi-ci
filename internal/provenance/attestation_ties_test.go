package provenance

import (
	"strings"
	"testing"
)

// TestSortAttestationEvidenceTies drives every tie-break comparator arm: equal
// names fall through to the secondary key for artifacts, reports and
// snapshots.
func TestSortAttestationEvidenceTies(t *testing.T) {
	att := ExecutionAttestation{
		Artifacts: []ExecutionAttestationArtifact{
			{Name: "b", SHA256: "z"},
			{Name: "a", SHA256: "z"},
			{Name: "a", SHA256: "a"},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "b", SuiteDigest: "z"},
			{Name: "a", SuiteDigest: "z"},
			{Name: "a", SuiteDigest: "a"},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "b", Phase: "post"},
			{ID: "a", Phase: "post"},
			{ID: "a", Phase: "pre"},
		},
	}
	SortAttestationEvidence(&att)
	if got := att.Artifacts; got[0].Name != "a" || got[0].SHA256 != "a" || got[1].SHA256 != "z" || got[2].Name != "b" {
		t.Fatalf("artifacts order = %+v", got)
	}
	if got := att.TestReports; got[0].Name != "a" || got[0].SuiteDigest != "a" || got[1].SuiteDigest != "z" || got[2].Name != "b" {
		t.Fatalf("reports order = %+v", got)
	}
	if got := att.Snapshots; got[0].ID != "a" || got[0].Phase != "post" || got[1].Phase != "pre" || got[2].ID != "b" {
		t.Fatalf("snapshots order = %+v", got)
	}
}

// TestExecutionEvidenceRootTieBreakOrdering proves the evidence root is
// canonical under every tie-break: shuffled input with equal names, digests,
// phases and generations still produces one root, and changing a tie-broken
// field changes it.
func TestExecutionEvidenceRootTieBreakOrdering(t *testing.T) {
	base := ExecutionEvidenceGraph{
		Artifacts: []ExecutionEvidenceArtifact{
			{Name: "a", SHA256: "a", Generation: 1},
			{Name: "a", SHA256: "a", Generation: 2},
			{Name: "a", SHA256: "z", Generation: 1},
			{Name: "b", SHA256: "a", Generation: 1},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "a", SuiteDigest: "a", Generation: 1},
			{Name: "a", SuiteDigest: "a", Generation: 2},
			{Name: "a", SuiteDigest: "z", Generation: 1},
			{Name: "b", SuiteDigest: "a", Generation: 1},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "a", Phase: "pre", SHA256: "a", Generation: 1},
			{ID: "a", Phase: "pre", SHA256: "a", Generation: 2},
			{ID: "a", Phase: "pre", SHA256: "z", Generation: 1},
			{ID: "a", Phase: "post", SHA256: "a", Generation: 1},
			{ID: "b", Phase: "pre", SHA256: "a", Generation: 1},
		},
	}
	want := ExecutionEvidenceRoot(base)

	shuffled := ExecutionEvidenceGraph{
		Artifacts: []ExecutionEvidenceArtifact{base.Artifacts[3], base.Artifacts[2], base.Artifacts[1], base.Artifacts[0]},
		TestReports: []ExecutionAttestationReport{
			base.TestReports[3], base.TestReports[2], base.TestReports[1], base.TestReports[0],
		},
		Snapshots: []ExecutionAttestationSnapshot{
			base.Snapshots[4], base.Snapshots[3], base.Snapshots[2], base.Snapshots[1], base.Snapshots[0],
		},
	}
	if got := ExecutionEvidenceRoot(shuffled); got != want {
		t.Fatalf("shuffled evidence root = %s, want %s", got, want)
	}

	changed := base
	changed.Artifacts = append([]ExecutionEvidenceArtifact(nil), base.Artifacts...)
	changed.Artifacts[0].Generation = 9
	if got := ExecutionEvidenceRoot(changed); got == want {
		t.Fatal("a changed generation did not change the evidence root")
	}
}

// TestVerifyExecutionAttestationErrorArms covers every consistency refusal: a
// foreign predicate type, a missing evidence block, a subject that does not
// bind the block, and mirror fields that disagree with the block.
func TestVerifyExecutionAttestationErrorArms(t *testing.T) {
	st, err := ExecutionAttestationStatement(attestationTestInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutionAttestation(st); err != nil {
		t.Fatalf("valid statement refused: %v", err)
	}

	foreign := st
	foreign.PredicateType = "cosign/something-else"
	if err := VerifyExecutionAttestation(foreign); err == nil || !strings.Contains(err.Error(), "predicate type") {
		t.Fatalf("foreign predicate = %v", err)
	}

	missing := st
	missing.Attestation = nil
	if err := VerifyExecutionAttestation(missing); err == nil || !strings.Contains(err.Error(), "no evidence block") {
		t.Fatalf("missing block = %v", err)
	}

	unbound := st
	unbound.Subject = []Subject{{Name: "x", Digest: map[string]string{"sha256": strings.Repeat("f", 64)}}}
	if err := VerifyExecutionAttestation(unbound); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unbound subject = %v", err)
	}

	attempt := st
	attempt.AttemptID = "job-1:99"
	if err := VerifyExecutionAttestation(attempt); err == nil || !strings.Contains(err.Error(), "attempt id mismatch") {
		t.Fatalf("attempt mismatch = %v", err)
	}

	capsule := st
	capsule.CapsuleDigest = strings.Repeat("f", 64)
	if err := VerifyExecutionAttestation(capsule); err == nil || !strings.Contains(err.Error(), "capsule digests disagree") {
		t.Fatalf("capsule mismatch = %v", err)
	}
}

// TestFormatTimePtr pins the absent-timestamp sentinel.
func TestFormatTimePtr(t *testing.T) {
	if got := formatTimePtr(nil); got != "" {
		t.Fatalf("formatTimePtr(nil) = %q, want empty", got)
	}
}

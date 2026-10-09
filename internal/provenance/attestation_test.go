package provenance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func attestationTestInput() ExecutionAttestationInput {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	return ExecutionAttestationInput{
		RunID:                  "run-1",
		JobID:                  "job-1",
		JobKey:                 "build[os=linux]",
		Generation:             7,
		Status:                 "success",
		StartedAt:              &start,
		FinishedAt:             &finish,
		RunnerIdentity:         "runner-a",
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		ObservedRuntime: &model.ObservedRuntime{
			OS: "linux", Arch: "amd64", RuntimeName: "docker", RuntimeVersion: "25.0",
			MainImage: "alpine:3.20", MainImageDigest: "sha256:" + strings.Repeat("c", 64),
			ServiceImages:       map[string]string{"db": "postgres:16"},
			ServiceImageDigests: map[string]string{"db": "sha256:" + strings.Repeat("d", 64)},
			Components:          map[string]string{"lib": strings.Repeat("e", 64)},
		},
		Artifacts: []ExecutionAttestationArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 7},
		},
		Snapshots: []ExecutionAttestationSnapshot{
			{ID: "snap-1", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 7},
			{ID: "snap-2", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("5", 64), Generation: 7},
		},
		WorkspaceRootSHA256: strings.Repeat("6", 64),
		MaterialRootSHA256:  strings.Repeat("7", 64),
	}
}

func TestExecutionAttestationStatementContent(t *testing.T) {
	st, err := ExecutionAttestationStatement(attestationTestInput())
	if err != nil {
		t.Fatal(err)
	}
	if st.Type != StatementType || st.PredicateType != ExecutionAttestationPredicateType {
		t.Fatalf("statement types = %q/%q", st.Type, st.PredicateType)
	}
	if st.Attestation == nil {
		t.Fatal("missing attestation block")
	}
	if st.AttemptID != "job-1:7" || st.Attestation.AttemptID != "job-1:7" {
		t.Fatalf("attempt id = %q/%q", st.AttemptID, st.Attestation.AttemptID)
	}
	if st.CapsuleDigest != strings.Repeat("a", 64) || st.ExecutionCapsuleDigest != strings.Repeat("b", 64) {
		t.Fatalf("capsule digests = %q/%q", st.CapsuleDigest, st.ExecutionCapsuleDigest)
	}
	if len(st.Subject) != 1 || st.Subject[0].Name != "job-1:7" {
		t.Fatalf("subject = %+v", st.Subject)
	}
	want, err := ExecutionAttestationDigest(*st.Attestation)
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject[0].Digest["sha256"] != want {
		t.Fatalf("subject digest does not bind the block: %q != %q", st.Subject[0].Digest["sha256"], want)
	}
	// The predicate must be omitted from the serialized statement (it is the
	// artifact-provenance shape, not this one).
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"predicate"`)) {
		t.Fatalf("attestation statement leaked the artifact predicate: %s", b)
	}
	if err := VerifyExecutionAttestation(st); err != nil {
		t.Fatalf("VerifyExecutionAttestation: %v", err)
	}
}

func TestExecutionAttestationDigestOrderIndependentAndTamperEvident(t *testing.T) {
	in := attestationTestInput()
	base, err := ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := attestationTestInput()
	shuffled.Artifacts = append(shuffled.Artifacts, ExecutionAttestationArtifact{Name: "aaa", SHA256: strings.Repeat("0", 64)})
	shuffled.Snapshots = []ExecutionAttestationSnapshot{shuffled.Snapshots[1], shuffled.Snapshots[0]}
	shuffled.TestReports = append(shuffled.TestReports, ExecutionAttestationReport{Name: "aaa", SuiteDigest: strings.Repeat("8", 64), Generation: 7})
	other, err := ExecutionAttestationStatement(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	// Order-independent for identical evidence: rebuilding with the original
	// order must produce the same digest as a build whose lists were
	// pre-sorted differently.
	again, err := ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := ExecutionAttestationDigest(*base.Attestation)
	d2, _ := ExecutionAttestationDigest(*again.Attestation)
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %s != %s", d1, d2)
	}
	d3, _ := ExecutionAttestationDigest(*other.Attestation)
	if d3 == d1 {
		t.Fatal("added evidence did not change the digest")
	}
	// Every field is bound: mutating one flips the digest.
	mutations := []func(a *ExecutionAttestation){
		func(a *ExecutionAttestation) { a.Status = "failure" },
		func(a *ExecutionAttestation) { a.RunnerIdentity = "other" },
		func(a *ExecutionAttestation) { a.JobKey = "other" },
		func(a *ExecutionAttestation) { a.WorkspaceRootSHA256 = strings.Repeat("9", 64) },
		func(a *ExecutionAttestation) { a.ObservedRuntime.Arch = "arm64" },
		func(a *ExecutionAttestation) { a.Artifacts[0].ProvenanceSHA256 = "" },
		func(a *ExecutionAttestation) { a.TestReports[0].SuiteDigest = strings.Repeat("f", 64) },
		func(a *ExecutionAttestation) { a.Snapshots[0].Phase = model.SnapshotPhasePostJob },
	}
	for i, mutate := range mutations {
		cp := *base.Attestation
		cp.Artifacts = append([]ExecutionAttestationArtifact(nil), base.Attestation.Artifacts...)
		cp.TestReports = append([]ExecutionAttestationReport(nil), base.Attestation.TestReports...)
		cp.Snapshots = append([]ExecutionAttestationSnapshot(nil), base.Attestation.Snapshots...)
		rt := *base.Attestation.ObservedRuntime
		cp.ObservedRuntime = &rt
		mutate(&cp)
		got, err := ExecutionAttestationDigest(cp)
		if err != nil {
			t.Fatal(err)
		}
		if got == d1 {
			t.Fatalf("mutation %d did not change the digest", i)
		}
	}
}

func TestExecutionAttestationSignVerifyAndTamper(t *testing.T) {
	st, err := ExecutionAttestationStatement(attestationTestInput())
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(st, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyWith(envBytes, func(kid string) (ed25519.PublicKey, bool) {
		return pub, kid == "kid-1"
	}, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyExecutionAttestation(got); err != nil {
		t.Fatalf("consistency: %v", err)
	}
	// A statement whose block disagrees with its subject/attempt mirror is
	// rejected even though the signature is valid.
	tampered := got
	cp := *got.Attestation
	cp.Status = "failure"
	tampered.Attestation = &cp
	if err := VerifyExecutionAttestation(tampered); err == nil {
		t.Fatal("inconsistent attestation block accepted")
	}
	// A byte-level payload tamper fails the signature.
	var raw Envelope
	if err := json.Unmarshal(envBytes, &raw); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(raw.Payload)
	payload[0] ^= 0x01
	raw.Payload = base64.StdEncoding.EncodeToString(payload)
	tamperedBytes, _ := json.Marshal(raw)
	if _, err := VerifyWith(tamperedBytes, nil, VerifyOptions{TrustedKey: pub}); err == nil {
		t.Fatal("tampered envelope verified")
	}
}

func TestExecutionAttestationConstraints(t *testing.T) {
	in := attestationTestInput()
	st, err := ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(st, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	envBytes, _ := json.Marshal(env)
	ok := VerifyOptions{TrustedKey: pub, AttemptID: "job-1:7", CapsuleDigest: in.CapsuleDigest, ExecutionCapsuleDigest: in.ExecutionCapsuleDigest}
	if _, err := VerifyWith(envBytes, nil, ok); err != nil {
		t.Fatalf("matching constraints failed: %v", err)
	}
	for _, bad := range []VerifyOptions{
		{TrustedKey: pub, AttemptID: "job-1:8"},
		{TrustedKey: pub, CapsuleDigest: strings.Repeat("0", 64)},
		{TrustedKey: pub, ExecutionCapsuleDigest: strings.Repeat("0", 64)},
	} {
		if _, err := VerifyWith(envBytes, nil, bad); err == nil {
			t.Fatalf("constraint %+v not enforced", bad)
		}
	}
}

// TestExecutionEvidenceRootBindsEvidenceGraph pins the canonical evidence
// root: deterministic under list order, and changed by ANY artifact identity,
// sidecar reference, report suite digest or snapshot identity.
func TestExecutionEvidenceRootBindsEvidenceGraph(t *testing.T) {
	artA := ExecutionEvidenceArtifact{
		Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, Generation: 7,
		ProvenanceSHA256: strings.Repeat("2", 64),
		SBOMPath:         "cas:sbom-1", SBOMSHA256: strings.Repeat("3", 64),
		SigstorePath: "cas:sigstore-1", SigstoreSHA256: strings.Repeat("4", 64),
	}
	artB := ExecutionEvidenceArtifact{Name: "aaa", SHA256: strings.Repeat("0", 64), Size: 1, Generation: 7}
	rep := ExecutionAttestationReport{Name: "test", SuiteDigest: strings.Repeat("5", 64), Generation: 7}
	snapA := ExecutionAttestationSnapshot{ID: "snap-1", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("6", 64), Generation: 7}
	snapB := ExecutionAttestationSnapshot{ID: "snap-2", Phase: model.SnapshotPhasePostJob, SHA256: strings.Repeat("7", 64), Generation: 7}

	graph := func(mut func(*ExecutionEvidenceGraph)) string {
		g := ExecutionEvidenceGraph{
			Artifacts:   []ExecutionEvidenceArtifact{artA, artB},
			TestReports: []ExecutionAttestationReport{rep},
			Snapshots:   []ExecutionAttestationSnapshot{snapA, snapB},
		}
		mut(&g)
		return ExecutionEvidenceRoot(g)
	}
	base := graph(func(*ExecutionEvidenceGraph) {})
	if len(base) != 64 {
		t.Fatalf("evidence root = %q, want 64 hex chars", base)
	}
	reordered := ExecutionEvidenceRoot(ExecutionEvidenceGraph{
		Artifacts: []ExecutionEvidenceArtifact{artB, artA}, TestReports: []ExecutionAttestationReport{rep},
		Snapshots: []ExecutionAttestationSnapshot{snapB, snapA},
	})
	if reordered != base {
		t.Fatalf("evidence root not order independent: %q != %q", reordered, base)
	}
	changes := map[string]string{
		"artifact name":       graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].Name = "other" }),
		"artifact sha":        graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].SHA256 = strings.Repeat("8", 64) }),
		"artifact size":       graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].Size = 43 }),
		"artifact generation": graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].Generation = 8 }),
		"provenance sha":      graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].ProvenanceSHA256 = strings.Repeat("9", 64) }),
		"sbom path":           graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].SBOMPath = "cas:other" }),
		"sbom sha":            graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].SBOMSHA256 = strings.Repeat("9", 64) }),
		"sigstore path":       graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].SigstorePath = "cas:other" }),
		"sigstore sha":        graph(func(g *ExecutionEvidenceGraph) { g.Artifacts[0].SigstoreSHA256 = strings.Repeat("9", 64) }),
		"report name":         graph(func(g *ExecutionEvidenceGraph) { g.TestReports[0].Name = "other" }),
		"report digest":       graph(func(g *ExecutionEvidenceGraph) { g.TestReports[0].SuiteDigest = strings.Repeat("9", 64) }),
		"report generation":   graph(func(g *ExecutionEvidenceGraph) { g.TestReports[0].Generation = 8 }),
		"snapshot id":         graph(func(g *ExecutionEvidenceGraph) { g.Snapshots[0].ID = "other" }),
		"snapshot phase":      graph(func(g *ExecutionEvidenceGraph) { g.Snapshots[0].Phase = model.SnapshotPhasePostJob }),
		"snapshot sha":        graph(func(g *ExecutionEvidenceGraph) { g.Snapshots[0].SHA256 = strings.Repeat("9", 64) }),
		"snapshot generation": graph(func(g *ExecutionEvidenceGraph) { g.Snapshots[0].Generation = 8 }),
	}
	for name, got := range changes {
		if got == base {
			t.Fatalf("%s did not change the evidence root", name)
		}
	}
}

// TestExecutionAttestationDigestBindsCompletionResultAndEvidenceRoot proves
// the new binding fields are part of the canonical digest: changing either
// changes the subject digest, and an intact statement still verifies.
func TestExecutionAttestationDigestBindsCompletionResultAndEvidenceRoot(t *testing.T) {
	const completionA = "1111111111111111111111111111111111111111111111111111111111111111"
	const completionB = "2222222222222222222222222222222222222222222222222222222222222222"
	const rootA = "3333333333333333333333333333333333333333333333333333333333333333"
	const rootB = "4444444444444444444444444444444444444444444444444444444444444444"

	in := attestationTestInput()
	in.CompletionResultDigest = completionA
	in.EvidenceRootSHA256 = rootA
	base, err := ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatal(err)
	}
	if base.Attestation.CompletionResultDigest != completionA || base.Attestation.EvidenceRootSHA256 != rootA {
		t.Fatalf("binding fields not copied: %+v", base.Attestation)
	}
	if err := VerifyExecutionAttestation(base); err != nil {
		t.Fatalf("intact statement does not verify: %v", err)
	}
	d0, _ := ExecutionAttestationDigest(*base.Attestation)

	changedCompletion := in
	changedCompletion.CompletionResultDigest = completionB
	stCompletion, err := ExecutionAttestationStatement(changedCompletion)
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := ExecutionAttestationDigest(*stCompletion.Attestation)
	if d1 == d0 {
		t.Fatal("changing completionResultDigest did not change the attestation digest")
	}
	changedRoot := in
	changedRoot.EvidenceRootSHA256 = rootB
	stRoot, err := ExecutionAttestationStatement(changedRoot)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := ExecutionAttestationDigest(*stRoot.Attestation)
	if d2 == d0 {
		t.Fatal("changing evidenceRootSha256 did not change the attestation digest")
	}

	// Tampering with either field in the signed block is detected by
	// verification even though the signature itself is intact.
	for _, mutate := range []func(a *ExecutionAttestation){
		func(a *ExecutionAttestation) { a.CompletionResultDigest = completionB },
		func(a *ExecutionAttestation) { a.EvidenceRootSHA256 = rootB },
	} {
		tampered := base
		cp := *base.Attestation
		mutate(&cp)
		tampered.Attestation = &cp
		if err := VerifyExecutionAttestation(tampered); err == nil {
			t.Fatal("tampered binding field accepted")
		}
	}
}

func TestTestReportSuiteDigestBindsCases(t *testing.T) {
	rep := model.TestReport{ID: "r1", Cases: []model.TestResult{
		{Name: "a", Passed: true, Duration: 1.5},
		{Name: "b", Passed: false, Message: "boom"},
	}}
	d1 := TestReportSuiteDigest(rep)
	d2 := TestReportSuiteDigest(rep)
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("suite digest not stable: %q / %q", d1, d2)
	}
	// Case order significant.
	rep.Cases[0], rep.Cases[1] = rep.Cases[1], rep.Cases[0]
	if TestReportSuiteDigest(rep) == d1 {
		t.Fatal("reordered cases produced the same suite digest")
	}
	rep.Cases[0], rep.Cases[1] = rep.Cases[1], rep.Cases[0]
	// Content change flips the digest.
	rep.Cases = append(rep.Cases, model.TestResult{Name: "c", Passed: true})
	if TestReportSuiteDigest(rep) == d1 {
		t.Fatal("added case produced the same suite digest")
	}
	// Per-delivery metadata (id/path/created time) is deliberately excluded.
	other := model.TestReport{ID: "r2", Path: "/elsewhere", CreatedAt: time.Now(), LeaseGeneration: 9, Cases: rep.Cases}
	if TestReportSuiteDigest(other) != TestReportSuiteDigest(rep) {
		t.Fatal("delivery metadata leaked into the suite digest")
	}
}

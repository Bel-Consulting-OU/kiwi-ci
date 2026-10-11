package scenarios

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// evidenceInput is the shared happy-path attestation input for the DF-EVID
// suite. Field values are fixed so a failure diff shows exactly which arm
// mutated which identity.
func evidenceInput() provenance.ExecutionAttestationInput {
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	return provenance.ExecutionAttestationInput{
		RunID:                  "run-evid",
		JobID:                  "job-evid",
		JobKey:                 "build",
		Generation:             3,
		Status:                 string(model.StatusSuccess),
		StartedAt:              &start,
		FinishedAt:             &finish,
		RunnerIdentity:         "runner-evid",
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		ObservedRuntime: &model.ObservedRuntime{
			OS: "linux", Arch: "amd64", RuntimeName: "docker", RuntimeVersion: "25.0",
			MainImage: "alpine:3.20", MainImageDigest: "sha256:" + strings.Repeat("c", 64),
		},
		Artifacts: []provenance.ExecutionAttestationArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 3},
		},
		Snapshots: []provenance.ExecutionAttestationSnapshot{
			{ID: "snap-1", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 3},
		},
		WorkspaceRootSHA256: strings.Repeat("6", 64),
		MaterialRootSHA256:  strings.Repeat("7", 64),
		ExecutionSemantics:  model.ExecutionSemanticsVersion,
		ExecutionAssuranceFacts: model.ExecutionFacts{
			Runtime:                   model.RuntimeFactContainer,
			FilesystemIsolated:        true,
			WorkspaceQuotaConfigured:  true,
			NetworkMode:               model.NetworkModeFactDefault,
			DeclaredAuthorityMediated: true,
		},
		ExternalEffects:  model.EffectsKiwiMediated,
		PolicyDigest:     strings.Repeat("8", 64),
		EventFrontier:    42,
		GraphFingerprint: strings.Repeat("9", 64),
	}
}

func signKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return pub, priv
}

// resign rebuilds the subject digest over a mutated attestation block so the
// tamper case isolates the SEMANTIC checks from the digest check: the
// signature is not what fails here (this is VerifyExecutionAttestation's
// job), but the block is internally bound as if re-signed.
func resign(st provenance.Statement) provenance.Statement {
	digest, err := provenance.ExecutionAttestationDigest(*st.Attestation)
	if err != nil {
		return st
	}
	if len(st.Subject) > 0 {
		st.Subject[0].Digest = map[string]string{"sha256": digest}
	}
	return st
}

// TestDFEVID001GenerationAndVerify is DF-EVID-001 positive arm: a correctly
// generated attestation verifies end to end (statement build → sign →
// signature verify → self-binding verify).
func TestDFEVID001GenerationAndVerify(t *testing.T) {
	entry, ok := Lookup(ScenarioEvidenceGenerationVerify)
	if !ok {
		t.Fatal("scenario DF-EVID-001 missing from the registry")
	}
	pub, priv := signKey(t)
	in := evidenceInput()
	st, err := provenance.ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	env, err := provenance.Sign(st, "df-key", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Local(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer h.Stop()
	got, err := h.VerifyEvidence(env, pub)
	if err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
	if got.AttemptID != "job-evid:3" {
		t.Fatalf("attempt id = %q, want job-evid:3", got.AttemptID)
	}
	// Negative arm: the same block presented without a valid signature must
	// be refused at the signature layer.
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, err := h.VerifyEvidence(env, pub); err == nil {
		t.Fatal("tampered signature verified")
	}
	_ = entry
}

// TestDFEVID002TamperMatrix is DF-EVID-002: flipping any single signed
// identity field must fail VerifyExecutionAttestation. The matrix covers
// commit/capsule, runner, job, attempt, artifact digest, policy digest,
// graph fingerprint, execution semantics, assurance facts, external effects
// and the event frontier — the audit's full tamper surface.
func TestDFEVID002TamperMatrix(t *testing.T) {
	if _, ok := Lookup(ScenarioEvidenceTamperMatrix); !ok {
		t.Fatal("scenario DF-EVID-002 missing from the registry")
	}
	base, err := provenance.ExecutionAttestationStatement(evidenceInput())
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	if err := provenance.VerifyExecutionAttestation(base); err != nil {
		t.Fatalf("untampered statement must verify: %v", err)
	}
	// flip mutates the attestation block in place; each case must then be
	// refused. "commit" is the capsule identity: CapsuleDigest binds the
	// admitted commit-derived computation the attempt ran.
	cases := []struct {
		name string
		flip func(*provenance.ExecutionAttestation)
	}{
		{"commit", func(a *provenance.ExecutionAttestation) {
			a.CapsuleDigest = strings.Repeat("f", 64)
		}},
		{"runner", func(a *provenance.ExecutionAttestation) {
			a.RunnerIdentity = "runner-evil"
		}},
		{"job", func(a *provenance.ExecutionAttestation) {
			a.JobID = "job-evil"
		}},
		{"attempt", func(a *provenance.ExecutionAttestation) {
			a.AttemptID = "job-evid:999"
		}},
		{"artifact-digest", func(a *provenance.ExecutionAttestation) {
			a.Artifacts[0].SHA256 = strings.Repeat("0", 64)
		}},
		{"policy-digest", func(a *provenance.ExecutionAttestation) {
			a.PolicyDigest = strings.Repeat("e", 64)
		}},
		{"graph-fingerprint", func(a *provenance.ExecutionAttestation) {
			a.GraphFingerprint = strings.Repeat("d", 64)
		}},
		{"execution-semantics", func(a *provenance.ExecutionAttestation) {
			a.ExecutionSemantics = "kiwi.execution.v0"
		}},
		{"assurance-facts", func(a *provenance.ExecutionAttestation) {
			// A native runtime under a claimed isolation boundary is an
			// invalid vector: the semantic layer must refuse it even when
			// the digest is rebuilt.
			a.ExecutionAssurance.Facts.Runtime = model.RuntimeFactNative
		}},
		{"external-effects", func(a *provenance.ExecutionAttestation) {
			a.ExternalEffects = model.ExternalEffectsClass("bogus")
		}},
		{"event-frontier", func(a *provenance.ExecutionAttestation) {
			a.EventFrontier = 99
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := cloneStatement(t, base)
			tc.flip(st.Attestation)
			// Layer 1: the un-recomputed subject digest detects the flip.
			if err := provenance.VerifyExecutionAttestation(st); err == nil {
				t.Fatalf("tampered %s verified against the original subject digest", tc.name)
			}
			// Layer 2: even a re-bound (re-signed) block must fail when the
			// flip made the block semantically inconsistent (facts no longer
			// derive their label / invalid vector / undefined class).
			rebound := resign(st)
			err := provenance.VerifyExecutionAttestation(rebound)
			if tc.name == "assurance-facts" || tc.name == "external-effects" {
				if err == nil {
					t.Fatalf("re-signed contradictory %s verified", tc.name)
				}
			}
			// For pure identity flips a re-sign WOULD be valid evidence of a
			// different attempt; the matrix's job is that the ORIGINAL
			// envelope cannot survive the flip, which layer 1 proved.
		})
	}
}

// TestDFEVID003EffectiveObservedMismatch is DF-EVID-003: a receipt that
// contradicts the effective vector must fail signing AND verification.
// The pinned contradiction: effective network=none on a container while the
// observed receipt reports a connected container namespace.
func TestDFEVID003EffectiveObservedMismatch(t *testing.T) {
	if _, ok := Lookup(ScenarioEvidenceObservedMismatch); !ok {
		t.Fatal("scenario DF-EVID-003 missing from the registry")
	}
	receipt := &model.ExecutionControlReceipt{
		Runtime:         "docker",
		SandboxStarted:  true,
		NetworkEnforced: model.ObservedNetworkContainerNamespace,
	}
	contradictory := model.ExecutionFacts{
		Runtime:            model.RuntimeFactContainer,
		FilesystemIsolated: true,
		NetworkMode:        model.NetworkModeFactNone,
	}
	if err := contradictory.ApplyObservedControl(receipt); err == nil {
		t.Fatal("contradictory receipt was accepted by ApplyObservedControl")
	}
	if contradictory.Valid() {
		t.Fatal("contradictory facts report Valid")
	}
	// Signing fails: the statement builder refuses an unclassifiable vector.
	in := evidenceInput()
	in.ExecutionAssuranceFacts = contradictory
	in.ObservedRuntime = &model.ObservedRuntime{RuntimeName: "docker", Control: receipt}
	if _, err := provenance.ExecutionAttestationStatement(in); err == nil {
		t.Fatal("signing accepted a contradictory effective/observed pair")
	}
	// Verification fails even over a digest-rebound block: the verifier
	// re-derives consistency from the signed facts and receipt.
	ok := evidenceInput()
	st, err := provenance.ExecutionAttestationStatement(ok)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	bad := contradictory
	st.Attestation.ExecutionAssurance.Facts = &bad
	if st.Attestation.ObservedRuntime != nil {
		obs := *st.Attestation.ObservedRuntime
		obs.Control = receipt
		st.Attestation.ObservedRuntime = &obs
	}
	if err := provenance.VerifyExecutionAttestation(resign(st)); err == nil {
		t.Fatal("verification accepted a contradictory effective/observed pair")
	}
}

// TestDFEVID004QuotaTruthfulness is DF-EVID-004: workspace_quota_enforced
// is ONLY ever true from an observed hard-quota receipt. The table pins the
// four observation paths and the admission consequence of the fifth.
func TestDFEVID004QuotaTruthfulness(t *testing.T) {
	if _, ok := Lookup(ScenarioEvidenceQuotaTruth); !ok {
		t.Fatal("scenario DF-EVID-004 missing from the registry")
	}
	cases := []struct {
		name string
		// configured is the plan's requested bound (WorkspaceQuotaConfigured).
		configured bool
		// receipt is the attempt-specific observation; nil means the
		// executor captured no receipt at all.
		receipt      *model.ExecutionControlReceipt
		wantEnforced bool
	}{
		{
			name:       "hard-quota-success",
			configured: true,
			receipt: &model.ExecutionControlReceipt{
				Runtime: "docker", SandboxStarted: true,
				NetworkEnforced: model.ObservedNetworkNone, WorkspaceQuotaEnforced: true,
			},
			wantEnforced: true,
		},
		{
			name:       "fallback-accounting",
			configured: true,
			receipt: &model.ExecutionControlReceipt{
				Runtime: "docker", SandboxStarted: true,
				NetworkEnforced: model.ObservedNetworkNone, WorkspaceQuotaEnforced: false,
			},
			wantEnforced: false,
		},
		{
			name:       "setup-failed",
			configured: true,
			receipt: &model.ExecutionControlReceipt{
				Runtime: "docker", SandboxStarted: true,
				NetworkEnforced: model.ObservedNetworkNone, WorkspaceQuotaEnforced: false,
			},
			wantEnforced: false,
		},
		{
			name:         "no-request",
			configured:   false,
			receipt:      &model.ExecutionControlReceipt{Runtime: "native", NetworkEnforced: model.ObservedNetworkHost},
			wantEnforced: false,
		},
		{
			name:         "no-receipt",
			configured:   true,
			receipt:      nil,
			wantEnforced: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := model.ExecutionFacts{
				Runtime:                  model.RuntimeFactContainer,
				FilesystemIsolated:       true,
				WorkspaceQuotaConfigured: tc.configured,
				NetworkMode:              model.NetworkModeFactNone,
			}
			if tc.receipt != nil && tc.receipt.Runtime == "native" {
				facts.Runtime = model.RuntimeFactNative
				facts.FilesystemIsolated = false
				facts.NetworkMode = model.NetworkModeFactDefault
			}
			if err := facts.ApplyObservedControl(tc.receipt); err != nil {
				t.Fatalf("ApplyObservedControl: %v", err)
			}
			if facts.WorkspaceQuotaEnforced != tc.wantEnforced {
				t.Fatalf("WorkspaceQuotaEnforced = %v, want %v", facts.WorkspaceQuotaEnforced, tc.wantEnforced)
			}
			// The enforcement fact must never be manufactured from the
			// configured request alone.
			if !tc.configured && facts.WorkspaceQuotaEnforced {
				t.Fatal("enforced quota fact set without a configured request")
			}
			// And a signer must refuse a claimed enforcement the receipt
			// does not corroborate (the overclaim direction).
			over := facts
			over.WorkspaceQuotaEnforced = !tc.wantEnforced
			if err := over.ValidateObservedConsistency(); err == nil {
				t.Fatal("overclaimed/underclaimed quota fact passed consistency")
			}
		})
	}
}

// TestDFEVID005SecretAbsence is DF-EVID-005: serialized evidence must not
// carry credential material. The scan is over the exact envelope bytes a
// consumer would fetch.
func TestDFEVID005SecretAbsence(t *testing.T) {
	if _, ok := Lookup(ScenarioEvidenceSecretAbsence); !ok {
		t.Fatal("scenario DF-EVID-005 missing from the registry")
	}
	markers := []string{
		"AKIA0000000000000000",
		"-----BEGIN RSA PRIVATE KEY-----",
		"kiwi-dogfood-secret-canary",
		"xoxb-000000000000",
	}
	st, err := provenance.ExecutionAttestationStatement(evidenceInput())
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	_, priv := signKey(t)
	env, err := provenance.Sign(st, "df-key", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if hits := dogfood.ScanSecretMarkers(raw, markers); len(hits) > 0 {
		t.Fatalf("evidence leaked secret markers: %v", hits)
	}
	// Negative arm: a planted marker must be detected — the scan is real.
	planted := append(append([]byte(nil), raw...), []byte("\nkiwi-dogfood-secret-canary")...)
	if hits := dogfood.ScanSecretMarkers(planted, markers); len(hits) != 1 {
		t.Fatalf("planted marker hits = %v, want exactly the canary", hits)
	}
}

func cloneStatement(t *testing.T, st provenance.Statement) provenance.Statement {
	t.Helper()
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	var out provenance.Statement
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	return out
}

func mustSeed(t *testing.T) dogfood.Seed {
	t.Helper()
	return dogfood.NewSeed(0xDFE001, time.Now(), dogfood.RunMetadata{
		Commit:       "deadbeefcafebabe",
		Executor:     "fake",
		Versions:     dogfood.VersionInfo{Server: "test", Runner: "test", Protocol: model.ExecutionSemanticsVersion},
		PolicyDigest: strings.Repeat("8", 64),
	})
}

func mustNamespace(t *testing.T) dogfood.Namespace {
	t.Helper()
	ns, err := dogfood.NewNamespace(time.Now(), rand.Reader)
	if err != nil {
		t.Fatalf("namespace: %v", err)
	}
	return ns
}

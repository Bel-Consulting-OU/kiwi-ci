package server

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

var errInjectedSigning = errors.New("injected provenance signing failure")

// seedRequiredProvenanceContract points the DB fake's job-a contract at a
// required-provenance artifact.
func seedRequiredProvenanceContract(t *testing.T, f *dbFakeStore) {
	t.Helper()
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{
		"bin": {Name: "bin", Paths: []string{"out/"}, Required: true, Provenance: storage.ArtifactProvenanceRequired},
	}
	f.mu.Unlock()
}

func artifactRows(f *dbFakeStore) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.artifacts)
}

// TestArtifactRequiredProvenanceUploadFailsClosed proves the upload ordering:
// with Provenance=required, a provenance signing failure REFUSES the upload
// (503) and commits NO artifact record; a later retry with a working signer
// commits the record with the durable provenance reference.
func TestArtifactRequiredProvenanceUploadFailsClosed(t *testing.T) {
	s, f, mb, hdrs := cacheFixture(t)
	seedRequiredProvenanceContract(t, f)
	original := provenanceSignFn
	provenanceSignFn = func(st provenance.Statement, keyID string, priv ed25519.PrivateKey) (provenance.Envelope, error) {
		return provenance.Envelope{}, errInjectedSigning
	}
	t.Cleanup(func() { provenanceSignFn = original })

	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("required-provenance upload with failing signer = %d, want 503: %s", w.Code, w.Body.String())
	}
	if rows := artifactRows(f); rows != 0 {
		t.Fatalf("artifact rows after refused upload = %d, want 0", rows)
	}

	// Retry with the real signer: the artifact commits with provenance.
	provenanceSignFn = original
	w = fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("retry = %d, want 201: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rows := append([]model.ArtifactRecord(nil), f.artifacts...)
	f.mu.Unlock()
	if len(rows) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(rows))
	}
	if rows[0].ProvenanceSHA256 == "" || rows[0].ProvenancePath == "" {
		t.Fatalf("committed record lacks provenance: %+v", rows[0])
	}
	// The provenance envelope is a verifiable CAS object.
	mb.mu.Lock()
	_, hasEnvelope := mb.objects[rows[0].ProvenanceSHA256]
	mb.mu.Unlock()
	if !hasEnvelope {
		t.Fatalf("provenance digest %s is not in the CAS", rows[0].ProvenanceSHA256)
	}
}

// TestArtifactBestEffortProvenanceSignerFailureUnchanged proves the
// best-effort policy keeps the historical behavior: a signing failure is
// logged, the upload still succeeds and the record simply carries no
// provenance reference (the completion gate for non-required contracts is
// unaffected).
func TestArtifactBestEffortProvenanceSignerFailureUnchanged(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	original := provenanceSignFn
	provenanceSignFn = func(st provenance.Statement, keyID string, priv ed25519.PrivateKey) (provenance.Envelope, error) {
		return provenance.Envelope{}, errInjectedSigning
	}
	t.Cleanup(func() { provenanceSignFn = original })

	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("best-effort upload with failing signer = %d, want 201: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rows := append([]model.ArtifactRecord(nil), f.artifacts...)
	f.mu.Unlock()
	if len(rows) != 1 || rows[0].ProvenanceSHA256 != "" || rows[0].ProvenancePath != "" {
		t.Fatalf("best-effort record = %+v, want no provenance refs", rows)
	}
}

// TestRequiredProvenanceCompletionGateLocal proves the fs/memory completion
// gate: a required artifact without a durable provenance digest cannot
// satisfy completion, while the same record with provenance can.
func TestRequiredProvenanceCompletionGateLocal(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fcSeedContract(s, "job-x", storage.ArtifactContract{Name: "bin", Required: true, Provenance: storage.ArtifactProvenanceRequired})
	s.mu.Lock()
	j := model.Job{ID: "job-x", RunID: "run-x", Key: "build", Status: model.StatusRunning}
	s.jobs["job-x"] = j
	s.artifacts["art-x"] = model.ArtifactRecord{ID: "art-x", RunID: "run-x", JobID: "job-x", Name: "bin", SHA256: strings.Repeat("1", 64)}
	missing := s.requiredArtifactsMissingLocked(j)
	s.artifacts["art-x"] = model.ArtifactRecord{ID: "art-x", RunID: "run-x", JobID: "job-x", Name: "bin", SHA256: strings.Repeat("1", 64), ProvenanceSHA256: strings.Repeat("2", 64)}
	present := s.requiredArtifactsMissingLocked(j)
	s.mu.Unlock()
	if missing != "bin" || present != "" {
		t.Fatalf("gate = %q / %q, want bin / empty", missing, present)
	}
}

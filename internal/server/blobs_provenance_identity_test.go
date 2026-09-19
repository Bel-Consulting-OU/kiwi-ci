package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// artifactIdentityFixture wires the DB-mode cacheFixture with the full run
// identity (repository/ref/commit) the signed provenance statement must
// carry, plus the declared "bin" contract.
func artifactIdentityFixture(t *testing.T) (*Server, *dbFakeStore, *memBlob, map[string]string) {
	t.Helper()
	s, f, mb, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.runs["run-c"] = model.Run{
		ID: "run-c", RepoID: "github.com/o/repo-a", Repo: "https://github.com/o/repo-a.git",
		RepoFullName: "o/repo-a", Ref: "refs/heads/main", SHA: "abc123", Status: model.StatusRunning,
	}
	f.mu.Unlock()
	return s, f, mb, hdrs
}

// assertNoArtifactCommitted proves an upload that failed identity resolution
// staged nothing: no artifact row, no CAS blob (payload, provenance or
// sidecar) and no local staging/provenance file under the job directory.
func assertNoArtifactCommitted(t *testing.T, s *Server, f *dbFakeStore, mb *memBlob, runID, jobID string) {
	t.Helper()
	f.mu.Lock()
	rows := len(f.artifacts)
	f.mu.Unlock()
	if rows != 0 {
		t.Fatalf("artifact rows = %d, want 0: upload proceeded without authoritative identity", rows)
	}
	mb.mu.Lock()
	objects := len(mb.objects)
	mb.mu.Unlock()
	if objects != 0 {
		t.Fatalf("CAS objects = %d, want 0: blob/provenance bytes were written", objects)
	}
	entries, err := os.ReadDir(filepath.Join(s.store.Root, "artifacts", runID, jobID))
	if err == nil && len(entries) != 0 {
		t.Fatalf("staged files = %v, want none", entries)
	}
}

func TestArtifactUploadGetRunErrorFailsClosed(t *testing.T) {
	s, f, mb, hdrs := artifactIdentityFixture(t)
	fault := errors.New("run table down")
	s.DB = &fcStore{dbFakeStore: f, getRunErr: fault}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with failing GetRun = %d, want 503: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), fault.Error()) {
		t.Fatalf("response body leaks the raw store error: %s", w.Body.String())
	}
	assertNoArtifactCommitted(t, s, f, mb, "run-c", "job-a")
}

func TestArtifactUploadRunNotFoundFailsClosed(t *testing.T) {
	s, f, mb, hdrs := artifactIdentityFixture(t)
	f.mu.Lock()
	delete(f.runs, "run-c")
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
	}
	assertNoArtifactCommitted(t, s, f, mb, "run-c", "job-a")
}

func TestArtifactUploadMemoryRunMissingFailsClosed(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	fcSeedContract(s, "job-a", fcBinContract())
	s.mu.Lock()
	delete(s.runs, "run-c")
	s.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("memory upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	rows := len(s.artifacts)
	s.mu.Unlock()
	if rows != 0 {
		t.Fatalf("memory artifact rows = %d, want 0: upload proceeded without authoritative identity", rows)
	}
	entries, err := os.ReadDir(filepath.Join(s.store.Root, "artifacts", "run-c", "job-a"))
	if err == nil && len(entries) != 0 {
		t.Fatalf("staged files = %v, want none", entries)
	}
}

func TestArtifactUploadProvenanceCarriesFullIdentity(t *testing.T) {
	s, _, _, hdrs := artifactIdentityFixture(t)
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.ProvenancePath, "cas:") || rec.ProvenanceSHA256 == "" {
		t.Fatalf("provenance refs = %q/%q, want cas: digest", rec.ProvenancePath, rec.ProvenanceSHA256)
	}
	rc, _, err := s.CAS.Open(context.Background(), rec.ProvenanceSHA256)
	if err != nil {
		t.Fatalf("provenance not in CAS: %v", err)
	}
	envBytes, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	if err := provenance.Verify(env, s.provenance.Public); err != nil {
		t.Fatalf("provenance verify: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st provenance.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"repository": "github.com/o/repo-a",
		"ref":        "refs/heads/main",
		"commit":     "abc123",
		"job":        "build",
	}
	params := st.Predicate.BuildDefinition.ExternalParameters
	for k, v := range want {
		if got, _ := params[k].(string); got != v {
			t.Fatalf("provenance %s = %q, want %q", k, got, v)
		}
	}
	if len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != rec.SHA256 {
		t.Fatalf("provenance subject = %+v, want artifact digest %s", st.Subject, rec.SHA256)
	}
	if got := st.Predicate.RunDetails.Metadata.InvocationID; got != "run-c/job-a" {
		t.Fatalf("provenance invocationId = %q, want run-c/job-a", got)
	}
}

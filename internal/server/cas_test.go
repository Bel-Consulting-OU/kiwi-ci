package server

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestCASArtifactUploadDownloadDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if s.CAS == nil || s.BlobStore == nil {
		t.Fatal("DB-mode server must wire the CAS blob store")
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	payload := "cas-payload-bytes"
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", payload, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.Path, "cas:") {
		t.Fatalf("record path = %q, want cas:<digest>", rec.Path)
	}
	if rec.Path != "cas:"+rec.SHA256 {
		t.Fatalf("record path = %q, digest = %q", rec.Path, rec.SHA256)
	}
	// The payload bytes must live in the shared CAS store keyed by digest.
	rc, obj, err := s.CAS.Open(context.Background(), rec.SHA256)
	if err != nil {
		t.Fatalf("cas open: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(got) != payload {
		t.Fatalf("cas bytes = %q, err=%v", got, err)
	}
	if obj.SHA256 != rec.SHA256 {
		t.Fatalf("cas object digest = %q", obj.SHA256)
	}
	// The record in the SQL store carries the marker path (shared across
	// replicas), not a local file path.
	f.mu.Lock()
	stored := rec
	for _, a := range f.artifacts {
		if a.ID == rec.ID {
			stored = a
		}
	}
	f.mu.Unlock()
	if !strings.HasPrefix(stored.Path, "cas:") {
		t.Fatalf("stored record path = %q", stored.Path)
	}
	// Download resolves through CAS.
	w = doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID, "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("download = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != payload {
		t.Fatalf("download body = %q", w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Content-SHA256") != rec.SHA256 {
		t.Fatalf("download sha header = %q", w.Header().Get("X-Kiwi-Content-SHA256"))
	}
	// No legacy local file may be required for the download to work.
	legacy := filepath.Join(s.store.Root, "artifacts", rec.RunID, rec.JobID, rec.ID+".tar.gz")
	if _, err := os.Stat(legacy); err == nil {
		t.Fatalf("CAS mode must not write the legacy local file %s", legacy)
	}
}

func TestCASLegacyFileFallback(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Non-DB mode: uploads still land as legacy local files.
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	payload := "legacy-payload"
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", payload, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(rec.Path, "cas:") {
		t.Fatalf("fs-mode record path = %q, want a local file", rec.Path)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID, "token", "")
	if w.Code != http.StatusOK || w.Body.String() != payload {
		t.Fatalf("legacy download = %d: %q", w.Code, w.Body.String())
	}
	// openArtifact resolves an absolute local path directly.
	tmp := filepath.Join(t.TempDir(), "legacy.bin")
	if err := os.WriteFile(tmp, []byte("direct"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := s.openArtifact(context.Background(), model.ArtifactRecord{Path: tmp, SHA256: ""})
	if err != nil {
		t.Fatalf("openArtifact: %v", err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "direct" {
		t.Fatalf("openArtifact bytes = %q", b)
	}
	// A CAS-mode record whose blob backend is overridden resolves through
	// the injected store even without the local file.
	alt := cas.New(blob.NewFS(filepath.Join(t.TempDir(), "alt")))
	obj, err := alt.Put(context.Background(), strings.NewReader("alt-payload"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetBlobStore(alt.Blobs)
	rc, err = s.openArtifact(context.Background(), model.ArtifactRecord{Path: "cas:" + obj.SHA256, SHA256: obj.SHA256})
	if err != nil {
		t.Fatalf("openArtifact cas: %v", err)
	}
	b, _ = io.ReadAll(rc)
	rc.Close()
	if string(b) != "alt-payload" {
		t.Fatalf("cas openArtifact bytes = %q", b)
	}
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// snapshotCASServer builds a DB-mode server whose CAS backend is a
// filesystem blob store, and enqueues + leases a job.
func snapshotCASServer(t *testing.T, f *dbFakeStore, casDir string) (*Server, string, string, Task, *testClient) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.SetBlobStore(blob.NewFS(casDir))
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: testPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	c := newTestClient(t, s.Handler(), "token")
	return s, runnerID, task.Job.ID, task, c
}

func snapshotArchive(t *testing.T) ([]byte, string) {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("snapshot data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	m, err := snapshot.Create(ws, &buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), m.RootSHA256
}

func uploadSnapshotCAS(t *testing.T, c *testClient, jobID, runnerID string, task Task, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": fmt.Sprint(task.LeaseGeneration),
		"Content-Type":            "application/gzip",
	}
	return c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", body, headers)
}

// TestSnapshotUploadDBModeCASAndRecord proves the DB-mode upload stores the
// archive bytes in CAS and persists the record through SnapshotStore, and
// that a FRESH server instance on the same DB+CAS serves the download.
func TestSnapshotUploadDBModeCASAndRecord(t *testing.T) {
	f := newDBFakeStore()
	casDir := t.TempDir()
	s, runnerID, jobID, task, c := snapshotCASServer(t, f, casDir)
	runID := task.Job.RunID
	body, wantRoot := snapshotArchive(t)

	w := uploadSnapshotCAS(t, c, jobID, runnerID, task, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	var rec struct {
		ID         string `json:"id"`
		SHA256     string `json:"sha256"`
		Path       string `json:"path"`
		RootSHA256 string `json:"root_sha256"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Path != "" {
		t.Fatal("server-local path leaked in DB-mode upload response")
	}
	if rec.RootSHA256 != wantRoot {
		t.Fatalf("root sha = %q, want %q", rec.RootSHA256, wantRoot)
	}
	if len(rec.SHA256) != 64 {
		t.Fatalf("digest = %q, want sha256 hex", rec.SHA256)
	}

	// The record is persisted through SnapshotStore with a cas: path.
	f.mu.Lock()
	var stored model.SnapshotRecord
	for _, r := range f.snapshots {
		if r.ID == rec.ID {
			stored = r
		}
	}
	f.mu.Unlock()
	if stored.Path != "cas:"+rec.SHA256 {
		t.Fatalf("stored path = %q, want cas:%s", stored.Path, rec.SHA256)
	}

	// The bytes are in CAS under the digest.
	rc, obj, err := s.CAS.Open(context.Background(), rec.SHA256)
	if err != nil {
		t.Fatalf("CAS open: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("CAS bytes differ: got %d bytes, want %d", len(got), len(body))
	}
	if obj.Size != int64(len(body)) {
		t.Fatalf("CAS object size = %d, want %d", obj.Size, len(body))
	}

	// List reads from the SQL records.
	w = c.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body.String())
	}
	var listed []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed snapshots = %d, want 1", len(listed))
	}

	// A fresh server instance on the same store+CAS serves the download:
	// the in-memory map of s2 is empty, so the record must come from the
	// SnapshotStore and the bytes from CAS by digest.
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.SetBlobStore(blob.NewFS(casDir))
	c2 := newTestClient(t, s2.Handler(), "token")
	w = c2.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+rec.ID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("download from fresh replica = %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("downloaded bytes differ: got %d, want %d", w.Body.Len(), len(body))
	}
	if w.Header().Get("X-Kiwi-Snapshot-SHA256") != rec.SHA256 {
		t.Fatalf("download digest header = %q, want %q", w.Header().Get("X-Kiwi-Snapshot-SHA256"), rec.SHA256)
	}
}

// TestSnapshotUploadDBModeRecordFailureFailsClosed proves an insertion
// failure fails the upload (503) and removes the CAS blob again.
func TestSnapshotUploadDBModeRecordFailureFailsClosed(t *testing.T) {
	f := newDBFakeStore()
	casDir := t.TempDir()
	s, runnerID, jobID, task, c := snapshotCASServer(t, f, casDir)
	body, _ := snapshotArchive(t)

	f.mu.Lock()
	f.snapshotErr = fmt.Errorf("snapshot: injected failure")
	f.mu.Unlock()
	w := uploadSnapshotCAS(t, c, jobID, runnerID, task, body)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload with record failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	records := len(f.snapshots)
	f.mu.Unlock()
	if records != 0 {
		t.Fatalf("records persisted = %d, want 0", records)
	}
	// The orphaned CAS blob was removed again: no object files remain
	// under the blob store (the sha256/ prefix layout keeps empty dirs).
	var blobFiles []string
	_ = filepath.Walk(filepath.Join(casDir, "sha256"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			blobFiles = append(blobFiles, path)
		}
		return nil
	})
	if len(blobFiles) != 0 {
		t.Fatalf("CAS blobs left behind after failed record insert: %d files", len(blobFiles))
	}
	_ = s
}

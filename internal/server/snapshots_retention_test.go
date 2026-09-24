package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// uploadTestSnapshot uploads one small valid snapshot under the leased job
// and returns the recorder.
func uploadTestSnapshot(t *testing.T, c *testClient, jobID, runnerID, token string, gen int64) *httptest.ResponseRecorder {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("snapshot data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := snapshot.Create(ws, &buf); err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	}
	return c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", buf.Bytes(), headers)
}

// TestSnapshotPerJobCapRejectsWithoutStaging is the G2-D regression: the
// per-job snapshot count cap rejects the over-cap upload with 409 and leaves
// no staged file behind (the check runs before any staging/write).
func TestSnapshotPerJobCapRejectsWithoutStaging(t *testing.T) {
	prev := snapshotMaxPerJob
	SetSnapshotMaxPerJob(1)
	t.Cleanup(func() { SetSnapshotMaxPerJob(prev) })

	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)

	if w := uploadTestSnapshot(t, c, jobID, runnerID, token, gen); w.Code != http.StatusCreated {
		t.Fatalf("first upload: %d %s", w.Code, w.Body.String())
	}
	snapDir := filepath.Join(dir, "snapshots", runID, jobID)
	before, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	if w := uploadTestSnapshot(t, c, jobID, runnerID, token, gen); w.Code != http.StatusConflict {
		t.Fatalf("over-cap upload: %d %s, want 409", w.Code, w.Body.String())
	}
	after, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("over-cap upload staged files: before=%d after=%d", len(before), len(after))
	}
	for _, e := range after {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("over-cap upload left a temp file %q", e.Name())
		}
	}
}

// TestDeleteSnapshotUnrefsBlob is the G2-D retention half: deleting a record
// removes it from the live reference set so the reference-aware GC can
// reclaim its CAS blob, while a wrong-run id is a no-op.
func TestDeleteSnapshotUnrefsBlob(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	keep := strings.Repeat("b", 64)
	s.mu.Lock()
	s.snapshots["snap-1"] = model.SnapshotRecord{ID: "snap-1", RunID: "run-1", JobID: "job-1", Path: "cas:" + digest, SHA256: digest, RootSHA256: digest}
	s.snapshots["snap-2"] = model.SnapshotRecord{ID: "snap-2", RunID: "run-1", JobID: "job-2", Path: "cas:" + keep, SHA256: keep, RootSHA256: keep}
	s.mu.Unlock()

	ctx := context.Background()
	refs, err := s.collectCASReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := refs[digest]; !ok {
		t.Fatal("digest not referenced before deletion")
	}
	if ok, err := s.DeleteSnapshot(ctx, "run-other", "snap-1"); err != nil || ok {
		t.Fatalf("wrong-run delete = (%v,%v), want (false,nil)", ok, err)
	}
	if ok, err := s.DeleteSnapshot(ctx, "run-1", "snap-1"); err != nil || !ok {
		t.Fatalf("delete = (%v,%v), want (true,nil)", ok, err)
	}
	refs, err = s.collectCASReferences(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := refs[digest]; ok {
		t.Fatal("deleted snapshot still references its blob")
	}
	if _, ok := refs[keep]; !ok {
		t.Fatal("unrelated snapshot lost its reference")
	}
}

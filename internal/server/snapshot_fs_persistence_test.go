package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// uploadFsSnapshot submits a valid archive under the job's lease and returns
// the created record ID and the archive bytes.
func uploadFsSnapshot(t *testing.T, c *testClient, jobID string, headers map[string]string) (string, []byte) {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("durable snapshot data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := snapshot.Create(ws, &buf); err != nil {
		t.Fatal(err)
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", buf.Bytes(), headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" {
		t.Fatal("uploaded snapshot has no id")
	}
	return rec.ID, buf.Bytes()
}

// TestSnapshotFsDurableRestartRoundTrip proves the fs-mode snapshot record is
// part of the durable state: after a restart on the same data dir the record
// is restored, listed, and its archive still downloads byte-identically.
func TestSnapshotFsDurableRestartRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	}
	recID, archive := uploadFsSnapshot(t, c, jobID, headers)

	// Restart on the same data dir: the record is reconstructed from the
	// state snapshot, not from the process's memory.
	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	rec, ok := s2.snapshots[recID]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("snapshot record not restored after restart")
	}
	if rec.RunID != runID || rec.JobID != jobID || rec.Size != int64(len(archive)) {
		t.Fatalf("restored record wrong: %+v", rec)
	}

	c2 := newTestClient(t, s2.Handler(), "secret")
	w := c2.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list after restart: %d %s", w.Code, w.Body.String())
	}
	var listed []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != recID {
		t.Fatalf("listed after restart = %+v, want the restored record", listed)
	}
	w = c2.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+recID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("download after restart: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), archive) {
		t.Fatalf("downloaded archive differs from the uploaded bytes: got %d bytes, want %d", w.Body.Len(), len(archive))
	}
}

// TestSnapshotFsMissingArchiveDroppedAtLoad proves a record whose archive was
// deleted is dropped at load (with a log) instead of being resurrected as a
// broken entry, and the pruned set is persisted back.
func TestSnapshotFsMissingArchiveDroppedAtLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	recID, _ := uploadFsSnapshot(t, c, jobID, map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	})
	s.mu.Lock()
	archivePath := s.snapshots[recID].Path
	s.mu.Unlock()
	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}

	dropped := []string{}
	oldDrop := snapshotRestoreDropped
	snapshotRestoreDropped = func(_ *Server, id string, _ error) { dropped = append(dropped, id) }
	t.Cleanup(func() { snapshotRestoreDropped = oldDrop })

	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != recID {
		t.Fatalf("dropped records = %v, want one %s", dropped, recID)
	}
	if len(s2.snapshots) != 0 {
		t.Fatalf("orphaned snapshot record resurrected: %+v", s2.snapshots)
	}
	// The pruned set was written back: a second restart never sees the
	// broken record again.
	snap, err := storage.New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Snapshots) != 0 {
		t.Fatalf("durable state still lists the dropped record: %+v", snap.Snapshots)
	}
}

// TestSnapshotFsTamperedArchiveDroppedAtLoad proves digest validation at
// load: an archive whose bytes no longer match the record is dropped.
func TestSnapshotFsTamperedArchiveDroppedAtLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	recID, archive := uploadFsSnapshot(t, c, jobID, map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	})
	s.mu.Lock()
	archivePath := s.snapshots[recID].Path
	s.mu.Unlock()
	tampered := append([]byte(nil), archive...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(archivePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	dropped := []string{}
	oldDrop := snapshotRestoreDropped
	snapshotRestoreDropped = func(_ *Server, id string, _ error) { dropped = append(dropped, id) }
	t.Cleanup(func() { snapshotRestoreDropped = oldDrop })

	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != recID {
		t.Fatalf("dropped records = %v, want one %s", dropped, recID)
	}
	if len(s2.snapshots) != 0 {
		t.Fatalf("tampered snapshot record resurrected: %+v", s2.snapshots)
	}
}

// TestSnapshotFsMissingManifestDroppedAtLoad proves a record whose manifest
// sidecar was deleted is dropped (the manifest is part of the durable pair).
func TestSnapshotFsMissingManifestDroppedAtLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	recID, _ := uploadFsSnapshot(t, c, jobID, map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	})
	s.mu.Lock()
	manifestPath := s.snapshots[recID].Path + ".manifest.json"
	s.mu.Unlock()
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	dropped := []string{}
	oldDrop := snapshotRestoreDropped
	snapshotRestoreDropped = func(_ *Server, id string, _ error) { dropped = append(dropped, id) }
	t.Cleanup(func() { snapshotRestoreDropped = oldDrop })

	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0] != recID {
		t.Fatalf("dropped records = %v, want one %s", dropped, recID)
	}
	if len(s2.snapshots) != 0 {
		t.Fatalf("manifest-less snapshot record resurrected: %+v", s2.snapshots)
	}
}

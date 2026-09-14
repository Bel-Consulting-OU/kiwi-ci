package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// uploadSnapshot is POST /api/v1/jobs/{id}/snapshots: the runner uploads a
// workspace snapshot tar.gz under its active lease. The archive is stored
// under the server data dir (snapshots/<runID>/<jobID>.tar.gz) together
// with a manifest sidecar, and the record is kept in memory (DB persistence
// is deferred — see the report's deferred items).
func (s *Server) uploadSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "snapshot storage requires persistent server", http.StatusServiceUnavailable)
		return
	}
	jobID := r.PathValue("id")
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	now := time.Now().UTC()
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.validActiveLease(j, runnerID, token, gen, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	dir := filepath.Join(s.store.Root, "snapshots", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	tmp := filepath.Join(dir, "."+id+".tmp")
	dst := filepath.Join(dir, id+".tar.gz")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, maxBlobBytes))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	// Build the manifest by scanning the stored archive (no extraction, no
	// trust in client-supplied metadata).
	af, err := os.Open(dst)
	if err != nil {
		_ = os.Remove(dst)
		http.Error(w, err.Error(), 500)
		return
	}
	m, err := snapshot.Parse(af)
	af.Close()
	if err != nil {
		_ = os.Remove(dst)
		http.Error(w, "invalid snapshot archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(dst+".manifest.json", mb, 0o600)
	rec := model.SnapshotRecord{
		ID:         id,
		RunID:      j.RunID,
		JobID:      j.ID,
		JobKey:     j.Key,
		Path:       dst,
		Size:       n,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		Version:    m.Version,
		RootSHA256: m.RootSHA256,
		CreatedAt:  time.Now().UTC(),
	}
	for _, e := range m.Entries {
		rec.Entries = append(rec.Entries, model.SnapshotEntry{Path: e.Path, Mode: e.Mode, Size: e.Size, SHA256: e.SHA256})
	}
	s.mu.Lock()
	s.snapshots[id] = rec
	s.auditLocked("snapshot.uploaded", runnerID, j.RunID, j.ID, "workspace snapshot uploaded", map[string]string{"sha256": rec.SHA256})
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, redactSnapshot(rec))
}

// listSnapshots is GET /api/v1/runs/{id}/snapshots: the manifests of every
// snapshot uploaded by the run's jobs.
func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DB != nil {
		if _, err := s.DB.GetRun(r.Context(), runID); errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else if _, ok := s.runs[runID]; !ok {
		http.NotFound(w, r)
		return
	}
	out := []model.SnapshotRecord{}
	for _, rec := range s.snapshots {
		if rec.RunID == runID {
			out = append(out, redactSnapshot(rec))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// redactSnapshot strips the server-local archive path before a record
// leaves the control plane.
func redactSnapshot(rec model.SnapshotRecord) model.SnapshotRecord {
	rec.Path = ""
	return rec
}

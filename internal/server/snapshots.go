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
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// uploadSnapshot is POST /api/v1/jobs/{id}/snapshots: the runner uploads a
// workspace snapshot tar.gz under its active lease. In memory mode the
// archive is stored under the server data dir (snapshots/<runID>/<jobID>)
// with a manifest sidecar and the record lives in the in-memory map. In DB
// mode the archive bytes go into CAS (content-addressed, digest-addressed
// for any replica) and the record is persisted through SnapshotStore in the
// same flow; a record-insertion failure fails the upload (503) instead of
// logging, and the in-memory map is not the source of truth.
func (s *Server) uploadSnapshot(w http.ResponseWriter, r *http.Request) {
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	j, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "snapshot storage requires a CAS blob store in DB mode", http.StatusServiceUnavailable)
			return
		}
		s.uploadSnapshotDB(w, r, j, runnerID)
		return
	}
	if s.store == nil {
		http.Error(w, "snapshot storage requires persistent server", http.StatusServiceUnavailable)
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
	s.mu.Unlock()
	// The audit trail records the digest, never the archive contents.
	s.auditLocked("snapshot.uploaded", runnerID, j.RunID, j.ID, "workspace snapshot uploaded", map[string]string{"sha256": rec.SHA256})
	writeJSON(w, http.StatusCreated, redactSnapshot(rec))
}

// uploadSnapshotDB is the DB-mode upload: the archive bytes are stored in
// CAS and the record is inserted through SnapshotStore in the same flow.
// Insertion failure fails the upload (503) and removes the orphaned CAS
// blob; a CAS failure fails the upload (503). The record's Path is the
// cas:<digest> reference, so any replica resolves the archive by digest.
func (s *Server) uploadSnapshotDB(w http.ResponseWriter, r *http.Request, j model.Job, runnerID string) {
	ctx := r.Context()
	tmp, err := os.CreateTemp("", "kiwi-snapshot-*")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, maxBlobBytes))
	if err := firstErr(copyErr); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	m, err := snapshot.Parse(tmp)
	if err != nil {
		http.Error(w, "invalid snapshot archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	obj, err := s.CAS.Put(ctx, tmp)
	if err != nil {
		http.Error(w, "snapshot storage failed", http.StatusServiceUnavailable)
		return
	}
	rec := model.SnapshotRecord{
		ID:         id,
		RunID:      j.RunID,
		JobID:      j.ID,
		JobKey:     j.Key,
		Path:       "cas:" + obj.SHA256,
		Size:       n,
		SHA256:     obj.SHA256,
		Version:    m.Version,
		RootSHA256: m.RootSHA256,
		CreatedAt:  time.Now().UTC(),
	}
	for _, e := range m.Entries {
		rec.Entries = append(rec.Entries, model.SnapshotEntry{Path: e.Path, Mode: e.Mode, Size: e.Size, SHA256: e.SHA256})
	}
	ss, ok := s.DB.(storage.SnapshotStore)
	if !ok {
		_ = s.CAS.Delete(ctx, obj.SHA256)
		http.Error(w, "snapshot record storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := ss.InsertSnapshotRecord(ctx, rec); err != nil {
		// Fail the upload instead of logging: a snapshot whose record is
		// not durable must not be acknowledged. The orphaned CAS blob is
		// removed again so retries re-put the same digest.
		if derr := s.CAS.Delete(ctx, obj.SHA256); derr != nil {
			s.logError("snapshot: CAS cleanup after record failure", "error", derr.Error())
		}
		http.Error(w, "snapshot record persistence failed", http.StatusServiceUnavailable)
		return
	}
	s.auditLocked("snapshot.uploaded", runnerID, j.RunID, j.ID, "workspace snapshot uploaded", map[string]string{"sha256": rec.SHA256})
	writeJSON(w, http.StatusCreated, redactSnapshot(rec))
}

// listSnapshots is GET /api/v1/runs/{id}/snapshots: the manifests of every
// snapshot uploaded by the run's jobs. DB mode reads the SQL records
// (SnapshotStore) as the single source of truth; memory mode reads the
// in-memory map.
func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out := []model.SnapshotRecord{}
		if ss, ok := s.DB.(storage.SnapshotStore); ok {
			recs, err := ss.ListSnapshotsByRun(r.Context(), runID)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			for _, rec := range recs {
				out = append(out, redactSnapshot(rec))
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
		writeJSON(w, http.StatusOK, out)
		return
	}
	run, ok := s.runs[runID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
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

// downloadSnapshot is GET /api/v1/runs/{id}/snapshots/{sid}: streams one
// uploaded workspace snapshot archive for replay/debugging (admin tier).
// DB mode resolves the record through SnapshotStore and the bytes from CAS
// by digest (any replica); memory mode streams the node-local archive.
func (s *Server) downloadSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.DB != nil {
		s.downloadSnapshotDB(w, r)
		return
	}
	sid := r.PathValue("sid")
	s.mu.Lock()
	rec, ok := s.snapshots[sid]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rec.RunID != r.PathValue("id") {
		http.NotFound(w, r)
		return
	}
	run, err := s.runForAuth(r.Context(), rec.RunID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	f, err := os.Open(rec.Path)
	if err != nil {
		http.Error(w, "snapshot archive missing", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	w.Header().Set("X-Kiwi-Snapshot-SHA256", rec.SHA256)
	if _, err := io.Copy(w, f); err != nil {
		s.logf("snapshot download: %v", err)
	}
}

// downloadSnapshotDB streams one snapshot in DB mode: the record comes
// from the SnapshotStore (not the in-memory map) and the archive bytes
// from CAS by digest, so a fresh replica with the same store+CAS serves
// the download. Records with a node-local Path (legacy) fall back to the
// local file.
func (s *Server) downloadSnapshotDB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID := r.PathValue("id")
	sid := r.PathValue("sid")
	run, err := s.DB.GetRun(ctx, runID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	ss, ok := s.DB.(storage.SnapshotStore)
	if !ok {
		http.NotFound(w, r)
		return
	}
	recs, err := ss.ListSnapshotsByRun(ctx, runID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var rec model.SnapshotRecord
	found := false
	for _, c := range recs {
		if c.ID == sid {
			rec = c
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(rec.Path, "cas:") {
		digest := strings.TrimPrefix(rec.Path, "cas:")
		rc, obj, err := s.CAS.Open(ctx, digest)
		if err != nil {
			http.Error(w, "snapshot archive missing", http.StatusNotFound)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(obj.Size, 10))
		w.Header().Set("X-Kiwi-Snapshot-SHA256", digest)
		if _, err := io.Copy(w, rc); err != nil {
			s.logf("snapshot download: %v", err)
		}
		return
	}
	if rec.Path != "" {
		f, err := os.Open(rec.Path)
		if err != nil {
			http.Error(w, "snapshot archive missing", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
		w.Header().Set("X-Kiwi-Snapshot-SHA256", rec.SHA256)
		if _, err := io.Copy(w, f); err != nil {
			s.logf("snapshot download: %v", err)
		}
		return
	}
	http.NotFound(w, r)
}

// redactSnapshot strips the server-local archive path before a record
// leaves the control plane.
func redactSnapshot(rec model.SnapshotRecord) model.SnapshotRecord {
	rec.Path = ""
	return rec
}

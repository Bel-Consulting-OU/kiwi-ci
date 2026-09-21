package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// snapshotUploadMaxBytes is the receiver's HTTP body cap for snapshot
// uploads: the ONE shared compressed snapshot archive budget
// (snapshot.MaxArchiveBytes) the runner's capture cap is clamped to and
// snapshot.Parse enforces. It is a variable so tests can exercise the
// boundary with small bodies instead of generating GiBs; production leaves
// it at the shared constant.
var snapshotUploadMaxBytes = snapshot.MaxArchiveBytes

// isSnapshotBodyTooLarge reports whether a body copy failed because the
// request exceeded snapshotUploadMaxBytes (http.MaxBytesReader), so the
// handler can answer 413 with a clear snapshot-archive reason instead of an
// opaque 500.
func isSnapshotBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// snapshotTooLargeError renders the shared body-cap rejection.
func snapshotTooLargeError() string {
	return fmt.Sprintf("snapshot archive exceeds the %d-byte upload limit", snapshotUploadMaxBytes)
}

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
		s.internalError(w, r, err, "")
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
		s.internalError(w, r, err, "")
		return
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, snapshotUploadMaxBytes))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		if isSnapshotBodyTooLarge(err) {
			http.Error(w, snapshotTooLargeError(), http.StatusRequestEntityTooLarge)
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		s.internalError(w, r, err, "")
		return
	}
	// The rename is only durable once the parent directory is fsynced.
	if err := storage.SyncDir(dir); err != nil {
		_ = os.Remove(dst)
		s.internalError(w, r, err, "")
		return
	}
	// Build the manifest by scanning the stored archive (no extraction, no
	// trust in client-supplied metadata).
	af, err := os.Open(dst)
	if err != nil {
		_ = os.Remove(dst)
		s.internalError(w, r, err, "")
		return
	}
	m, err := snapshot.Parse(af)
	af.Close()
	if err != nil {
		_ = os.Remove(dst)
		http.Error(w, "invalid snapshot archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		_ = os.Remove(dst)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// The manifest sidecar is part of the durable archive pair: write it
	// through the checked atomic writer before the record is committed.
	if err := storage.AtomicWriteFile(dst+".manifest.json", mb, 0o600); err != nil {
		_ = os.Remove(dst)
		s.internalError(w, r, err, "")
		return
	}
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
	// Commit the authoritative record only after the archive and manifest
	// are durably stored, and only acknowledge the upload once the record
	// itself is durable in the state snapshot. A failed state write removes
	// the in-memory record and the unreferenced files, so the runner can
	// retry instead of losing the snapshot silently.
	s.mu.Lock()
	s.snapshots[id] = rec
	persistErr := s.persistLocked()
	if persistErr != nil {
		delete(s.snapshots, id)
	}
	s.mu.Unlock()
	if persistErr != nil {
		_ = os.Remove(dst)
		_ = os.Remove(dst + ".manifest.json")
		http.Error(w, "snapshot record persistence failed", http.StatusServiceUnavailable)
		return
	}
	// The audit trail records the digest, never the archive contents.
	s.auditLocked("snapshot.uploaded", runnerID, j.RunID, j.ID, "workspace snapshot uploaded", map[string]string{"sha256": rec.SHA256})
	writeJSON(w, http.StatusCreated, redactSnapshot(rec))
}

// snapshotRestoreDropped is a test seam over the log line emitted when a
// durable snapshot record fails load validation. Production logs through the
// server logger; tests capture the drop calls.
var snapshotRestoreDropped = func(s *Server, id string, err error) {
	s.logError("snapshot record dropped at load", "snapshot", id, "error", err.Error())
}

// restoreSnapshots installs the durable fs-mode snapshot records after
// validating every referenced archive/manifest pair. A record whose files
// are missing, truncated, altered, or inconsistent with its manifest is
// dropped (and logged) instead of resurrecting a broken entry; the next
// state write persists the pruned set.
func (s *Server) restoreSnapshots(recs map[string]model.SnapshotRecord) {
	out := make(map[string]model.SnapshotRecord, len(recs))
	for id, rec := range recs {
		if err := validateSnapshotFiles(rec); err != nil {
			snapshotRestoreDropped(s, id, err)
			continue
		}
		out[id] = rec
	}
	s.snapshots = out
}

// validateSnapshotFiles checks one fs-mode snapshot record against the
// files it references: the archive must exist, have the recorded size and
// SHA-256, and its manifest sidecar must exist and decode to the recorded
// version and root digest.
func validateSnapshotFiles(rec model.SnapshotRecord) error {
	if rec.ID == "" {
		return errors.New("empty snapshot id")
	}
	if rec.Path == "" {
		return errors.New("empty snapshot archive path")
	}
	f, err := os.Open(rec.Path)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if err := firstErr(copyErr, closeErr); err != nil {
		return err
	}
	if n != rec.Size {
		return fmt.Errorf("archive size %d does not match record %d", n, rec.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != rec.SHA256 {
		return fmt.Errorf("archive digest %s does not match record %s", got, rec.SHA256)
	}
	mb, err := os.ReadFile(rec.Path + ".manifest.json")
	if err != nil {
		return fmt.Errorf("manifest sidecar: %w", err)
	}
	var m snapshot.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return fmt.Errorf("manifest decode: %w", err)
	}
	if m.Version != rec.Version || m.RootSHA256 != rec.RootSHA256 {
		return fmt.Errorf("manifest version=%d root=%s does not match record version=%d root=%s",
			m.Version, m.RootSHA256, rec.Version, rec.RootSHA256)
	}
	return nil
}

// uploadSnapshotDB is the DB-mode upload: the archive bytes are stored in
// CAS and the record is inserted through SnapshotStore in the same flow.
// Insertion failure fails the upload (503); the already written CAS blob is
// left as an orphan for the reference-aware blob GC — never deleted,
// because a failed metadata persist must not remove a digest another
// record may reference. The record's Path is the cas:<digest> reference,
// so any replica resolves the archive by digest.
func (s *Server) uploadSnapshotDB(w http.ResponseWriter, r *http.Request, j model.Job, runnerID string) {
	ctx := r.Context()
	tmp, err := os.CreateTemp("", "kiwi-snapshot-*")
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, snapshotUploadMaxBytes))
	if err := firstErr(copyErr); err != nil {
		if isSnapshotBodyTooLarge(copyErr) {
			http.Error(w, snapshotTooLargeError(), http.StatusRequestEntityTooLarge)
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		s.internalError(w, r, err, "")
		return
	}
	m, err := snapshot.Parse(tmp)
	if err != nil {
		http.Error(w, "invalid snapshot archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		s.internalError(w, r, err, "")
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Publish + record commit under the digest fence (the collector re-reads
	// references under the same fence). The digest is only known after Put,
	// so the staging temp file is hashed here first; a matching CAS.Put is
	// idempotent.
	stagedSum, sumErr := fileSHA256(tmp.Name())
	if sumErr != nil {
		s.internalError(w, r, sumErr, "")
		return
	}
	releaseSnap, fenceErr := s.acquireDigestFence(ctx, stagedSum)
	if fenceErr != nil {
		s.internalError(w, r, fenceErr, "")
		return
	}
	defer releaseSnap()
	obj, err := s.CAS.Put(ctx, tmp)
	if err != nil {
		http.Error(w, "snapshot storage failed", http.StatusServiceUnavailable)
		return
	}
	// Read-back verification: the bytes must be complete and content-
	// addressed exactly as streamed. A store that truncated or altered the
	// archive (obj digest/size disagreeing with the request hash, or the
	// stored object failing the CAS digest check on re-read) fails the
	// upload instead of being acknowledged; the unreferenced blob is left
	// for the reference-aware GC.
	wantSHA := hex.EncodeToString(h.Sum(nil))
	if obj.SHA256 != wantSHA || obj.Size != n {
		http.Error(w, "snapshot storage verification failed", http.StatusServiceUnavailable)
		return
	}
	if err := verifyStoredSnapshot(ctx, s.CAS, wantSHA, n); err != nil {
		s.logf("snapshot upload: stored archive verification failed: %v", err)
		http.Error(w, "snapshot storage verification failed", http.StatusServiceUnavailable)
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
		http.Error(w, "snapshot record storage unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := ss.InsertSnapshotRecord(ctx, rec); err != nil {
		// Fail the upload instead of logging: a snapshot whose record is
		// not durable must not be acknowledged. The CAS blob is left in
		// place as an orphan (content-addressed, possibly referenced by
		// another record); the reference-aware GC reclaims it.
		http.Error(w, "snapshot record persistence failed", http.StatusServiceUnavailable)
		return
	}
	s.auditLocked("snapshot.uploaded", runnerID, j.RunID, j.ID, "workspace snapshot uploaded", map[string]string{"sha256": rec.SHA256})
	writeJSON(w, http.StatusCreated, redactSnapshot(rec))
}

// verifyStoredSnapshot opens a just-written CAS object and re-hashes it,
// guaranteeing the stored archive matches the size and digest computed while
// the request body was streamed. CAS.Open already verifies the digest while
// streaming; this read-back additionally proves the object is readable and
// its size is what the record will advertise.
func verifyStoredSnapshot(ctx context.Context, c *cas.CAS, digest string, wantSize int64) error {
	rc, obj, err := c.Open(ctx, digest)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, rc)
	closeErr := rc.Close()
	if err := firstErr(copyErr, closeErr); err != nil {
		return err
	}
	if n != wantSize || obj.Size != wantSize {
		return fmt.Errorf("stored snapshot size %d (object %d), want %d", n, obj.Size, wantSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("stored snapshot digest %s, want %s", got, digest)
	}
	return nil
}

// snapshotListMemoryLock is a test seam invoked immediately before
// listSnapshots takes s.mu to copy the memory-mode records. DB-mode tests
// assert the hook is never reached, pinning the contract that the DB branch
// does not touch the global server mutex. Production leaves it a no-op.
var snapshotListMemoryLock = func() {}

// requireRunAdmin enforces the admin action for the workspace snapshot
// archive download, scoped by the run's canonical policy identity
// (repoIDForRun). The repository resolution keeps the decision anchored to
// the addressed run instead of a blanket gate, while auth.Authorize makes
// ActionAdmin unsatisfiable by any repository grant: only the global admin
// role (or the admin token, which carries no principal) passes. A
// non-admin authenticated principal is answered 403 by requireAction.
func (s *Server) requireRunAdmin(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	return s.requireAction(w, r, auth.ActionAdmin, repoIDForRun(run), false)
}

// listSnapshots is GET /api/v1/runs/{id}/snapshots: the manifests of every
// snapshot uploaded by the run's jobs. The metadata listing is read tier
// (requireRunRead): the records carry no archive contents and no local path
// (redactSnapshot strips it). Only the archive DOWNLOAD is admin tier.
// DB mode reads the SQL records
// (SnapshotStore) as the single source of truth; memory mode reads the
// in-memory map. Neither mode holds s.mu across a store call, response
// serialization or a client write: the DB branch touches no in-memory state,
// and the memory branch copies the run and its matching records under the
// lock, releases it, and only then sorts and serializes — a slow PostgreSQL
// or a slow client can never stall unrelated control-plane operations.
func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out := []model.SnapshotRecord{}
		if ss, ok := s.DB.(storage.SnapshotStore); ok {
			recs, err := ss.ListSnapshotsByRun(r.Context(), runID)
			if err != nil {
				s.internalError(w, r, err, "")
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
	// Memory mode: resolve the run and copy only its records under the lock,
	// then redact, sort and serialize outside it.
	snapshotListMemoryLock()
	s.mu.Lock()
	run, ok := s.runs[runID]
	var out []model.SnapshotRecord
	if ok {
		out = s.snapshotRecordsForRunLocked(runID)
	}
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	redacted := make([]model.SnapshotRecord, 0, len(out))
	for _, rec := range out {
		redacted = append(redacted, redactSnapshot(rec))
	}
	sort.Slice(redacted, func(i, j int) bool { return redacted[i].CreatedAt.Before(redacted[j].CreatedAt) })
	writeJSON(w, http.StatusOK, redacted)
}

// snapshotRecordsForRunLocked copies the in-memory snapshot records of one
// run into a fresh non-nil slice. s.mu must be held; the caller is
// responsible for releasing it before sorting or serializing.
func (s *Server) snapshotRecordsForRunLocked(runID string) []model.SnapshotRecord {
	out := make([]model.SnapshotRecord, 0, len(s.snapshots))
	for _, rec := range s.snapshots {
		if rec.RunID == runID {
			out = append(out, rec)
		}
	}
	return out
}

// downloadSnapshot is GET /api/v1/runs/{id}/snapshots/{sid}: streams one
// uploaded workspace snapshot archive for replay/debugging (admin tier). The
// archive is the full private workspace (checkout, generated and
// secret-derived files), so the download demands the admin action
// (requireRunAdmin, auth.ActionAdmin) — a repository read or artifact_read
// grant is not enough — while the route map in auth.ActionFor classifies
// exactly this path as ActionAdmin. The decision is scoped to the run's
// canonical repository identity (repoIDForRun) and the record must belong to
// the addressed run. DB mode resolves the record through SnapshotStore and
// the bytes from CAS by digest (any replica); memory mode streams the
// node-local archive.
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
	if !s.requireRunAdmin(w, r, run) {
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
// the download. Like the memory path it is admin tier — requireRunAdmin
// resolves the run's canonical repository before the admin decision — and
// records with a node-local Path (legacy) fall back to the local file.
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
		s.internalError(w, r, err, "")
		return
	}
	if !s.requireRunAdmin(w, r, run) {
		return
	}
	ss, ok := s.DB.(storage.SnapshotStore)
	if !ok {
		http.NotFound(w, r)
		return
	}
	recs, err := ss.ListSnapshotsByRun(ctx, runID)
	if err != nil {
		s.internalError(w, r, err, "")
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

// fileSHA256 hashes a staged file so the digest fence can be taken before
// the object is published to CAS.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// snapshotUploadMaxBytes is the receiver's HTTP body cap for snapshot
// uploads: the ONE shared compressed snapshot archive budget
// (snapshot.MaxArchiveBytes) the runner's capture cap is clamped to and
// snapshot.Parse enforces. It is a variable so tests can exercise the
// boundary with small bodies instead of generating GiBs; production leaves
// it at the shared constant.
var snapshotUploadMaxBytes = snapshot.MaxArchiveBytes

// DefaultSnapshotMaxPerJob bounds how many snapshot records one (run, job)
// pair may retain. Each record pins its archive blob in CAS until the record
// is deleted (the reference-aware GC treats records as live references), so
// an unbounded per-job snapshot history would pin arbitrary storage forever.
// The cap is enforced BEFORE any staging reservation, directory creation or
// archive write, so a rejected upload leaves no staging artifact behind.
// Repository is implied by the run/job: a job's repository cannot change, so
// a per-(run, job) cap is the per-(run, job, repository) bound.
const DefaultSnapshotMaxPerJob = 32

// snapshotMaxPerJob is the effective per-job snapshot cap. It is a package
// var so tests and embedders can override it without a config-file change;
// production keeps DefaultSnapshotMaxPerJob. A value <= 0 disables the cap.
var snapshotMaxPerJob = DefaultSnapshotMaxPerJob

// SetSnapshotMaxPerJob overrides the per-job snapshot cap (0 or negative
// disables it). It exists so operators/tests can tighten the documented
// default without a config-file schema change.
func SetSnapshotMaxPerJob(n int) { snapshotMaxPerJob = n }

// snapshotDeleteStore is the optional durable deletion capability. A store
// that implements it can remove one snapshot record by its (run_id, id)
// identity; a store without it fails the admin deletion closed rather than
// silently leaving the record (and its pinned blob) in place.
type snapshotDeleteStore interface {
	DeleteSnapshotRecord(ctx context.Context, runID, snapshotID string) (bool, error)
}

// errSnapshotStoreUnavailable is reported when a DB store lacks the
// SnapshotStore capability: the cap check delegates to the same fail-closed
// 503 the upload path uses.
var errSnapshotStoreUnavailable = errors.New("snapshot record storage unavailable")

// snapshotCountForJob returns how many snapshot records the (run, job) pair
// currently holds. DB mode reads the run's records through SnapshotStore;
// memory mode counts the in-memory mirror.
func (s *Server) snapshotCountForJob(ctx context.Context, runID, jobID string) (int, error) {
	if s.DB != nil {
		ss, ok := s.DB.(storage.SnapshotStore)
		if !ok {
			return 0, errSnapshotStoreUnavailable
		}
		recs, err := ss.ListSnapshotsByRun(ctx, runID)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, rec := range recs {
			if rec.JobID == jobID {
				n++
			}
		}
		return n, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rec := range s.snapshots {
		if rec.RunID == runID && rec.JobID == jobID {
			n++
		}
	}
	return n, nil
}

// DeleteSnapshot is the admin retention/deletion path: it removes one
// snapshot record (scoped to its run) so the record stops pinning its CAS
// blob, which the reference-aware GC then reclaims once no other record
// references the digest. Node-local archive files are removed best-effort;
// the CAS object is NEVER deleted here because it is content-addressed and
// may be shared (deletion belongs to GC). It returns ok=false when no record
// with that (run, id) exists. In DB mode the store must implement
// snapshotDeleteStore or the call fails closed.
func (s *Server) DeleteSnapshot(ctx context.Context, runID, snapshotID string) (bool, error) {
	if runID == "" || snapshotID == "" {
		return false, nil
	}
	if s.DB != nil {
		del, ok := s.DB.(snapshotDeleteStore)
		if !ok {
			return false, fmt.Errorf("snapshot deletion unsupported by configured store")
		}
		return del.DeleteSnapshotRecord(ctx, runID, snapshotID)
	}
	s.mu.Lock()
	rec, ok := s.snapshots[snapshotID]
	if !ok || rec.RunID != runID {
		s.mu.Unlock()
		return false, nil
	}
	delete(s.snapshots, snapshotID)
	if err := s.persistLocked(); err != nil {
		// Keep the record (and therefore the blob reference) when the
		// durable state write fails, so a restart cannot resurrect a
		// deleted-but-still-referenced record or lose the tombstone.
		s.snapshots[snapshotID] = rec
		s.mu.Unlock()
		return false, err
	}
	s.mu.Unlock()
	if rec.Path != "" && !strings.HasPrefix(rec.Path, "cas:") {
		_ = os.Remove(rec.Path)
		_ = os.Remove(rec.Path + ".manifest.json")
	}
	return true, nil
}

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

// Snapshot staging integration (L4-C).
//
// DB-mode uploads spool the archive through the server's shared bounded
// staging budget (Server.Staging, see server.go and staging.go) instead of
// the bare system temporary directory: the reservation is taken BEFORE the
// request body is accepted, so concurrent valid runners can never stage more
// bytes than the configured bound, and the startup prune (part of the
// constructor / app wiring) reclaims files abandoned by a crashed process.
// Production refuses startup without an explicit staging.dir and
// staging.max_bytes (internal/config validateStaging plus the app wiring's
// production check); a server without an installed budget fails the upload
// closed with 503.

// snapshotStagingReserve reports how many staging bytes to reserve BEFORE the
// request body is accepted: the declared Content-Length when the client
// announced a positive one, otherwise the endpoint maximum (the worst case
// the request can still stream). A declared length above the endpoint cap is
// refused outright, so a lying client can neither stage past the endpoint cap
// nor past its own declaration (the body reader is capped at the reserved
// amount).
func snapshotStagingReserve(r *http.Request) (int64, bool) {
	if r.ContentLength > snapshotUploadMaxBytes {
		return 0, false
	}
	if r.ContentLength > 0 {
		return r.ContentLength, true
	}
	return snapshotUploadMaxBytes, true
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
	// Retention bound: refuse BEFORE taking a staging reservation, creating
	// a directory or writing a byte, so an over-cap upload leaves no stage
	// file and no orphan blob. The record's CAS blob stays pinned until an
	// admin deletes the record (DeleteSnapshot), after which the
	// reference-aware GC reclaims it.
	if snapshotMaxPerJob > 0 {
		n, cerr := s.snapshotCountForJob(r.Context(), j.RunID, j.ID)
		if cerr != nil {
			if errors.Is(cerr, errSnapshotStoreUnavailable) {
				http.Error(w, "snapshot record storage unavailable", http.StatusServiceUnavailable)
				return
			}
			s.internalError(w, r, cerr, "")
			return
		}
		if n >= snapshotMaxPerJob {
			http.Error(w, fmt.Sprintf("snapshot count limit reached for this job (max %d)", snapshotMaxPerJob), http.StatusConflict)
			return
		}
	}
	if s.DB != nil {
		if s.CAS == nil {
			http.Error(w, "snapshot storage requires a CAS blob store in DB mode", http.StatusServiceUnavailable)
			return
		}
		s.uploadSnapshotDB(w, r, j, runnerID, gen)
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
	// Commit-time lease predicate under the SAME lock as the record insert:
	// a revoke/cancel/replacement/expiry during the (multi-GB) staging must
	// not be acknowledged in dev mode either.
	if !s.validActiveLease(s.jobs[j.ID], runnerID, token, gen, time.Now().UTC()) {
		s.mu.Unlock()
		_ = os.Remove(dst)
		_ = os.Remove(dst + ".manifest.json")
		s.auditLocked("snapshot.lease_lost_at_commit", runnerID, j.RunID, j.ID, "lease lost before snapshot commit", nil)
		http.Error(w, "lease expired during upload", http.StatusConflict)
		return
	}
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

// uploadSnapshotDB is the DB-mode upload: the archive bytes are staged
// through the configured bounded staging area (never the bare system
// temporary directory, so concurrent valid runners cannot exhaust the
// control-plane root filesystem), published to CAS, and the record is
// inserted through SnapshotStore in the same flow.
// Insertion failure fails the upload (503); the already written CAS blob is
// left as an orphan for the reference-aware blob GC — never deleted,
// because a failed metadata persist must not remove a digest another
// record may reference. The record's Path is the cas:<digest> reference,
// so any replica resolves the archive by digest.
func (s *Server) uploadSnapshotDB(w http.ResponseWriter, r *http.Request, j model.Job, runnerID string, gen int64) {
	ctx := r.Context()
	stagingBudget := s.StagingBudget()
	if stagingBudget == nil {
		http.Error(w, "snapshot storage requires a configured staging budget", http.StatusServiceUnavailable)
		return
	}
	// Reserve BEFORE accepting the body: the staging bound is enforced
	// against the declared Content-Length (or the endpoint maximum when the
	// length is unknown), so two concurrent uploads whose combined size
	// exceeds the budget serialize on the reservation instead of both
	// writing to disk. The reservation is released on every exit path —
	// including copy errors, parse failures and client disconnects (the
	// deferred Release plus the request-context cancellation Acquire
	// observes).
	reserve, ok := snapshotStagingReserve(r)
	if !ok {
		http.Error(w, snapshotTooLargeError(), http.StatusRequestEntityTooLarge)
		return
	}
	res, err := stagingBudget.Acquire(ctx, reserve)
	if err != nil {
		if ctx.Err() != nil {
			// The client is gone; there is nobody to answer. The failed
			// Acquire released nothing, so the budget is intact.
			return
		}
		if errors.Is(err, staging.ErrBudgetExceeded) {
			// The request itself is larger than the whole configured
			// staging budget: waiting could never make it fit.
			http.Error(w, "snapshot archive exceeds the configured staging budget", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "snapshot staging capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	defer res.Release()
	// Stage the archive through the budget-owned spool primitive: the file is
	// created AND registered as an active spool under the budget mutex, so a
	// concurrent Budget.Prune can never unlink a live snapshot spool by age
	// (a raw os.CreateTemp with the reclaimable FilePrefix would be invisible
	// to the active-spool set). The body is bounded at the reservation, which
	// SpoolFile also enforces on the source.
	stagedPath, n, err := stagingBudget.SpoolFile(http.MaxBytesReader(w, r.Body, reserve), reserve)
	if err != nil {
		if isSnapshotBodyTooLarge(err) || errors.Is(err, staging.ErrTooLarge) {
			http.Error(w, snapshotTooLargeError(), http.StatusRequestEntityTooLarge)
			return
		}
		if ctx.Err() != nil {
			// The client is gone; there is nobody to answer.
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer os.Remove(stagedPath)
	f, err := os.Open(stagedPath)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	m, err := snapshot.Parse(f)
	_ = f.Close()
	if err != nil {
		http.Error(w, "invalid snapshot archive: "+err.Error(), http.StatusBadRequest)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	// Publish + record commit under the digest fence (the collector re-reads
	// references under the same fence). The digest is only known after the
	// staged bytes are hashed, so the staging spool is hashed here first; the
	// publication then streams that SAME staged file into the backend (no
	// second copy) and validates the object the backend reports.
	stagedSum, sumErr := fileSHA256(stagedPath)
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
	obj, err := s.CAS.PutFile(ctx, stagedPath, stagedSum, n)
	if err != nil {
		if casIntegrityError(err) {
			s.logf("snapshot upload: CAS publication failed: %v", err)
			http.Error(w, "snapshot storage verification failed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "snapshot storage failed", http.StatusServiceUnavailable)
		return
	}
	// Read-back verification: the bytes must be complete and content-
	// addressed exactly as streamed. A store that truncated or altered the
	// archive (obj digest/size disagreeing with the request hash, or the
	// stored object failing the CAS digest check on re-read) fails the
	// upload instead of being acknowledged; the unreferenced blob is left
	// for the reference-aware GC.
	wantSHA := stagedSum
	if obj.Key != wantSHA || obj.SHA256 != wantSHA || obj.Size != n {
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
	// Prefer the lease-fenced store method: the live-lease predicate and the
	// record insert run in ONE transaction, so a lease lost during the
	// multi-GB staging can never be acknowledged as a snapshot commit.
	if leaseStore, ok := s.DB.(storage.LeaseCommitStore); ok {
		if err := leaseStore.InsertSnapshotForLease(ctx, j.ID, runnerID, gen, rec); err != nil {
			if leaseLostAtCommit(err) {
				s.auditLocked("snapshot.lease_lost_at_commit", runnerID, j.RunID, j.ID, "lease lost before snapshot commit", nil)
				http.Error(w, "lease expired during upload", http.StatusConflict)
				return
			}
			http.Error(w, "snapshot record persistence failed", http.StatusServiceUnavailable)
			return
		}
	} else if err := ss.InsertSnapshotRecord(ctx, rec); err != nil {
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
// surface — the record/manifest LISTING and the archive DOWNLOAD, both of
// which describe or carry the private workspace — scoped by the run's
// canonical policy identity (repoIDForRun). The repository resolution keeps
// the decision anchored to the addressed run instead of a blanket gate, while
// auth.Authorize makes ActionAdmin unsatisfiable by any repository grant:
// only the global admin role (or the admin token, which carries no principal)
// passes. A non-admin authenticated principal is answered 403 by
// requireAction.
func (s *Server) requireRunAdmin(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	return s.requireAction(w, r, auth.ActionAdmin, repoIDForRun(run), false)
}

// listSnapshots is GET /api/v1/runs/{id}/snapshots: the snapshot records of
// the run's jobs, ADMIN tier — the same tier as the archive download.
//
// TIER DECISION (L4-A): a record is not innocuous metadata. It carries every
// SnapshotEntry (workspace file name, mode, size, SHA-256), the manifest root
// digest and the archive digest — an inventory of the private workspace the
// archive holds (checkout, generated and secret-derived files). The download
// is already admin tier, so the collection that describes exactly that
// archive is admin tier too: requireRunAdmin resolves auth.ActionAdmin
// against the run's canonical repository identity (repoIDForRun) and no
// repository grant (not even artifact_read) satisfies it. The server-local
// archive path is still stripped (redactSnapshot); the admin caller sees the
// digests and entries the archive itself contains.
//
// The response is keyset-paginated (bounded limit + opaque cursor,
// created_at ASC, id ASC) so neither manifests nor metadata can be requested
// unbounded: one page holds at most storage.MaxSnapshotPageLimit records,
// the cap is advertised in X-Kiwi-Snapshots-Limit-Cap, and
// X-Kiwi-Next-Cursor carries the position of the last returned record while
// more exist. DB mode reads through SnapshotPageStore (failing closed if the
// configured store lacks that capability, never falling back to an unbounded
// list); memory mode applies the same contract through
// storage.PageSnapshots. Neither mode holds s.mu across a store call,
// response serialization or a client write.
func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	cursor, ok := decodeSnapshotsCursor(r.URL.Query().Get("cursor"))
	if !ok {
		// Opaque: the malformed value and the decoder's reason are never
		// echoed back.
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}
	limit := storage.NormalizeSnapshotPageLimit(snapshotsPageLimitParam(r))
	var page storage.SnapshotPage
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if !s.requireRunAdmin(w, r, run) {
			return
		}
		page, err = listSnapshotsPageFromStore(r.Context(), s.DB, runID, cursor, limit)
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
	} else {
		// Memory mode: resolve the run and copy only its records under the
		// lock, then page, redact and serialize outside it.
		snapshotListMemoryLock()
		s.mu.Lock()
		run, ok := s.runs[runID]
		var recs []model.SnapshotRecord
		if ok {
			recs = s.snapshotRecordsForRunLocked(runID)
		}
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !s.requireRunAdmin(w, r, run) {
			return
		}
		page = storage.PageSnapshots(recs, runID, cursor.createdAt, cursor.id, limit)
	}
	out := make([]model.SnapshotRecord, 0, len(page.Snapshots))
	for _, rec := range page.Snapshots {
		out = append(out, redactSnapshot(rec))
	}
	w.Header().Set("X-Kiwi-Snapshots-Limit-Cap", strconv.Itoa(storage.MaxSnapshotPageLimit))
	if page.HasMore && page.NextID != "" {
		w.Header().Set("X-Kiwi-Next-Cursor", encodeSnapshotsCursor(page.NextCreatedAt, page.NextID))
	}
	writeJSON(w, http.StatusOK, out)
}

// snapshotsCursorPrefix versions the opaque snapshot-collection cursor. The
// encoding is the repository's structured-key style (runs' rk1, testintel
// history keys): a version prefix plus base64.RawURLEncoding of a JSON array,
// here [created_at in RFC3339Nano UTC, record id], so every id byte
// round-trips exactly (including separators, unicode and whitespace).
const snapshotsCursorPrefix = "sk1:"

// snapshotsCursor is the decoded position of the previous page: the
// (created_at, id) of its last record. The zero value is the first-page
// position.
type snapshotsCursor struct {
	createdAt time.Time
	id        string
}

// encodeSnapshotsCursor renders the opaque cursor for the record that ended a
// page.
func encodeSnapshotsCursor(createdAt time.Time, id string) string {
	raw, _ := json.Marshal([2]string{createdAt.UTC().Format(time.RFC3339Nano), id})
	return snapshotsCursorPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSnapshotsCursor parses the opaque cursor query parameter. An empty
// value is the first-page position. Anything else must be exactly the
// encoding encodeSnapshotsCursor produces; malformed input reports ok=false
// so the handler answers an opaque 400 instead of guessing at a position.
func decodeSnapshotsCursor(raw string) (snapshotsCursor, bool) {
	if raw == "" {
		return snapshotsCursor{}, true
	}
	rest, found := strings.CutPrefix(raw, snapshotsCursorPrefix)
	if !found {
		return snapshotsCursor{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return snapshotsCursor{}, false
	}
	var fields [2]string
	if err := json.Unmarshal(decoded, &fields); err != nil {
		return snapshotsCursor{}, false
	}
	createdAt, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil {
		return snapshotsCursor{}, false
	}
	return snapshotsCursor{createdAt: createdAt, id: fields[1]}, true
}

// snapshotsPageLimitParam parses the bounded page-size query parameter.
// Absent, unparsable and non-positive values select the default; values above
// the cap are clamped (the cap is advertised in X-Kiwi-Snapshots-Limit-Cap).
func snapshotsPageLimitParam(r *http.Request) int {
	limit, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if err != nil {
		return storage.DefaultSnapshotPageLimit
	}
	return storage.NormalizeSnapshotPageLimit(limit)
}

// errSnapshotsPaginationUnsupported is the fail-closed answer for a
// configured store without the SnapshotPageStore capability. An unbounded
// ListSnapshotsByRun window cannot honor an older cursor, so the walk would
// re-read the oldest records forever instead of reaching the rest of the
// collection. Every store shipped with Kiwi implements SnapshotPageStore;
// the detail is logged server-side and the client sees the opaque 500 body.
var errSnapshotsPaginationUnsupported = errors.New("snapshots pagination unsupported by configured store")

// listSnapshotsPageFromStore reads one keyset page from a store that
// implements storage.SnapshotPageStore (the memory and PostgreSQL stores do).
// A store without the capability fails closed instead of being served an
// unbounded ListSnapshotsByRun snapshot, so a misconfigured custom store
// reports the missing pagination contract rather than returning a truncated
// or unbounded collection.
func listSnapshotsPageFromStore(ctx context.Context, store storage.Store, runID string, cursor snapshotsCursor, limit int) (storage.SnapshotPage, error) {
	paged, ok := store.(storage.SnapshotPageStore)
	if !ok {
		return storage.SnapshotPage{}, fmt.Errorf("%w: %T", errSnapshotsPaginationUnsupported, store)
	}
	return paged.ListSnapshotsPage(ctx, runID, cursor.createdAt, cursor.id, limit)
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
	// Strong integrity: the archive is preverified (exact length + digest)
	// before the response is committed; the verified file is then streamed.
	s.serveVerifiedDownload(w, r, "snapshot", f, rec.Size, rec.SHA256, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
		w.Header().Set("X-Kiwi-Snapshot-SHA256", rec.SHA256)
	})
}

// downloadSnapshotDB streams one snapshot in DB mode: the record comes from
// the SnapshotStore through the single-record GetSnapshot (run_id, id) lookup
// — never by listing every record of the run and scanning the slice — and
// the archive bytes from CAS by digest, so a fresh replica with the same
// store+CAS serves the download. Like the memory path it is admin tier —
// requireRunAdmin resolves the run's canonical repository before the admin
// decision — and records with a node-local Path (legacy) fall back to the
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
	rec, found, err := ss.GetSnapshot(ctx, runID, sid)
	if err != nil {
		s.internalError(w, r, err, "")
		return
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
		wantSize := rec.Size
		if wantSize <= 0 {
			wantSize = obj.Size
		}
		wantSHA := rec.SHA256
		if wantSHA == "" {
			wantSHA = digest
		}
		// Strong integrity: preverify the CAS object (exact length + digest)
		// before committing the response; a corrupt backend yields no 200.
		s.serveVerifiedDownload(w, r, "snapshot", rc, wantSize, wantSHA, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Length", strconv.FormatInt(wantSize, 10))
			w.Header().Set("X-Kiwi-Snapshot-SHA256", digest)
		})
		return
	}
	if rec.Path != "" {
		f, err := os.Open(rec.Path)
		if err != nil {
			http.Error(w, "snapshot archive missing", http.StatusNotFound)
			return
		}
		s.serveVerifiedDownload(w, r, "snapshot", f, rec.Size, rec.SHA256, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/gzip")
			w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
			w.Header().Set("X-Kiwi-Snapshot-SHA256", rec.SHA256)
		})
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

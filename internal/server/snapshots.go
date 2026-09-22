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
func (s *Server) uploadSnapshotDB(w http.ResponseWriter, r *http.Request, j model.Job, runnerID string) {
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
	// The staging file carries staging.FilePrefix, so an abandoned file left
	// by a crashed process is reclaimed by the package's startup Prune.
	tmp, err := os.CreateTemp(stagingBudget.Dir(), staging.FilePrefix+"snapshot-*")
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), http.MaxBytesReader(w, r.Body, reserve))
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
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	w.Header().Set("X-Kiwi-Snapshot-SHA256", rec.SHA256)
	if _, err := io.Copy(w, f); err != nil {
		s.logf("snapshot download: %v", err)
	}
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

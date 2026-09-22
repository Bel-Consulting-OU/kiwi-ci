package server

import (
	"bytes"
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const maxBlobBytes int64 = 8 << 30 // 8 GiB hard safety limit for the built-in store.

// cacheUploadMaxBytes is the receiver's HTTP body cap for cache uploads: the
// same 8 GiB safety limit the artifact path enforces. It is a variable so
// tests can exercise the boundary with small bodies; production leaves it at
// maxBlobBytes.
var cacheUploadMaxBytes = maxBlobBytes

// cacheStageHook, when non-nil, runs with the staged file path and the
// reserved byte amount immediately after the body is fully staged (inside
// the budget reservation) and before publication. It is a test-only seam
// (production leaves it nil) so the staging wiring — the path is inside the
// configured budget directory and the reservation is held — can be observed
// without a multi-GB body.
var cacheStageHook func(path string, reserved int64)

// artifactStageHook, when non-nil, runs with the staged file path and the
// reserved byte amount immediately after the artifact body is fully staged
// (inside the budget reservation) and before it is hashed and published. It
// is the artifact counterpart of cacheStageHook: a test-only seam
// (production leaves it nil) so tests can observe the staging wiring or
// inject a staged-file failure without a multi-GB body.
var artifactStageHook func(path string, reserved int64)

// provenanceSidecarWrite publishes the fs-mode provenance envelope sidecar.
// Production uses fsutil.AtomicWriteFile — the shared durable sequence: a
// unique temp file in the destination directory, checked write/chmod/file
// fsync/close, rename over the destination, and a parent-directory fsync — so
// a crash can never leave a durable artifact record whose local
// `.intoto.json` sidecar is missing, truncated or not durable. It is a var
// only so tests can inject a specific durability-phase failure through the
// real primitive (scoped to this writer, so the payload finalization in the
// same request is unaffected); production never reassigns it.
var provenanceSidecarWrite = fsutil.AtomicWriteFile

var cacheKeyRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

// provenanceFenceTimeout bounds how long an artifact upload waits for the
// provenance digest's second fence. Holding two digest fences per upload
// means a fully saturated DB-mode advisory pool (every connection held by a
// fence) must not be able to block a handler forever: the handler already
// holds the payload digest's fence while it waits for the provenance
// digest's, so an unbounded wait with every other upload in the same state
// would never resolve. On timeout the provenance envelope is skipped — never
// published unfenced — exactly like a failed Put; the artifact upload
// itself still succeeds. It is a var only so tests can shrink the bound
// (same seam convention as the storage fence release bounds); production
// never reassigns it.
var provenanceFenceTimeout = 5 * time.Second

// uploadArtifact implements PUT /api/v1/jobs/{id}/artifacts/{name}.
//
// The upload is verified against the job's artifact contract: undeclared
// names are rejected (403), the declared retention drives expiry, and a
// declared MaxSize is enforced (413). Idempotency is scoped to (job, lease
// generation, name): re-uploading the same digest returns the existing
// record, a different digest for the same generation conflicts (409).
// Bytes are staged to a temp file, hashed, gated on the SBOM/sigstore
// attestation contract, and only then committed and recorded.
func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "artifact storage requires persistent server", http.StatusServiceUnavailable)
		return
	}
	name := cleanBlobName(r.PathValue("name"))
	if name == "" {
		http.Error(w, "invalid artifact name", http.StatusBadRequest)
		return
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	j, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	// The run record carries the signed provenance identity
	// (repository/ref/commit), so loading it is never best-effort: an
	// unavailable or missing run fails the upload closed BEFORE any bytes
	// are staged, rather than minting a statement with an empty identity.
	var run model.Run
	if s.DB != nil {
		loaded, err := s.DB.GetRun(r.Context(), j.RunID)
		if err != nil {
			s.logError("artifact: authoritative run lookup failed", "job", j.ID, "run", j.RunID, "error", err.Error())
			http.Error(w, "artifact provenance identity unavailable", http.StatusServiceUnavailable)
			return
		}
		run = loaded
	} else {
		s.mu.Lock()
		loaded, ok := s.runs[j.RunID]
		s.mu.Unlock()
		if !ok {
			s.logError("artifact: authoritative run lookup failed", "job", j.ID, "run", j.RunID, "error", "run not found")
			http.Error(w, "artifact provenance identity unavailable", http.StatusServiceUnavailable)
			return
		}
		run = loaded
	}
	// Contract resolution: every upload name must trace to a declared
	// artifact (or its .sbom/.sigstore attestation sibling).
	contracts, err := s.contractsForJob(r.Context(), j)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	contract, kind, ok := contractForUploadName(contracts, name)
	if !ok {
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "upload for undeclared artifact name", map[string]string{"name": name, "job": j.Key})
		http.Error(w, "artifact name is not declared by the job's artifact contract", http.StatusForbidden)
		return
	}
	switch kind {
	case "sbom":
		s.uploadSBOM(w, r, j, contract, strings.TrimSuffix(name, sbomSuffix))
		return
	case "sigstore":
		s.uploadSigstore(w, r, j, contract, strings.TrimSuffix(name, sigstoreSuffix))
		return
	}
	s.uploadArtifactPayload(w, r, j, run, contract, name, runnerID, token, gen)
}

// uploadArtifactPayload commits one declared artifact payload under the
// per-job critical section.
//
// Staging: the body spools through the server's shared bounded staging
// budget (never a bare system temp directory and never the artifact data dir
// itself), so concurrent uploads to every job together can never stage more
// than staging.max_bytes. The reservation is the request's Content-Length, or
// the effective artifact limit when the body length is unknown (chunked); it
// is released on every exit path — including copy errors, gate rejections and
// client disconnects — and held until the CAS publication / record commit no
// longer needs the staged bytes. A body that exceeds the artifact limit or
// the staging capacity is answered 413; a full budget blocks until room
// frees up or the request context ends.
func (s *Server) uploadArtifactPayload(w http.ResponseWriter, r *http.Request, j model.Job, run model.Run, contract storage.ArtifactContract, name, runnerID, token string, gen int64) {
	ctx := r.Context()
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.internalError(w, r, err, "")
		return
	}
	// The critical section: idempotency check, staging, gate and record
	// insertion are atomic per job so concurrent re-uploads of the same
	// (job, generation, name) cannot interleave.
	lock := s.jobLock(j.ID)
	lock.Lock()
	defer lock.Unlock()

	// Effective limit is the smaller of the global safety ceiling and the
	// frozen artifact contract: a 10 MiB contract must reject a multi-GB
	// body BEFORE it is staged, hashed or written anywhere. An excessive
	// Content-Length is rejected outright; the stream itself is bounded at
	// effectiveLimit+1 so an unknown-length body cannot run past it either.
	effectiveLimit := maxBlobBytes
	if contract.MaxSize > 0 && contract.MaxSize < effectiveLimit {
		effectiveLimit = contract.MaxSize
	}
	if cl := r.ContentLength; cl > effectiveLimit {
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact Content-Length exceeds declared max size", map[string]string{"name": name, "size": strconv.FormatInt(cl, 10), "max": strconv.FormatInt(effectiveLimit, 10)})
		http.Error(w, "artifact exceeds the declared maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	// Staging reservation (the cache-upload model): without a configured
	// bound this path would spool into unbounded scratch space — exactly
	// the control-plane root-filesystem exhaustion it must not allow — so
	// it fails closed. A declared length above the whole staging capacity
	// can never be admitted (413); an unknown length reserves the effective
	// maximum, charging the endpoint's worst case before a byte is read.
	budget := s.StagingBudget()
	if budget == nil {
		http.Error(w, "artifact staging budget unavailable", http.StatusServiceUnavailable)
		return
	}
	reserve := effectiveLimit
	if cl := r.ContentLength; cl >= 0 {
		if cl > budget.MaxBytes() {
			s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact exceeds the staging capacity", map[string]string{"name": name, "size": strconv.FormatInt(cl, 10), "staging_max": strconv.FormatInt(budget.MaxBytes(), 10)})
			http.Error(w, "artifact exceeds the staging capacity", http.StatusRequestEntityTooLarge)
			return
		}
		reserve = cl
	}
	res, err := budget.Acquire(ctx, reserve)
	if err != nil {
		if errors.Is(err, staging.ErrBudgetExceeded) {
			s.logError("artifact: staging reservation refused", "bytes", reserve, "budget", budget.MaxBytes())
			http.Error(w, "artifact staging capacity unavailable for this upload", http.StatusServiceUnavailable)
			return
		}
		if ctx.Err() != nil {
			// The client is gone; there is nobody to answer.
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer res.Release()
	start := time.Now()
	// Stage and hash inside the budget directory, then publish: the digest
	// whose fence we take is the digest actually staged. SpoolFile never
	// writes more than the reservation to disk (the over-limit byte is
	// detected on the source), so the reservation stays exact even when the
	// body lies about its length.
	stagedPath, n, err := staging.SpoolFile(budget.Dir(), http.MaxBytesReader(w, r.Body, effectiveLimit+1), reserve)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || errors.Is(err, staging.ErrTooLarge) {
			s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact exceeds declared max size", map[string]string{"name": name, "max": strconv.FormatInt(effectiveLimit, 10)})
			http.Error(w, "artifact exceeds the declared maximum size", http.StatusRequestEntityTooLarge)
			return
		}
		if ctx.Err() != nil {
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer func() { _ = os.Remove(stagedPath) }()
	if artifactStageHook != nil {
		artifactStageHook(stagedPath, reserve)
	}
	digest, err := fileSHA256(stagedPath)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	// Payload size limit: the stream is bounded at effectiveLimit+1, so any
	// body that reached the bound (global OR contract) is rejected
	// unconditionally — an absent/greater contract must not let a
	// chunked-encoding body sneak one byte past the global ceiling.
	if n > effectiveLimit {
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact exceeds the effective size limit", map[string]string{"name": name, "size": strconv.FormatInt(n, 10), "max": strconv.FormatInt(effectiveLimit, 10)})
		http.Error(w, "artifact exceeds the declared maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	// Contract size limit (legacy path retained for contracts smaller than
	// the global ceiling; effectiveLimit already covers it).
	if contract.MaxSize > 0 && n > contract.MaxSize {
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact exceeds declared max size", map[string]string{"name": name, "size": strconv.FormatInt(n, 10), "max": strconv.FormatInt(contract.MaxSize, 10)})
		http.Error(w, "artifact exceeds the declared maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	// Idempotency on (job, generation, name).
	if existing, lerr := s.findArtifactByJobName(ctx, j.RunID, j.ID, name); lerr == nil {
		if rec, found := existingArtifactForGeneration(existing, gen); found {
			if rec.SHA256 == digest {
				s.auditLocked("artifact.idempotent_replay", runnerID, j.RunID, j.ID, "duplicate artifact upload acknowledged", map[string]string{"name": name, "sha256": digest})
				writeJSON(w, http.StatusOK, rec)
				return
			}
			s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact digest changed within one lease generation", map[string]string{"name": name, "existing": rec.SHA256, "incoming": digest})
			http.Error(w, "artifact already uploaded for this lease generation with a different digest", http.StatusConflict)
			return
		}
	} else {
		s.internalError(w, r, lerr, "")
		return
	}
	// SBOM/sigstore attestation gate: required attestations must be
	// present and valid before the payload is committed. The frozen
	// artifact contract is authoritative — the pipeline is never re-parsed.
	if code, msg := s.gateArtifactAttestations(ctx, contract, j, name, digest, dir); code != 0 {
		http.Error(w, msg, code)
		return
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	dst := filepath.Join(dir, id+".tar.gz")
	// DB-mode CAS transport: the payload bytes become a CAS blob object
	// addressed by their digest (shared across replicas); the artifact
	// record carries the "cas:" marker path so downloads resolve through
	// the shared store. Legacy local files remain the fallback.
	casMode := s.DB != nil && s.CAS != nil
	if casMode {
		// Hold the digest fence across "publish object + commit durable
		// reference": the CAS collector re-reads references under the same
		// fence, so a concurrent pass can never delete an object whose
		// reference this handler is about to commit (and a pass that
		// already decided to delete blocks this publish until it finishes,
		// after which the put recreates the object).
		release, ferr := s.acquireDigestFence(ctx, digest)
		if ferr != nil {
			s.internalError(w, r, ferr, "")
			return
		}
		defer release()
		// Publish the STAGED file directly (no second copy): the CAS
		// streams it into the backend, verifies the content against the
		// staged digest, and validates the object the backend reports.
		obj, perr := s.CAS.PutFile(ctx, stagedPath, digest, n)
		if perr != nil {
			if casIntegrityError(perr) {
				s.auditLocked("artifact.integrity_failure", runnerID, j.RunID, j.ID, "artifact CAS object disagrees with the streamed bytes", map[string]string{"name": name, "want_sha256": digest, "want_size": strconv.FormatInt(n, 10), "error": perr.Error()})
				http.Error(w, "artifact storage verification failed", http.StatusServiceUnavailable)
				return
			}
			s.internalError(w, r, perr, "")
			return
		}
		// CAS integrity invariant: the published object must be exactly the
		// staged bytes. A broken or misconfigured backend that reports a
		// different digest/size must never leave a record (and provenance
		// statement) naming the local digest while the shared object differs.
		if obj.Key != digest || obj.SHA256 != digest || obj.Size != n {
			s.auditLocked("artifact.integrity_failure", runnerID, j.RunID, j.ID, "artifact CAS object disagrees with the streamed bytes", map[string]string{"name": name, "want_sha256": digest, "want_size": strconv.FormatInt(n, 10), "got_sha256": obj.SHA256, "got_size": strconv.FormatInt(obj.Size, 10)})
			http.Error(w, "artifact storage verification failed", http.StatusServiceUnavailable)
			return
		}
		// Read-back verification (parity with the snapshot path): reopen the
		// newly written object, stream and hash it, and require the digest
		// and exact byte length before the record is committed.
		if verr := verifyStoredBlob(ctx, s.CAS, digest, n); verr != nil {
			s.logError("artifact: stored object verification failed", "job", j.ID, "sha256", digest, "error", verr.Error())
			http.Error(w, "artifact storage verification failed", http.StatusServiceUnavailable)
			return
		}
	} else {
		// Filesystem mode: move the staged bytes into the destination
		// durably. The staging directory may live on another filesystem
		// than the data dir, so a plain rename is only the fast path: the
		// fallback is a destination-local streamed copy with the full
		// fsync/rename/parent-fsync sequence.
		if err := finalizeStagedFile(stagedPath, dst); err != nil {
			s.internalError(w, r, err, "")
			return
		}
	}
	// The lease must still be live at commit time.
	if s.DB != nil {
		current, gerr := s.jobForLease(ctx, j.ID)
		if gerr != nil || !s.validActiveLease(current, runnerID, token, gen, time.Now().UTC()) {
			if !casMode {
				_ = os.Remove(dst)
			}
			http.Error(w, "lease expired during upload", http.StatusConflict)
			return
		}
	} else {
		s.mu.Lock()
		current, still := s.jobs[j.ID]
		leaseValid := still && s.validActiveLease(current, runnerID, token, gen, time.Now().UTC())
		s.mu.Unlock()
		if !leaseValid {
			_ = os.Remove(dst)
			http.Error(w, "lease expired during upload", http.StatusConflict)
			return
		}
	}
	createdAt := time.Now().UTC()
	rec := model.ArtifactRecord{ID: id, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Name: name, Path: dst, Size: n, SHA256: digest, ContentType: "application/gzip", CreatedAt: createdAt, LeaseGeneration: gen}
	if casMode {
		rec.Path = "cas:" + digest
	}
	if retention := contractRetention(contract.Retention); retention > 0 {
		expires := createdAt.Add(retention)
		rec.ExpiresAt = &expires
	}
	if err := s.attachSidecarsToRecord(r.Context(), &rec, j, name, dir); err != nil {
		// The sidecar references could not be resolved (store outage): the
		// record must not silently lose its attestations, so the upload
		// fails closed. A CAS blob already written above stays as an
		// orphan for the reference-aware GC.
		removeStagedArtifact(dst, casMode)
		s.logError("artifact: sidecar reference lookup failed", "job", j.ID, "error", err.Error())
		http.Error(w, "artifact sidecar reference lookup failed", http.StatusInternalServerError)
		return
	}
	// Provenance signs with the dedicated provenance key — never the OIDC
	// key — so the two trust roots stay independent.
	finished := time.Now().UTC()
	signer := s.ensureProvenanceKey()
	st := provenance.ArtifactStatement(provenance.ArtifactInput{Name: name, SHA256: rec.SHA256, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Repository: repoIDForRun(run), Ref: run.Ref, Commit: run.SHA, Runner: runnerID, Trusted: j.Trusted, Started: jobStart(j), Finished: finished})
	st.Builder = provenance.BuilderPlaceholder
	// Fence ordering (deadlock-free): the CAS fences of one handler are
	// acquired in PUBLICATION order — the payload digest's fence was taken
	// above, before the payload CAS.Put, and the provenance digest's fence is
	// taken here, before its own CAS.Put. Both are held across the durable
	// artifact insert below (and released, provenance first, when the
	// handler returns), so the collector can never reclaim either object
	// between its publication and the commit of the reference that makes it
	// reachable. No path takes the pair in the opposite order, the collector
	// takes one digest fence at a time, and the second acquisition is
	// bounded (provenanceFenceTimeout) so a saturated advisory pool cannot
	// pin the handler either. A provenance Put that cannot be fenced is
	// SKIPPED (the envelope is non-essential metadata, exactly like a failed
	// Put), never published unfenced.
	var releaseProvenance func()
	if env, er := provenance.Sign(st, signer.KID, signer.Private); er == nil {
		if ab, mer := json.MarshalIndent(env, "", "  "); mer == nil {
			sum := sha256.Sum256(ab)
			provDigest := hex.EncodeToString(sum[:])
			// HA sidecars: the envelope bytes live in the shared CAS store
			// and the record carries the digest reference; fs dev mode
			// keeps the local sidecar file for compatibility.
			if casMode {
				fctx, cancel := context.WithTimeout(ctx, provenanceFenceTimeout)
				release, ferr := s.acquireDigestFence(fctx, provDigest)
				cancel()
				if ferr != nil {
					s.logError("artifact: provenance digest fence failed; provenance not stored", "job", j.ID, "sha256", provDigest, "error", ferr.Error())
				} else {
					releaseProvenance = release
					// The provenance envelope is published only when the CAS
					// object is the exact envelope bytes: the record must
					// never reference a digest the shared store disagrees
					// with (same invariant as the payload publication above).
					// The bytes are in memory and their digest is known, so
					// PutKnown publishes them without any scratch file.
					if pobj, perr := s.CAS.PutKnown(ctx, provDigest, int64(len(ab)), bytes.NewReader(ab)); perr == nil && pobj.Key == provDigest && pobj.SHA256 == provDigest && pobj.Size == int64(len(ab)) {
						rec.ProvenancePath = "cas:" + provDigest
						rec.ProvenanceSHA256 = provDigest
					} else if perr != nil {
						s.logError("artifact: provenance store failed; provenance not stored", "job", j.ID, "sha256", provDigest, "error", perr.Error())
					} else {
						s.logError("artifact: provenance CAS object disagrees with the envelope; provenance not stored", "job", j.ID, "sha256", provDigest, "got_sha256", pobj.SHA256, "got_size", pobj.Size)
					}
				}
			} else {
				ap := dst + ".intoto.json"
				if werr := s.publishProvenanceSidecarFS(ap, ab, provDigest); werr != nil {
					if fsutil.Renamed(werr) {
						// Post-rename (parent-directory fsync) failure: the
						// sidecar bytes ARE visible at ap but their crash
						// durability is not certified. The artifact must NOT
						// be acknowledged — a durable record naming a
						// ProvenanceSHA256 whose sidecar may vanish in a crash
						// is exactly the defect this sequence prevents. Keep
						// the published sidecar (and the already-fsynced
						// payload) in place; the degraded marker folded by
						// publishProvenanceSidecarFS fails /readiness closed
						// until a later successful persist in this directory
						// reconciles it.
						s.logError("artifact: provenance sidecar published but not durably certified; upload refused", "job", j.ID, "path", ap, "error", werr.Error())
						http.Error(w, statePersistenceDegradedBody, http.StatusServiceUnavailable)
						return
					}
					// Definitely not published (or published bytes that could
					// not be re-verified): never acknowledge an artifact whose
					// provenance sidecar is not durably recorded, and never
					// record a ProvenanceSHA256 whose bytes were not
					// re-hashed. Drop the now-unreferenced payload; the
					// envelope is regenerated on retry.
					_ = os.Remove(dst)
					s.logError("artifact: provenance sidecar not durably published; upload refused", "job", j.ID, "path", ap, "error", werr.Error())
					http.Error(w, "artifact provenance sidecar not durable", http.StatusServiceUnavailable)
					return
				}
				rec.ProvenancePath = ap
				rec.ProvenanceSHA256 = provDigest
			}
		}
	}
	if releaseProvenance != nil {
		defer releaseProvenance()
	}
	if s.DB != nil {
		// PostgreSQL is authoritative: the (job, generation, name) unique
		// index admits exactly one record across replicas. Losing a race to
		// a concurrent upload returns the stored record (same digest, 200)
		// or conflicts (409); the stored record is never overwritten.
		idem, ok := s.DB.(storage.ArtifactIdempotentStore)
		if !ok {
			_ = os.Remove(dst)
			http.Error(w, "artifact store does not support idempotent artifact insertion", 500)
			return
		}
		stored, created, ierr := idem.InsertArtifactOnce(ctx, rec)
		if errors.Is(ierr, storage.ErrArtifactDigestConflict) {
			removeStagedArtifact(dst, casMode)
			s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact digest changed within one lease generation", map[string]string{"name": name, "existing": stored.SHA256, "incoming": digest})
			http.Error(w, "artifact already uploaded for this lease generation with a different digest", http.StatusConflict)
			return
		}
		if ierr != nil {
			removeStagedArtifact(dst, casMode)
			s.internalError(w, r, ierr, "")
			return
		}
		if !created {
			removeStagedArtifact(dst, casMode)
			s.auditLocked("artifact.idempotent_replay", runnerID, j.RunID, j.ID, "duplicate artifact upload acknowledged", map[string]string{"name": name, "sha256": stored.SHA256})
			writeJSON(w, http.StatusOK, stored)
			return
		}
		// The record is durable: consume ONLY the pending sidecar rows this
		// exact record references (job, generation, name, kind). Every other
		// artifact's (or generation's) pending sidecar survives until its own
		// commit or the 7-day prune. A cleanup failure is logged, never fatal
		// — the record already carries the digests and the maintenance tick
		// prunes any leftover row.
		if cerr := s.consumeArtifactPendingSidecars(ctx, rec); cerr != nil {
			s.logError("artifact: pending sidecar cleanup failed", "job", j.ID, "artifact", rec.ID, "error", cerr.Error())
		}
		s.metricAdd("kiwi_artifact_bytes_total", float64(n), nil)
		s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
		s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256, "provenance_kid": signer.KID})
		writeJSON(w, http.StatusCreated, rec)
		return
	}
	// Memory mode: the IDENTICAL (job, generation, name)/digest semantics
	// under s.mu, so concurrent uploads on one instance resolve exactly like
	// the SQL unique key.
	s.mu.Lock()
	stored, created, merr := s.insertArtifactMemoryLocked(rec)
	switch {
	case errors.Is(merr, storage.ErrArtifactDigestConflict):
		s.mu.Unlock()
		_ = os.Remove(dst)
		_ = os.Remove(dst + ".intoto.json")
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact digest changed within one lease generation", map[string]string{"name": name, "existing": stored.SHA256, "incoming": digest})
		http.Error(w, "artifact already uploaded for this lease generation with a different digest", http.StatusConflict)
		return
	case merr != nil:
		s.mu.Unlock()
		_ = os.Remove(dst)
		s.internalError(w, r, merr, "")
		return
	case !created:
		s.mu.Unlock()
		_ = os.Remove(dst)
		_ = os.Remove(dst + ".intoto.json")
		s.auditLocked("artifact.idempotent_replay", runnerID, j.RunID, j.ID, "duplicate artifact upload acknowledged", map[string]string{"name": name, "sha256": stored.SHA256})
		writeJSON(w, http.StatusOK, stored)
		return
	}
	s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256, "provenance_kid": signer.KID})
	if perr := s.persistCheckedErrLocked("artifact.upload"); perr != nil {
		// The record never became durable: roll back the in-memory record,
		// leave the pending-sidecar bookkeeping untouched, drop the staged
		// payload and fail closed. A 201 here would acknowledge an artifact
		// the snapshot does not contain, and the retry would replay from the
		// ghost without ever writing it.
		delete(s.artifacts, rec.ID)
		s.mu.Unlock()
		_ = os.Remove(dst)
		_ = os.Remove(dst + ".intoto.json")
		http.Error(w, "artifact upload not durable", http.StatusServiceUnavailable)
		return
	}
	// Dev-mode mirror: the record now carries its sidecar references, so
	// only ITS OWN (job, generation, name) pending entries are consumed.
	delete(s.pendingSidecars, sidecarPendingKey(j.ID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSBOM))
	delete(s.pendingSidecars, sidecarPendingKey(j.ID, rec.LeaseGeneration, name, storage.ArtifactSidecarKindSigstore))
	s.mu.Unlock()
	s.metricAdd("kiwi_artifact_bytes_total", float64(n), nil)
	s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
	writeJSON(w, http.StatusCreated, rec)
}

// insertArtifactMemoryLocked is the memory-mode equivalent of the
// authoritative SQL insert: the (job, generation, name) key admits exactly
// one record and a different digest for the same key conflicts. The caller
// holds s.mu.
func (s *Server) insertArtifactMemoryLocked(rec model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	if rec.JobID == "" {
		// Matches SQL NULL semantics: rows without a job never join the key.
		s.artifacts[rec.ID] = rec
		return rec, true, nil
	}
	for _, existing := range s.artifacts {
		if existing.JobID != rec.JobID || existing.LeaseGeneration != rec.LeaseGeneration || existing.Name != rec.Name {
			continue
		}
		if existing.SHA256 != rec.SHA256 {
			return existing, false, storage.ErrArtifactDigestConflict
		}
		return existing, false, nil
	}
	s.artifacts[rec.ID] = rec
	return rec, true, nil
}

// removeStagedArtifact cleans up the local staging artifacts of a lost or
// conflicting upload race. CAS blobs are content-addressed and deduplicated,
// so they are left for the blob GC: deleting a digest could remove content
// another record references.
func removeStagedArtifact(dst string, casMode bool) {
	if casMode {
		return
	}
	_ = os.Remove(dst)
	_ = os.Remove(dst + ".intoto.json")
}

// publishProvenanceSidecarFS durably publishes the filesystem-mode provenance
// envelope next to its artifact payload and returns the sidecar path only
// after REOPENING and RE-HASHING it: the digest the caller records is thereby
// proven to match the bytes actually on disk, never merely the in-memory
// envelope digest. A sidecar whose published bytes cannot be re-read or whose
// re-hash disagrees is reported as an error, so no ProvenanceSHA256 is ever
// recorded for unverified bytes.
//
// The durable write's outcome is folded into the per-directory uncertainty
// set (noteFilePersistResult, the same signal /readiness and the lease gate
// consume) exactly like every other security-state file write: a
// parent-directory-fsync failure (fsutil.Renamed) arms uncertainty for the
// sidecar's directory because it is visible while its crash durability is
// unproven; a pre-rename failure leaves the set untouched; a success clears
// that directory's uncertainty. The caller decides the HTTP contract from
// fsutil.Renamed: post-rename uncertainty must not be acknowledged, while a
// pre-rename failure must not leave a record behind.
func (s *Server) publishProvenanceSidecarFS(path string, envelope []byte, digest string) error {
	werr := provenanceSidecarWrite(path, envelope, 0o600)
	s.noteFilePersistResult(path, werr)
	if werr != nil {
		return werr
	}
	got, herr := fileSHA256(path)
	if herr != nil {
		return fmt.Errorf("reopen provenance sidecar %s: %w", path, herr)
	}
	if got != digest {
		return fmt.Errorf("provenance sidecar %s re-hashed to %s, envelope digest %s", path, got, digest)
	}
	return nil
}

// casIntegrityError reports whether err is a CAS publication integrity
// failure: the backend reported an object that disagrees with the published
// key/digest/size (ErrBackendIntegrity), or the content did not match the
// advertised digest/size (ErrDigestMismatch/ErrSizeMismatch). Every such
// failure fails the upload closed with 503 and commits nothing (no manifest,
// no artifact record, no provenance statement), exactly like a failed
// read-back verification.
func casIntegrityError(err error) bool {
	return errors.Is(err, cas.ErrBackendIntegrity) ||
		errors.Is(err, cas.ErrDigestMismatch) ||
		errors.Is(err, cas.ErrSizeMismatch)
}

// stagedRename is the test seam over the fast-path rename of
// finalizeStagedFile. Production renames through fsutil.RealRename (the
// shared durability primitive's rename step); tests replace it to exercise
// the cross-filesystem fallback deterministically.
var stagedRename = fsutil.RealRename

// finalizeStagedFile moves a fully staged, fsynced file into its destination
// durably. A same-filesystem rename is the fast path; when the staging
// directory and the destination live on different filesystems the rename
// cannot work (the failure is reported cross-device), so the bytes are
// instead streamed into a destination-local temp file and published with the
// full durability sequence — never assuming a rename across volumes is
// possible.
func finalizeStagedFile(staged, dst string) error {
	if err := stagedRename(staged, dst); err == nil {
		return fsutil.SyncDir(filepath.Dir(dst))
	}
	return copyFileIntoPlace(staged, dst)
}

// copyFileIntoPlace is the cross-filesystem finalization at the destination:
// a unique temp file in the destination directory, the staged bytes
// streamed into it (fsutil's durability steps: write, chmod, file fsync,
// checked close, rename over the destination, parent-directory fsync). The
// staged source is left untouched for the caller to remove.
func copyFileIntoPlace(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	f, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := io.Copy(f, in); err != nil {
		_ = fsutil.RealFileClose(f)
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = fsutil.RealFileClose(f)
		_ = os.Remove(tmp)
		return err
	}
	if err := fsutil.RealFileSync(f); err != nil {
		_ = fsutil.RealFileClose(f)
		_ = os.Remove(tmp)
		return err
	}
	if err := fsutil.RealFileClose(f); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := fsutil.RealRename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsutil.SyncDir(dir)
}

// jobLock returns the per-job upload mutex.
func (s *Server) jobLock(jobID string) *sync.Mutex {
	s.jobLocksMu.Lock()
	defer s.jobLocksMu.Unlock()
	m, ok := s.jobLocks[jobID]
	if !ok {
		m = &sync.Mutex{}
		s.jobLocks[jobID] = m
	}
	return m
}

func jobStart(j model.Job) time.Time {
	if j.StartedAt != nil {
		return *j.StartedAt
	}
	return time.Now().UTC()
}

func (s *Server) listArtifacts(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		// Unlike the upload path, this run load only scopes the read; it
		// signs no provenance. It is already fail-closed: a missing record
		// answers 404 and a store failure aborts before any authorization,
		// so a zero-valued run can never widen the list.
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if !s.requireRunArtifactRead(w, r, run) {
			return
		}
		out, err := s.DB.ListArtifacts(r.Context(), runID)
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		dto := make([]v1.ArtifactDTO, 0, len(out))
		for _, a := range out {
			dto = append(dto, v1.ArtifactDTOFrom(a))
		}
		writeJSON(w, 200, dto)
		return
	}
	s.mu.Lock()
	run, ok := s.runs[runID]
	if ok {
		s.mu.Unlock()
		if !s.requireRunArtifactRead(w, r, run) {
			return
		}
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	out := []model.ArtifactRecord{}
	for _, a := range s.artifacts {
		if a.RunID == runID {
			a.Path = ""
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	dto := make([]v1.ArtifactDTO, 0, len(out))
	for _, a := range out {
		dto = append(dto, v1.ArtifactDTOFrom(a))
	}
	writeJSON(w, 200, dto)
}
func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.artifactRecord(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !s.requireArtifactRead(w, r, rec) {
		return
	}
	f, err := s.openArtifact(r.Context(), rec)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", rec.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, cleanBlobName(rec.Name)))
	w.Header().Set("X-Kiwi-Content-SHA256", rec.SHA256)
	w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	_, _ = io.Copy(w, f)
}

// artifactRecord loads one artifact record: from the store in DB mode
// (the shared artifact table is authoritative there), from the in-memory
// map otherwise.
func (s *Server) artifactRecord(ctx context.Context, id string) (model.ArtifactRecord, error) {
	if s.DB != nil {
		if ls, ok := s.DB.(storage.ArtifactLookupStore); ok {
			return ls.GetArtifact(ctx, id)
		}
		return model.ArtifactRecord{}, storage.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.artifacts[id]
	if !ok {
		return model.ArtifactRecord{}, storage.ErrNotFound
	}
	return a, nil
}

// openArtifact resolves an artifact's bytes: CAS mode records (marker path
// "cas:" prefix, or DB-mode records with a digest and no local path)
// resolve through the shared content-addressed store; everything else
// falls back to the legacy local file.
func (s *Server) openArtifact(ctx context.Context, rec model.ArtifactRecord) (io.ReadCloser, error) {
	if s.CAS != nil && (strings.HasPrefix(rec.Path, "cas:") || (rec.Path == "" && rec.SHA256 != "")) {
		rc, _, err := s.CAS.Open(ctx, rec.SHA256)
		return rc, err
	}
	if rec.Path == "" {
		return nil, os.ErrNotExist
	}
	return os.Open(rec.Path)
}

// cacheNamespace derives the cache namespace from the leased job: the
// canonical repository identity (the stored RepoID, derived from the URL +
// full name for legacy jobs) and the trust domain. Clients can never
// influence the namespace: the legacy
// X-Kiwi-Repository/X-Kiwi-Trust-Domain headers are rejected.
func cacheNamespace(j model.Job) (repo, trust string) {
	repo = repoIDForJob(j)
	repo = strings.TrimSpace(repo)
	trust = "untrusted"
	if j.Trusted {
		trust = "trusted"
	}
	return repo, trust
}

// cacheFileKey maps the server-derived (repo, trust, logicalKey) triple onto
// the 64-hex on-disk key so a cache entry can never collide across
// repositories or trust domains.
func cacheFileKey(repo, trust, logicalKey string) string {
	sum := sha256.Sum256([]byte(repo + "\x00" + trust + "\x00" + logicalKey))
	return hex.EncodeToString(sum[:])
}

// cacheLease verifies the job-lease contract for a cache request via the
// shared authorizeRunnerLease gate: identity binding, a live lease, and the
// absence of the forbidden legacy namespace headers. On success it returns
// the leased job.
func (s *Server) cacheLease(w http.ResponseWriter, r *http.Request) (model.Job, string, bool) {
	// The namespace is server-derived; stale clients that still send the
	// repository/trust-domain headers are rejected so they fail loudly.
	if r.Header.Get("X-Kiwi-Repository") != "" || r.Header.Get("X-Kiwi-Trust-Domain") != "" {
		http.Error(w, "cache namespace headers are not accepted: the namespace is derived from the job lease", http.StatusBadRequest)
		return model.Job{}, "", false
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	j, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return model.Job{}, "", false
	}
	return j, runnerID, true
}

// uploadJobCache implements PUT /api/v1/jobs/{id}/cache/{key}. The payload
// is streamed into the shared content-addressed store (CAS) in BOTH modes —
// a filesystem-backed CAS under dataDir/cas in dev, the configured blob
// backend in HA — so dev and HA behave identically. A signed manifest
// binds (repo, trust_domain, logical_key) to the blob digest: persisted in
// the cache_manifests table in DB mode, next to the dataDir in fs mode.
// The namespace is derived from the leased job; the response carries the
// content digest and the manifest digest. The manifest must commit
// durably BEFORE the 201: a manifest failure fails the upload (5xx) so a
// cache entry can never exist without its signed mapping. The already
// written CAS blob is left in place as an orphan for the reference-aware
// blob GC — never deleted, because the digest may be referenced by
// another entry.
//
// Staging: the body spools into the server's shared bounded staging budget
// (never a bare system temp directory). The reservation is the request's
// Content-Length, or the endpoint maximum when the body length is unknown
// (chunked), so concurrent valid runners can never stage more than
// staging.max_bytes in total; the reservation is released on every exit
// path, including copy errors and client disconnects. A body that exceeds
// either the endpoint cap or the staging capacity is answered 413; a full
// budget blocks until room frees up or the request context ends.
func (s *Server) uploadJobCache(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "cache storage requires persistent server", http.StatusServiceUnavailable)
		return
	}
	if s.CAS == nil {
		http.Error(w, "cache storage requires a blob store", http.StatusServiceUnavailable)
		return
	}
	if s.Staging == nil {
		// Fail closed: without a bound this path would spool into unbounded
		// scratch space, exactly the control-plane root-filesystem
		// exhaustion it must not allow. Production startup refuses to serve
		// in this state; this is the belt-and-braces runtime guard.
		http.Error(w, "cache staging budget unavailable", http.StatusServiceUnavailable)
		return
	}
	j, runnerID, ok := s.cacheLease(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !cacheKeyRE.MatchString(key) {
		http.Error(w, "invalid cache key", 400)
		return
	}
	repo, trust := cacheNamespace(j)
	fileKey := cacheFileKey(repo, trust, key)
	// The body cap is the endpoint maximum; an oversized Content-Length is
	// rejected before any staging happens, and the stream is bounded at the
	// same value so an unknown-length (chunked) body cannot run past it.
	limit := cacheUploadMaxBytes
	cl := r.ContentLength
	if cl > limit {
		http.Error(w, cacheTooLargeError(), http.StatusRequestEntityTooLarge)
		return
	}
	reserve := limit
	if cl >= 0 {
		if cl > s.Staging.MaxBytes() {
			// The reservation can never succeed: refuse before staging.
			http.Error(w, "cache entry exceeds the staging capacity", http.StatusRequestEntityTooLarge)
			return
		}
		reserve = cl
	}
	res, err := s.Staging.Acquire(r.Context(), reserve)
	if err != nil {
		if errors.Is(err, staging.ErrBudgetExceeded) {
			s.logError("cache: staging reservation refused", "bytes", reserve, "budget", s.Staging.MaxBytes())
			http.Error(w, "cache staging capacity unavailable for this upload", http.StatusServiceUnavailable)
			return
		}
		if r.Context().Err() != nil {
			// The client is gone; there is nobody to answer.
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer res.Release()
	// Stage and hash on disk inside the budget directory, then publish: the
	// digest whose fence we take is the digest actually staged.
	stagedPath, n, err := staging.SpoolFile(s.Staging.Dir(), http.MaxBytesReader(w, r.Body, limit), reserve)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || errors.Is(err, staging.ErrTooLarge) {
			http.Error(w, cacheTooLargeError(), http.StatusRequestEntityTooLarge)
			return
		}
		if r.Context().Err() != nil {
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer func() { _ = os.Remove(stagedPath) }()
	if cacheStageHook != nil {
		cacheStageHook(stagedPath, reserve)
	}
	sum, err := fileSHA256(stagedPath)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	release, ferr := s.acquireDigestFence(r.Context(), sum)
	if ferr != nil {
		s.internalError(w, r, ferr, "")
		return
	}
	defer release()
	// Publish the STAGED file directly (no second copy): the CAS streams it
	// into the backend, verifies the content against the staged digest, and
	// validates the object the backend reports.
	obj, err := s.CAS.PutFile(r.Context(), stagedPath, sum, n)
	if err != nil {
		if casIntegrityError(err) {
			s.auditLocked("cache.integrity_failure", runnerID, j.RunID, j.ID, "cache CAS object disagrees with the staged bytes", map[string]string{"key": key, "want_sha256": sum, "want_size": strconv.FormatInt(n, 10), "error": err.Error()})
			http.Error(w, "cache storage verification failed", http.StatusServiceUnavailable)
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	// CAS integrity invariant: the published object must be exactly the
	// staged bytes. A backend that reports (or stores) a different digest or
	// size must never be acknowledged — otherwise the signed manifest would
	// bind the locally computed digest to a shared object that differs.
	if obj.Key != sum || obj.SHA256 != sum || obj.Size != n {
		s.auditLocked("cache.integrity_failure", runnerID, j.RunID, j.ID, "cache CAS object disagrees with the staged bytes", map[string]string{"key": key, "want_sha256": sum, "want_size": strconv.FormatInt(n, 10), "got_sha256": obj.SHA256, "got_size": strconv.FormatInt(obj.Size, 10)})
		http.Error(w, "cache storage verification failed", http.StatusServiceUnavailable)
		return
	}
	// Read-back verification (parity with the snapshot path): reopen the
	// newly written object, stream and hash it, and require the digest and
	// the exact byte length before the signed manifest is committed.
	if verr := verifyStoredBlob(r.Context(), s.CAS, sum, n); verr != nil {
		s.logError("cache: stored object verification failed", "sha256", sum, "error", verr.Error())
		http.Error(w, "cache storage verification failed", http.StatusServiceUnavailable)
		return
	}
	envelope, err := s.writeCacheManifest(r.Context(), fileKey, key, repo, trust, sum, n, j)
	if err != nil {
		// The manifest is the durable mapping: without it the blob is an
		// unreachable ORPHAN, and the upload fails closed. It is never
		// deleted here: CAS writes are append/deduplicate, so the digest
		// may be referenced by another cache entry or record; the
		// reference-aware blob GC owns orphan reclamation.
		s.logError("cache: manifest persist failed; blob left for GC", "sha256", sum, "error", err.Error())
		http.Error(w, "cache manifest persist failed", http.StatusInternalServerError)
		return
	}
	s.metricAdd("kiwi_cache_bytes_total", float64(n), nil)
	w.Header().Set("X-Kiwi-Cache-SHA256", sum)
	w.Header().Set("X-Kiwi-Content-SHA256", sum)
	w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(envelope))
	s.auditLocked("cache.uploaded", runnerID, j.RunID, j.ID, "cache entry stored", map[string]string{"key": key, "repository": repo, "trust_domain": trust})
	w.WriteHeader(http.StatusCreated)
}

// cacheTooLargeError renders the fixed cache body-cap rejection. It is
// deliberately free of request-supplied data so the 413 body is stable.
func cacheTooLargeError() string {
	return fmt.Sprintf("cache entry exceeds the %d-byte upload limit", cacheUploadMaxBytes)
}

// verifyStoredBlob reopens a just-published CAS object, streams and hashes
// it, and requires the digest and the exact byte length computed while the
// request body was staged. CAS.Open already fails a digest mismatch at EOF;
// this read-back additionally proves the object is readable and its length
// is what the committed record/manifest advertises. It is the artifact/cache
// counterpart of the snapshot path's verifyStoredSnapshot.
func verifyStoredBlob(ctx context.Context, c *cas.CAS, digest string, wantSize int64) error {
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
	if n != wantSize {
		return fmt.Errorf("stored object is %d bytes, want %d", n, wantSize)
	}
	if obj.Size != wantSize {
		return fmt.Errorf("stored object reports size %d, want %d", obj.Size, wantSize)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("stored object digest %s, want %s", got, digest)
	}
	return nil
}

// writeCacheManifest signs the cache manifest with the dedicated cache
// signing key and stores it durably: in DB mode as a cache_manifests row
// (the signed envelope rides the payload column), in fs mode as the
// manifest file next to the dataDir written atomically and fsynced. The
// namespace is server-derived from the leased job — repository and trust
// domain never come from client headers. It returns the signed envelope
// bytes and any persistence error.
func (s *Server) writeCacheManifest(ctx context.Context, fileKey, logicalKey, repo, trust, sum string, size int64, j model.Job) ([]byte, error) {
	signer := s.ensureCacheSigner()
	m := cache.CacheManifest{
		Version:     1,
		Repository:  repo,
		TrustDomain: trust,
		LogicalKey:  logicalKey,
		BlobSHA256:  sum,
		BlobSize:    size,
		ProducerRun: j.RunID,
		ProducerJob: j.ID,
		CreatedAt:   time.Now().UTC(),
	}
	b, err := cache.SignManifest(m, signer.KID, signer.Private)
	if err != nil {
		return nil, err
	}
	if s.DB != nil {
		if cs, ok := s.DB.(storage.CacheManifestStore); !ok {
			return nil, fmt.Errorf("cache manifest store unavailable")
		} else if err := cs.PutCacheManifest(ctx, storage.CacheManifestRecord{
			Repo:        repo,
			TrustDomain: trust,
			LogicalKey:  logicalKey,
			BlobSHA256:  sum,
			BlobSize:    size,
			ProducerRun: j.RunID,
			ProducerJob: j.ID,
			CreatedAt:   m.CreatedAt,
			Envelope:    b,
		}); err != nil {
			return nil, err
		}
		return b, nil
	}
	path := filepath.Join(s.store.Root, "cache", fileKey+".manifest.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := storage.AtomicWriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// writeFileSync writes data atomically via a temp file + rename and fsyncs
// the file before the rename so a durable manifest write cannot be lost by
// a crash.

// downloadJobCache implements GET /api/v1/jobs/{id}/cache/{key}. The
// namespace is resolved from the leased job, the manifest row (DB mode) or
// manifest file (fs mode) maps it to the blob digest, and the bytes stream
// from the shared CAS store so every replica serves the same entry. The
// signed envelope is verified in BOTH modes before any bytes are served: a
// tampered or unverifiable manifest never resolves a payload. The response
// headers keep the runner-facing contract: X-Kiwi-Cache-SHA256 is the
// manifest digest of the archive bytes.
func (s *Server) downloadJobCache(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "cache storage requires persistent server", http.StatusServiceUnavailable)
		return
	}
	if s.CAS == nil {
		http.Error(w, "cache storage requires a blob store", http.StatusServiceUnavailable)
		return
	}
	j, runnerID, ok := s.cacheLease(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if !cacheKeyRE.MatchString(key) {
		http.Error(w, "invalid cache key", 400)
		return
	}
	repo, trust := cacheNamespace(j)
	var (
		digest   string
		envelope []byte
	)
	if s.DB != nil {
		if cs, ok := s.DB.(storage.CacheManifestStore); ok {
			rec, found, err := cs.GetCacheManifest(r.Context(), repo, trust, key)
			if err != nil {
				s.internalError(w, r, err, "")
				return
			}
			if !found || rec.BlobSHA256 == "" {
				s.metricAdd("kiwi_cache_misses_total", 1, nil)
				http.NotFound(w, r)
				return
			}
			// DB restore verifies the signed envelope exactly like fs mode:
			// the persisted envelope is the authoritative record, and its
			// signature and digest must verify before the payload resolves.
			// A tampered row serves nothing — never a corrupt payload.
			m, verr := cache.VerifyManifest(rec.Envelope, s.ensureCacheSigner().Public)
			if verr != nil {
				s.metricAdd("kiwi_cache_misses_total", 1, nil)
				s.logError("cache: manifest verification failed", "error", verr.Error())
				http.Error(w, "cache manifest verification failed", http.StatusInternalServerError)
				return
			}
			if m.BlobSHA256 != rec.BlobSHA256 || m.BlobSHA256 == "" {
				s.metricAdd("kiwi_cache_misses_total", 1, nil)
				s.logError("cache: manifest digest mismatch", "row", rec.BlobSHA256, "envelope", m.BlobSHA256)
				http.NotFound(w, r)
				return
			}
			digest = m.BlobSHA256
			envelope = rec.Envelope
		}
	} else {
		fileKey := cacheFileKey(repo, trust, key)
		if b, err := os.ReadFile(filepath.Join(s.store.Root, "cache", fileKey+".manifest.json")); err == nil {
			envelope = b
			if m, verr := cache.VerifyManifest(b, s.ensureCacheSigner().Public); verr == nil {
				digest = m.BlobSHA256
			}
		}
	}
	if digest == "" {
		s.metricAdd("kiwi_cache_misses_total", 1, nil)
		http.NotFound(w, r)
		return
	}
	rc, _, err := s.CAS.Open(r.Context(), digest)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			s.metricAdd("kiwi_cache_misses_total", 1, nil)
			http.NotFound(w, r)
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	defer rc.Close()
	s.metricAdd("kiwi_cache_hits_total", 1, nil)
	w.Header().Set("X-Kiwi-Cache-SHA256", digest)
	w.Header().Set("X-Kiwi-Content-SHA256", digest)
	if len(envelope) > 0 {
		w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(envelope))
	}
	w.Header().Set("Content-Type", "application/gzip")
	n, _ := io.Copy(w, rc)
	s.metricAdd("kiwi_cache_bytes_total", float64(n), nil)
	s.auditLocked("cache.downloaded", runnerID, j.RunID, j.ID, "cache entry read", map[string]string{"key": key, "repository": repo, "trust_domain": trust})
}

// manifestDigestOf hashes a serialized manifest envelope for the response
// header.
func manifestDigestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Server) downloadProvenance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := s.artifactRecord(r.Context(), id)
	if err != nil || a.ProvenanceSHA256 == "" {
		http.NotFound(w, r)
		return
	}
	if !s.requireArtifactRead(w, r, a) {
		return
	}
	rc, err := s.openSidecar(r.Context(), a.ProvenancePath, a.ProvenanceSHA256)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
	w.Header().Set("X-Kiwi-Content-SHA256", a.ProvenanceSHA256)
	_, _ = io.Copy(w, rc)
}

// openSidecar resolves a sidecar (provenance/SBOM/sigstore) byte stream:
// records with a cas: digest reference stream from the shared CAS store;
// everything else falls back to the legacy local file (fs dev mode).
func (s *Server) openSidecar(ctx context.Context, pathRef, digest string) (io.ReadCloser, error) {
	if s.CAS != nil && strings.HasPrefix(pathRef, "cas:") {
		want := strings.TrimPrefix(pathRef, "cas:")
		if want == "" && digest != "" {
			want = digest
		}
		if want != "" {
			rc, _, err := s.CAS.Open(ctx, want)
			return rc, err
		}
	}
	if pathRef == "" {
		return nil, os.ErrNotExist
	}
	return os.Open(pathRef)
}

func (s *Server) cleanupExpiredArtifactsLocked(now time.Time) int {
	removed := 0
	for id, a := range s.artifacts {
		if a.ExpiresAt == nil || a.ExpiresAt.After(now) {
			continue
		}
		// CAS-mode records share content-addressed blobs; only the record
		// is removed, never the blob (other records may reference it).
		if !strings.HasPrefix(a.Path, "cas:") {
			_ = os.Remove(a.Path)
		}
		if a.ProvenancePath != "" {
			_ = os.Remove(a.ProvenancePath)
		}
		// FS/dev sidecars are immutable per (lease generation, artifact,
		// kind, digest): the record points at the exact digest-qualified
		// file, so ONLY that file is removed. Another generation's (or
		// another artifact's) sidecars live in different files and survive;
		// the per-generation directory is dropped only once it is empty.
		for _, p := range []string{a.SBOMPath, a.SigstorePath} {
			if p == "" || strings.HasPrefix(p, "cas:") {
				continue
			}
			_ = os.Remove(p)
			if genDir := filepath.Dir(p); strings.HasPrefix(filepath.Base(genDir), "g-") {
				_ = os.Remove(genDir)
			}
		}
		delete(s.artifacts, id)
		removed++
		s.auditLocked("artifact.expired", "scheduler", a.RunID, a.JobID, "artifact retention expired", map[string]string{"name": a.Name})
	}
	return removed
}

// SetBlobStore replaces the CAS blob backend (the app agent wires the S3
// backend here when config selects blob.backend = "s3"; the default remains
// the filesystem store under dataDir/cas). The replacement CAS is rebuilt
// through newServerCAS with the SAME authoritative object maximum and the
// server's current staging budget, so swapping the backend can never drop the
// bound or strand the fallback CAS.Put path without a spool budget.
func (s *Server) SetBlobStore(b blob.Store) {
	s.BlobStore = b
	s.CAS = newServerCAS(b, s.Staging)
}

func cleanBlobName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "..", "_")
	s = strings.Trim(s, " .")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

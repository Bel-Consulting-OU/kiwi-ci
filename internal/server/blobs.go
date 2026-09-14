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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const maxBlobBytes int64 = 8 << 30 // 8 GiB hard safety limit for the built-in store.
var cacheKeyRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

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
	jobID, name := r.PathValue("id"), cleanBlobName(r.PathValue("name"))
	if name == "" {
		http.Error(w, "invalid artifact name", http.StatusBadRequest)
		return
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	now := time.Now().UTC()
	if !s.verifyRunnerIdentity(r, runnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	run := model.Run{}
	if s.DB != nil {
		run, _ = s.DB.GetRun(r.Context(), j.RunID)
	} else {
		s.mu.Lock()
		run = s.runs[j.RunID]
		s.mu.Unlock()
	}
	if !s.validActiveLease(j, runnerID, token, gen, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	// Contract resolution: every upload name must trace to a declared
	// artifact (or its .sbom/.sigstore attestation sibling).
	contracts, err := s.contractsForJob(r.Context(), j)
	if err != nil {
		http.Error(w, err.Error(), 500)
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
func (s *Server) uploadArtifactPayload(w http.ResponseWriter, r *http.Request, j model.Job, run model.Run, contract storage.ArtifactContract, name, runnerID, token string, gen int64) {
	ctx := r.Context()
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// The critical section: idempotency check, staging, gate and record
	// insertion are atomic per job so concurrent re-uploads of the same
	// (job, generation, name) cannot interleave.
	lock := s.jobLock(j.ID)
	lock.Lock()
	defer lock.Unlock()

	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	tmp := filepath.Join(dir, "."+id+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	start := time.Now()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, maxBlobBytes))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstErr(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	digest := hex.EncodeToString(h.Sum(nil))
	// Contract size limit.
	if contract.MaxSize > 0 && n > contract.MaxSize {
		_ = os.Remove(tmp)
		s.auditLocked("artifact.contract_violation", runnerID, j.RunID, j.ID, "artifact exceeds declared max size", map[string]string{"name": name, "size": strconv.FormatInt(n, 10), "max": strconv.FormatInt(contract.MaxSize, 10)})
		http.Error(w, "artifact exceeds the declared maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	// Idempotency on (job, generation, name).
	if existing, lerr := s.findArtifactByJobName(ctx, j.RunID, j.ID, name); lerr == nil {
		if rec, found := existingArtifactForGeneration(existing, gen); found {
			_ = os.Remove(tmp)
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
		http.Error(w, lerr.Error(), 500)
		return
	}
	// SBOM/sigstore attestation gate: required attestations must be
	// present and valid before the payload is committed. The frozen
	// artifact contract is authoritative — the pipeline is never re-parsed.
	if code, msg := s.gateArtifactAttestations(contract, j, name, digest, dir); code != 0 {
		_ = os.Remove(tmp)
		http.Error(w, msg, code)
		return
	}
	dst := filepath.Join(dir, id+".tar.gz")
	// DB-mode CAS transport: the payload bytes become a CAS blob object
	// addressed by their digest (shared across replicas); the artifact
	// record carries the "cas:" marker path so downloads resolve through
	// the shared store. Legacy local files remain the fallback.
	casMode := s.DB != nil && s.CAS != nil
	if casMode {
		tf, oerr := os.Open(tmp)
		if oerr != nil {
			_ = os.Remove(tmp)
			http.Error(w, oerr.Error(), 500)
			return
		}
		if _, perr := s.CAS.Put(ctx, tf); perr != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			http.Error(w, perr.Error(), 500)
			return
		}
		_ = tf.Close()
		_ = os.Remove(tmp)
	} else {
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			http.Error(w, err.Error(), 500)
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
	attachSidecarsToRecord(&rec, j, name, dir)
	// Provenance signs with the dedicated provenance key — never the OIDC
	// key — so the two trust roots stay independent.
	finished := time.Now().UTC()
	signer := s.ensureProvenanceKey()
	st := provenance.ArtifactStatement(provenance.ArtifactInput{Name: name, SHA256: rec.SHA256, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Repository: run.RepoFullName, Ref: run.Ref, Commit: run.SHA, Runner: runnerID, Trusted: j.Trusted, Started: jobStart(j), Finished: finished})
	st.Builder = provenance.BuilderPlaceholder
	if env, er := provenance.Sign(st, signer.KID, signer.Private); er == nil {
		if ab, mer := json.MarshalIndent(env, "", "  "); mer == nil {
			ap := dst + ".intoto.json"
			if os.WriteFile(ap, ab, 0o600) == nil {
				sum := sha256.Sum256(ab)
				rec.ProvenancePath = ap
				rec.ProvenanceSHA256 = hex.EncodeToString(sum[:])
			}
		}
	}
	if s.DB != nil {
		if err := s.DB.InsertArtifact(ctx, rec); err != nil {
			_ = os.Remove(dst)
			http.Error(w, err.Error(), 500)
			return
		}
		s.metricAdd("kiwi_artifact_bytes_total", float64(n), nil)
		s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
		s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256, "provenance_kid": signer.KID})
		writeJSON(w, http.StatusCreated, rec)
		return
	}
	s.mu.Lock()
	s.artifacts[id] = rec
	s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256, "provenance_kid": signer.KID})
	_ = s.persistLocked()
	s.mu.Unlock()
	s.metricAdd("kiwi_artifact_bytes_total", float64(n), nil)
	s.metricObserve("kiwi_cas_latency_seconds", time.Since(start).Seconds(), nil)
	writeJSON(w, http.StatusCreated, rec)
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
		if _, err := s.DB.GetRun(r.Context(), runID); errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out, err := s.DB.ListArtifacts(r.Context(), runID)
		if err != nil {
			http.Error(w, err.Error(), 500)
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
	defer s.mu.Unlock()
	if _, ok := s.runs[runID]; !ok {
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

func (s *Server) uploadCache(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "cache storage requires persistent server", 503)
		return
	}
	key := r.PathValue("key")
	if !cacheKeyRE.MatchString(key) {
		http.Error(w, "invalid cache key", 400)
		return
	}
	dir := filepath.Join(s.store.Root, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	uniq, err := newID()
	if err != nil {
		http.Error(w, "internal server error", 500)
		return
	}
	tmp := filepath.Join(dir, "."+key+"."+uniq+".tmp")
	dst := filepath.Join(dir, key+".tar.gz")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	h := sha256.New()
	n, e1 := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, maxBlobBytes))
	e2 := f.Sync()
	e3 := f.Close()
	if err := firstErr(e1, e2, e3); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	_ = os.WriteFile(dst+".sha256", []byte(sum), 0o600)
	w.Header().Set("X-Kiwi-Content-SHA256", sum)
	s.metricAdd("kiwi_cache_bytes_total", float64(n), nil)
	if s.DB != nil {
		s.writeCacheManifest(w, r, key, sum, n)
	}
	w.WriteHeader(http.StatusCreated)
}

// writeCacheManifest records a signed cache manifest next to the blob in DB
// mode. The namespace is derived from the request's repository/trust-domain
// headers (set by the runner client); the manifest is signed with the
// dedicated cache signing key so cache consumers can pin one trust root.
func (s *Server) writeCacheManifest(w http.ResponseWriter, r *http.Request, key, sum string, size int64) {
	repo := cleanBlobName(r.Header.Get("X-Kiwi-Repository"))
	trust := cleanBlobName(r.Header.Get("X-Kiwi-Trust-Domain"))
	if repo == "" {
		return
	}
	if trust == "" {
		trust = "untrusted"
	}
	signer := s.ensureCacheSigner()
	m := cache.CacheManifest{
		Version:     1,
		Repository:  repo,
		TrustDomain: trust,
		LogicalKey:  key,
		BlobSHA256:  sum,
		BlobSize:    size,
		CreatedAt:   time.Now().UTC(),
	}
	b, err := cache.SignManifest(m, signer.KID, signer.Private)
	if err != nil {
		return
	}
	path := filepath.Join(s.store.Root, "cache", key+".manifest.json")
	_ = writeFileAtomic(path, b, 0o600)
	w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(b))
}
func (s *Server) downloadCache(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "cache storage requires persistent server", 503)
		return
	}
	key := r.PathValue("key")
	if !cacheKeyRE.MatchString(key) {
		http.Error(w, "invalid cache key", 400)
		return
	}
	path := filepath.Join(s.store.Root, "cache", key+".tar.gz")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.metricAdd("kiwi_cache_misses_total", 1, nil)
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
	s.metricAdd("kiwi_cache_hits_total", 1, nil)
	if b, err := os.ReadFile(path + ".sha256"); err == nil {
		w.Header().Set("X-Kiwi-Content-SHA256", strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile(path + ".manifest.json"); err == nil {
		w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(b))
	}
	w.Header().Set("Content-Type", "application/gzip")
	n, _ := io.Copy(w, f)
	s.metricAdd("kiwi_cache_bytes_total", float64(n), nil)
}

// manifestDigestOf hashes a serialized manifest envelope for the response
// header.
func manifestDigestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Server) downloadProvenance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	a, ok := s.artifacts[id]
	s.mu.Unlock()
	if !ok || a.ProvenancePath == "" {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(a.ProvenancePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.dsse.envelope.v1+json")
	w.Header().Set("X-Kiwi-Content-SHA256", a.ProvenanceSHA256)
	_, _ = w.Write(b)
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
		delete(s.artifacts, id)
		removed++
		s.auditLocked("artifact.expired", "scheduler", a.RunID, a.JobID, "artifact retention expired", map[string]string{"name": a.Name})
	}
	return removed
}

// SetBlobStore replaces the CAS blob backend (the app agent wires the S3
// backend here when config selects blob.backend = "s3"; the default remains
// the filesystem store under dataDir/cas).
func (s *Server) SetBlobStore(b blob.Store) {
	s.BlobStore = b
	s.CAS = cas.New(b)
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

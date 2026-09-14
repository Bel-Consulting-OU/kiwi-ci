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
	if code, msg := s.gateArtifactAttestations(ctx, contract, j, name, digest, dir); code != 0 {
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
	s.attachSidecarsToRecord(r.Context(), &rec, j, name, dir)
	// Provenance signs with the dedicated provenance key — never the OIDC
	// key — so the two trust roots stay independent.
	finished := time.Now().UTC()
	signer := s.ensureProvenanceKey()
	st := provenance.ArtifactStatement(provenance.ArtifactInput{Name: name, SHA256: rec.SHA256, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Repository: run.RepoFullName, Ref: run.Ref, Commit: run.SHA, Runner: runnerID, Trusted: j.Trusted, Started: jobStart(j), Finished: finished})
	st.Builder = provenance.BuilderPlaceholder
	if env, er := provenance.Sign(st, signer.KID, signer.Private); er == nil {
		if ab, mer := json.MarshalIndent(env, "", "  "); mer == nil {
			sum := sha256.Sum256(ab)
			provDigest := hex.EncodeToString(sum[:])
			// HA sidecars: the envelope bytes live in the shared CAS store
			// and the record carries the digest reference; fs dev mode
			// keeps the local sidecar file for compatibility.
			if casMode {
				if _, perr := s.CAS.Put(ctx, bytes.NewReader(ab)); perr == nil {
					rec.ProvenancePath = "cas:" + provDigest
					rec.ProvenanceSHA256 = provDigest
				}
			} else {
				ap := dst + ".intoto.json"
				if os.WriteFile(ap, ab, 0o600) == nil {
					rec.ProvenancePath = ap
					rec.ProvenanceSHA256 = provDigest
				}
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
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunArtifactRead(w, r, run) {
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
// repository identity (preferring the full name, falling back to the repo
// URL) and the trust domain. Clients can never influence the namespace:
// the legacy X-Kiwi-Repository/X-Kiwi-Trust-Domain headers are rejected.
func cacheNamespace(j model.Job) (repo, trust string) {
	repo = j.RepoFullName
	if repo == "" {
		repo = j.RepoURL
	}
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

// cacheLease verifies the job-lease contract for a cache request: identity
// binding, a live lease, and the absence of the forbidden legacy namespace
// headers. On success it returns the leased job.
func (s *Server) cacheLease(w http.ResponseWriter, r *http.Request) (model.Job, string, bool) {
	jobID := r.PathValue("id")
	// The namespace is server-derived; stale clients that still send the
	// repository/trust-domain headers are rejected so they fail loudly.
	if r.Header.Get("X-Kiwi-Repository") != "" || r.Header.Get("X-Kiwi-Trust-Domain") != "" {
		http.Error(w, "cache namespace headers are not accepted: the namespace is derived from the job lease", http.StatusBadRequest)
		return model.Job{}, "", false
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	if !s.verifyRunnerIdentity(r, runnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return model.Job{}, "", false
	}
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return model.Job{}, "", false
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return model.Job{}, "", false
	}
	if !s.validActiveLease(j, runnerID, token, gen, time.Now().UTC()) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
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
// content digest and the manifest digest.
func (s *Server) uploadJobCache(w http.ResponseWriter, r *http.Request) {
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
	fileKey := cacheFileKey(repo, trust, key)
	obj, err := s.CAS.Put(r.Context(), http.MaxBytesReader(w, r.Body, maxBlobBytes))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sum := obj.SHA256
	size := obj.Size
	s.metricAdd("kiwi_cache_bytes_total", float64(size), nil)
	w.Header().Set("X-Kiwi-Cache-SHA256", sum)
	w.Header().Set("X-Kiwi-Content-SHA256", sum)
	s.writeCacheManifest(w, r.Context(), fileKey, key, repo, trust, sum, size, j)
	s.auditLocked("cache.uploaded", runnerID, j.RunID, j.ID, "cache entry stored", map[string]string{"key": key, "repository": repo, "trust_domain": trust})
	w.WriteHeader(http.StatusCreated)
}

// writeCacheManifest signs the cache manifest with the dedicated cache
// signing key and stores it: in DB mode as a cache_manifests row, in fs
// mode as the manifest file next to the dataDir. The namespace is
// server-derived from the leased job — repository and trust domain never
// come from client headers.
func (s *Server) writeCacheManifest(w http.ResponseWriter, ctx context.Context, fileKey, logicalKey, repo, trust, sum string, size int64, j model.Job) {
	signer := s.ensureCacheSigner()
	m := cache.CacheManifest{
		Version:     1,
		Repository:  repo,
		TrustDomain: trust,
		LogicalKey:  logicalKey,
		BlobSHA256:  sum,
		BlobSize:    size,
		CreatedAt:   time.Now().UTC(),
	}
	b, err := cache.SignManifest(m, signer.KID, signer.Private)
	if err != nil {
		return
	}
	if s.DB != nil {
		if cs, ok := s.DB.(storage.CacheManifestStore); ok {
			if err := cs.PutCacheManifest(ctx, storage.CacheManifestRecord{
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
				s.logError("cache: manifest persist failed", "error", err.Error())
				return
			}
		}
		w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(b))
		return
	}
	path := filepath.Join(s.store.Root, "cache", fileKey+".manifest.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		s.logError("cache: manifest dir failed", "error", err.Error())
		return
	}
	_ = writeFileAtomic(path, b, 0o600)
	w.Header().Set("X-Kiwi-Cache-Manifest-SHA256", manifestDigestOf(b))
}

// downloadJobCache implements GET /api/v1/jobs/{id}/cache/{key}. The
// namespace is resolved from the leased job, the manifest row (DB mode) or
// manifest file (fs mode) maps it to the blob digest, and the bytes stream
// from the shared CAS store so every replica serves the same entry. The
// response headers keep the runner-facing contract: X-Kiwi-Cache-SHA256 is
// the manifest digest of the archive bytes.
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
				http.Error(w, err.Error(), 500)
				return
			}
			if !found || rec.BlobSHA256 == "" {
				s.metricAdd("kiwi_cache_misses_total", 1, nil)
				http.NotFound(w, r)
				return
			}
			digest = rec.BlobSHA256
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
		http.Error(w, err.Error(), 500)
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

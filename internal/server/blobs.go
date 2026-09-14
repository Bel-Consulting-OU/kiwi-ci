package server

import (
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
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const maxBlobBytes int64 = 8 << 30 // 8 GiB hard safety limit for the built-in store.
var cacheKeyRE = regexp.MustCompile(`^[a-f0-9]{64}$`)

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

	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	dir := filepath.Join(s.store.Root, "artifacts", j.RunID, j.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), 500)
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
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		http.Error(w, firstErr(copyErr, syncErr, closeErr).Error(), 500)
		return
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, err.Error(), 500)
		return
	}
	createdAt := time.Now().UTC()
	rec := model.ArtifactRecord{ID: id, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Name: name, Path: dst, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), ContentType: "application/gzip", CreatedAt: createdAt}
	retention := artifactRetention(j, name)
	if retention > 0 {
		expires := createdAt.Add(retention)
		rec.ExpiresAt = &expires
	}
	finished := time.Now().UTC()
	started := finished
	if j.StartedAt != nil {
		started = *j.StartedAt
	}
	if s.oidc != nil {
		st := provenance.ArtifactStatement(provenance.ArtifactInput{Name: name, SHA256: rec.SHA256, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Repository: run.RepoFullName, Ref: run.Ref, Commit: run.SHA, Runner: runnerID, Trusted: j.Trusted, Started: started, Finished: finished})
		env, er := provenance.Sign(st, s.oidc.KID, s.oidc.Private)
		if er == nil {
			ab, _ := json.MarshalIndent(env, "", "  ")
			ap := dst + ".intoto.json"
			if os.WriteFile(ap, ab, 0o600) == nil {
				sum := sha256.Sum256(ab)
				rec.ProvenancePath = ap
				rec.ProvenanceSHA256 = hex.EncodeToString(sum[:])
			}
		}
	}
	s.mu.Lock()
	current, still := s.jobs[jobID]
	leaseValid := still && s.validActiveLease(current, runnerID, token, gen, time.Now().UTC())
	s.mu.Unlock()
	if s.DB != nil {
		current, gerr := s.jobForLease(r.Context(), jobID)
		if gerr != nil || !s.validActiveLease(current, runnerID, token, gen, time.Now().UTC()) {
			_ = os.Remove(dst)
			http.Error(w, "lease expired during upload", http.StatusConflict)
			return
		}
		leaseValid = true
	}
	if !leaseValid {
		_ = os.Remove(dst)
		http.Error(w, "lease expired during upload", http.StatusConflict)
		return
	}
	if s.DB != nil {
		if err := s.DB.InsertArtifact(r.Context(), rec); err != nil {
			_ = os.Remove(dst)
			http.Error(w, err.Error(), 500)
			return
		}
		s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256})
		writeJSON(w, http.StatusCreated, rec)
		return
	}
	s.mu.Lock()
	s.artifacts[id] = rec
	s.auditLocked("artifact.uploaded", runnerID, j.RunID, j.ID, "artifact uploaded", map[string]string{"name": name, "sha256": rec.SHA256})
	_ = s.persistLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, rec)
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
		for i := range out {
			out[i].Path = ""
			out[i].ProvenancePath = ""
		}
		writeJSON(w, 200, out)
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
	writeJSON(w, 200, out)
}
func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	a, ok := s.artifacts[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(a.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, cleanBlobName(a.Name)))
	w.Header().Set("X-Kiwi-Content-SHA256", a.SHA256)
	w.Header().Set("Content-Length", strconv.FormatInt(a.Size, 10))
	_, _ = io.Copy(w, f)
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
	_, e1 := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, maxBlobBytes))
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
	w.WriteHeader(http.StatusCreated)
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
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = io.Copy(w, f)
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
		_ = os.Remove(a.Path)
		if a.ProvenancePath != "" {
			_ = os.Remove(a.ProvenancePath)
		}
		delete(s.artifacts, id)
		removed++
		s.auditLocked("artifact.expired", "scheduler", a.RunID, a.JobID, "artifact retention expired", map[string]string{"name": a.Name})
	}
	return removed
}

func artifactRetention(j model.Job, name string) time.Duration {
	const defaultRetention = 30 * 24 * time.Hour
	spec, err := pipeline.Parse([]byte(j.Pipeline))
	if err != nil {
		return defaultRetention
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return defaultRetention
	}
	cj, ok := g.Jobs[j.Key]
	if !ok {
		return defaultRetention
	}
	for _, a := range cj.Job.Artifacts {
		if a.Name != name {
			continue
		}
		d, err := pipeline.ParseRetention(a.Retention)
		if err != nil || d == 0 {
			return defaultRetention
		}
		if d < 0 {
			return 0
		}
		return d
	}
	return defaultRetention
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

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// seedCacheJob installs a running job with a valid lease directly into the
// server state, returning the lease headers.
func seedCacheJob(t *testing.T, s *Server, jobID, runnerID, repoURL, repoFullName string, trusted bool) map[string]string {
	t.Helper()
	raw := "cache-lease-token"
	exp := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: repoURL, RepoFullName: repoFullName, Status: model.StatusRunning}
	s.jobs[jobID] = model.Job{ID: jobID, RunID: "run-c", Key: "build", RepoURL: repoURL, RepoFullName: repoFullName,
		Status: model.StatusRunning, Trusted: trusted, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, raw), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	s.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
	s.mu.Unlock()
	return map[string]string{"X-Kiwi-Runner-ID": runnerID, "X-Kiwi-Lease-Token": raw, "X-Kiwi-Lease-Generation": "5"}
}

func TestJobCacheLeaseNamespacedPutGet(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	key := strings.Repeat("a", 64)

	// PUT under the runner token with a valid lease.
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "cache-payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	// GET by the same runner/lease hits.
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusOK {
		t.Fatalf("cache get = %d: %s", w.Code, w.Body.String())
	}
	if got := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); got.Body.String() != "cache-payload" {
		t.Fatalf("cache payload = %q", got.Body.String())
	}

	// A different repository's runner resolves a different namespace: 404.
	hdrsB := seedCacheJob(t, s, "job-b", "runner-b", "https://github.com/o/repo-b.git", "o/repo-b", true)
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-b/cache/"+key, "runner-tok", "", hdrsB); w.Code != http.StatusNotFound {
		t.Fatalf("cross-repo cache get: want 404 got %d", w.Code)
	}
	// A different trust domain (untrusted) also namespaces apart.
	hdrsU := seedCacheJob(t, s, "job-u", "runner-u", "https://github.com/o/repo-a.git", "o/repo-a", false)
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-u/cache/"+key, "runner-tok", "", hdrsU); w.Code != http.StatusNotFound {
		t.Fatalf("cross-trust cache get: want 404 got %d", w.Code)
	}
}

func TestJobCacheRejectsNamespaceHeaders(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	key := strings.Repeat("c", 64)
	// Stale clients sending the legacy namespace headers are rejected.
	legacy := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": "cache-lease-token", "X-Kiwi-Lease-Generation": "5", "X-Kiwi-Repository": "o/repo-a", "X-Kiwi-Trust-Domain": "trusted"}
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "x", legacy); w.Code != http.StatusBadRequest {
		t.Fatalf("namespace header put: want 400 got %d", w.Code)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", legacy); w.Code != http.StatusBadRequest {
		t.Fatalf("namespace header get: want 400 got %d", w.Code)
	}
	_ = hdrs
}

func TestJobCacheRequiresLeaseAndRunnerToken(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("d", 64)
	// No bearer at all: the runner tier rejects.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/job-x/cache/"+key, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token cache get: want 401 got %d", w.Code)
	}
	// Runner bearer but no lease: the handler rejects (409).
	noLease := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": "nope", "X-Kiwi-Lease-Generation": "1"}
	seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "x", noLease); w.Code != http.StatusConflict {
		t.Fatalf("no-lease cache put: want 409 got %d", w.Code)
	}
	// Admin token cannot use the runner-tier cache route.
	hdrs := seedCacheJob(t, s, "job-b", "runner-b", "https://github.com/o/repo-a.git", "o/repo-a", true)
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-b/cache/"+key, "admin-tok", "", hdrs); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin token on runner cache route: want 401 got %d", w.Code)
	}
}

func TestLegacyCacheRoutesRemoved(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("e", 64)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/cache/"+key, "token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("legacy cache GET: want 404 got %d", w.Code)
	}
	// PUT resolves through no handler: the mux answers 404/405 (method not
	// allowed) because only the job-scoped cache routes exist.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/cache/"+key, "token", "x"); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("legacy cache PUT: want 404/405 got %d", w.Code)
	}
}

func TestCacheManifestCarriesServerDerivedNamespace(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	// DB mode resolves the job through the store: mirror the seeded job.
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", Capacity: 1}
	f.mu.Unlock()
	key := strings.Repeat("f", 64)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Cache-Manifest-SHA256") == "" {
		t.Fatal("missing cache manifest digest header")
	}
	repo, trust := cacheNamespace(s.mustJob("job-a"))
	f.mu.Lock()
	rec, ok := f.cacheMans[repo+"\x00"+trust+"\x00"+key]
	f.mu.Unlock()
	if !ok {
		t.Fatal("manifest row not persisted through CacheManifestStore")
	}
	m, err := cache.VerifyManifest(rec.Envelope, s.ensureCacheSigner().Public)
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
	if m.Repository != "github.com/o/repo-a" || m.TrustDomain != "trusted" || m.LogicalKey != key {
		t.Fatalf("manifest namespace mismatch: repo=%q trust=%q key=%q", m.Repository, m.TrustDomain, m.LogicalKey)
	}
	if rec.BlobSHA256 != m.BlobSHA256 || rec.BlobSHA256 == "" {
		t.Fatalf("manifest blob digest mismatch: %q", rec.BlobSHA256)
	}
	if rec.ProducerRun != "run-c" || rec.ProducerJob != "job-a" {
		t.Fatalf("manifest producer provenance = %s/%s", rec.ProducerRun, rec.ProducerJob)
	}
	// GET resolves the manifest row and streams the blob from CAS; the
	// runner-facing digest header matches the content.
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("cache get = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "payload" {
		t.Fatalf("cache payload = %q", w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-Cache-SHA256"); got != m.BlobSHA256 {
		t.Fatalf("X-Kiwi-Cache-SHA256 = %q, want %q", got, m.BlobSHA256)
	}
}

func (s *Server) mustJob(id string) model.Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fcProducerFixture installs a consumer job (key consume, pipeline
// producerPipeline) plus a producer job (key build) in run-c with a valid
// consumer lease.
func fcProducerFixture(t *testing.T) (*Server, map[string]string, string) {
	t.Helper()
	s, hdrs := fcMemoryBlobServer(t)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	s.mu.Lock()
	consumer := s.jobs["job-a"]
	consumer.Key = "consume"
	consumer.Pipeline = producerPipeline
	consumer.Needs = []string{"job-build"}
	consumer.LeaseExpiresAt = &exp
	s.jobs["job-a"] = consumer
	s.jobs["job-build"] = model.Job{
		ID: "job-build", RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git",
		RepoFullName: "o/repo-a", Status: model.StatusSuccess, Pipeline: producerPipeline,
		CreatedAt: now, FinishedAt: &now,
	}
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	s.mu.Unlock()
	return s, hdrs, "job-a"
}

func fcSeedProducerArtifact(t *testing.T, s *Server, id, path string) {
	t.Helper()
	s.mu.Lock()
	s.artifacts[id] = model.ArtifactRecord{ID: id, RunID: "run-c", JobID: "job-build", JobKey: "build", Name: "bin", Path: path, Size: 3, SHA256: sha256Hex([]byte("abc")), ContentType: "application/gzip", CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
}

func TestFlowProducerInvalidArtifactName(t *testing.T) {
	s := New("tok")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/j/dependencies/build/x", nil)
	r.SetPathValue("id", "j")
	r.SetPathValue("producer", "build")
	r.SetPathValue("artifact", "  ")
	w := httptest.NewRecorder()
	s.downloadDependency(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("blank artifact name = %d, want 400", w.Code)
	}
}

func TestFlowProducerPipelineUnavailable(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("pipeline unavailable = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerUndeclaredName(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/lib", "runner-tok", "", hdrs)
	if w.Code != http.StatusForbidden {
		t.Fatalf("undeclared artifact = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerNotADependency(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	s.mu.Lock()
	consumer := s.jobs[jobID]
	consumer.Needs = nil
	s.jobs[jobID] = consumer
	s.mu.Unlock()
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusForbidden {
		t.Fatalf("producer not a dependency = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerUnknownContractName(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	// The producer's pipeline declares no artifacts at all.
	s.mu.Lock()
	p := s.jobs["job-build"]
	p.Pipeline = "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n"
	s.jobs["job-build"] = p
	s.mu.Unlock()
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown contract name = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerAmbiguousMatch(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	now := time.Now().UTC()
	s.mu.Lock()
	consumer := s.jobs[jobID]
	consumer.Needs = []string{"job-build", "job-build2"}
	s.jobs[jobID] = consumer
	s.jobs["job-build2"] = model.Job{ID: "job-build2", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: producerPipeline, CreatedAt: now}
	s.mu.Unlock()
	dir := t.TempDir()
	f1 := filepath.Join(dir, "b1")
	f2 := filepath.Join(dir, "b2")
	for _, p := range []string{f1, f2} {
		if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fcSeedProducerArtifact(t, s, "art-1", f1)
	s.mu.Lock()
	s.artifacts["art-2"] = model.ArtifactRecord{ID: "art-2", RunID: "run-c", JobID: "job-build2", JobKey: "build", Name: "bin", Path: f2, Size: 3, SHA256: sha256Hex([]byte("abc"))}
	s.mu.Unlock()
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("ambiguous match = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerArtifactBytesMissing(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	fcSeedProducerArtifact(t, s, "art-broken", filepath.Join(t.TempDir(), "gone"))
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing artifact bytes = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerDownloadSuccessAndWriteFailure(t *testing.T) {
	s, hdrs, jobID := fcProducerFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bin.tar.gz")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	fcSeedProducerArtifact(t, s, "art-ok", path)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK || w.Body.String() != "abc" {
		t.Fatalf("dependency download = %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Producer-Job") != "build" {
		t.Fatal("missing producer header")
	}

	// A response writer that fails mid-stream must abort the handler: the
	// integrity copy path panics with http.ErrAbortHandler so the connection
	// is closed instead of silently completing a truncated response.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", nil)
	r.SetPathValue("id", jobID)
	r.SetPathValue("producer", "build")
	r.SetPathValue("artifact", "bin")
	r.Header.Set("X-Kiwi-Runner-ID", "runner-a")
	r.Header.Set("X-Kiwi-Lease-Token", "cache-lease-token")
	r.Header.Set("X-Kiwi-Lease-Generation", "5")
	fw := &fcFailWriter{limit: 0}
	func() {
		defer func() {
			rec := recover()
			err, ok := rec.(error)
			if rec == nil || !ok || !errors.Is(err, http.ErrAbortHandler) {
				t.Fatalf("write-failure download panic = %v, want http.ErrAbortHandler", rec)
			}
		}()
		s.downloadDependency(fw, r)
	}()
	if got := fw.Header().Get("X-Kiwi-Producer-Job"); got != "build" {
		t.Fatalf("write-failure download did not reach the copy stage: header %q", got)
	}
}

func TestFlowProducerDBContractLookupFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	hdrs := fcDBProducerSetup(t, s, f)
	s.DB = &fcStore{dbFakeStore: f, getContractsErr: errors.New("contract table down")}
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-consume/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusNotFound {
		t.Fatalf("db contract lookup failure = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestFlowProducerDBArtifactListFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	hdrs := fcDBProducerSetup(t, s, f)
	s.DB = &fcStore{dbFakeStore: f, listArtifactsErr: errors.New("artifact table down")}
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-consume/dependencies/build/bin", "runner-tok", "", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("db artifact list failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// fcDBProducerSetup installs a consumer/producer pair in the DB fake and
// returns the consumer lease headers.
func fcDBProducerSetup(t *testing.T, s *Server, f *dbFakeStore) map[string]string {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	f.jobs["job-build"] = model.Job{ID: "job-build", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: producerPipeline,
		RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.jobs["job-consume"] = model.Job{ID: "job-consume", RunID: "run-c", Key: "consume", Status: model.StatusRunning, Pipeline: producerPipeline,
		RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp,
		Needs: []string{"job-build"}}
	f.contracts["job-build"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "art-db", RunID: "run-c", JobID: "job-build", JobKey: "build", Name: "bin", Path: "cas:" + sha256Hex([]byte("abc")), Size: 3, SHA256: sha256Hex([]byte("abc"))})
	f.mu.Unlock()
	return map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": "cache-lease-token", "X-Kiwi-Lease-Generation": "5"}
}

func TestFlowProducerEachJobByRunDB(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listJobsErr: errors.New("job list down")}
	called := false
	s.eachJobByRun(context.Background(), "run-c", func(model.Job) { called = true })
	if called {
		t.Fatal("list failure must not invoke the callback")
	}
	// Memory path iterates the run's jobs.
	s2, _ := fcMemoryBlobServer(t)
	count := 0
	s2.eachJobByRun(context.Background(), "run-c", func(model.Job) { count++ })
	if count != 1 {
		t.Fatalf("memory iteration visited %d jobs, want 1", count)
	}
}

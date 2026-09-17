package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIDCovGetRunAndLogsDBEdges covers the plain DB read success and the
// getLogs resolver failure.
func TestIDCovGetRunAndLogsDBEdges(t *testing.T) {
	f := newDBFakeStore()
	f.mu.Lock()
	f.runs["run-ok"] = model.Run{ID: "run-ok", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	f.mu.Unlock()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-ok", "admin", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "run-ok") {
		t.Fatalf("db getRun = %d: %s", w.Code, w.Body.String())
	}
	// A run resolver failure on the logs route is a 500.
	fault := &idcovFaultStore{dbFakeStore: f, getRunErr: errors.New("run read failed")}
	s.DB = fault
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-ok/logs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing logs resolver = %d, want 500", w.Code)
	}
}

// TestIDCovServingBareAliasVisibility covers the bare-alias serving
// projection: the run's canonical id carries a host, its full name does not
// match the alias directly.
func TestIDCovServingBareAliasVisibility(t *testing.T) {
	s := New("admin")
	s.mu.Lock()
	s.runners["r-serv"] = model.Runner{ID: "r-serv", Name: "rs", Capacity: 1, ActiveJobs: []string{"job-bare"}}
	s.jobs["job-bare"] = model.Job{ID: "job-bare", RunID: "run-bare", Key: "build", Status: model.StatusRunning}
	s.runs["run-bare"] = model.Run{ID: "run-bare", RepoID: "github.com/acme/service", RepoFullName: "acme/service-full", Status: model.StatusRunning}
	s.mu.Unlock()
	principal := auth.Principal{Subject: "u", Roles: []auth.Role{auth.RoleRead}, Repositories: map[string]auth.RepositoryPermission{"acme/service": {Read: true}}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runners/serving", nil)
	req = req.WithContext(auth.WithPrincipal(context.Background(), principal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "job-bare") {
		t.Fatalf("bare-alias serving = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovRunnerDisableMemoryEdges covers the unknown-runner refusal and
// the decoy-job skip in the memory kill switch.
func TestIDCovRunnerDisableMemoryEdges(t *testing.T) {
	s := New("admin")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/ghost/disable", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown disable = %d, want 404", w.Code)
	}
	// A running job held by another runner is skipped by the kill switch.
	idcovSeedMemoryJob(t, s, "job-other", "run-other", "r-other", "tok", nil)
	idcovSeedMemoryJob(t, s, "job-mine", "run-mine", "r-mine", "tok", nil)
	s.mu.Lock()
	s.runners["r-mine"] = model.Runner{ID: "r-mine", Name: "rm", Capacity: 1, ActiveJobs: []string{"job-mine"}}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-mine/disable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	other := s.jobs["job-other"]
	mine := s.jobs["job-mine"]
	s.mu.Unlock()
	if other.Status != model.StatusRunning {
		t.Fatalf("other runner's job was cancelled: %q", other.Status)
	}
	if mine.Status != model.StatusCancelled {
		t.Fatalf("own job was not cancelled: %q", mine.Status)
	}
}

// TestIDCovCompleteDBUnknownJob covers the lease-gate 404 render.
func TestIDCovCompleteDBUnknownJob(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := `{"runner_id":"runner-a","lease_token":"tok","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/ghost/complete", []byte(body), "secret", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown job completion = %d, want 404: %s", w.Code, w.Body.String())
	}
}

// TestIDCovCompleteDBStaleReplaySucceeds covers the 204 acknowledgement of a
// stale-lease replay whose fast-path receipt check missed.
func TestIDCovCompleteDBStaleReplaySucceeds(t *testing.T) {
	f := newDBFakeStore()
	hash := completionResultHash(model.StatusFailure, "", nil)
	store := &idcovReceiptScriptStore{dbFakeStore: f}
	store.fn = func(n int) (model.CompletionReceipt, bool, error) {
		if n == 1 {
			return model.CompletionReceipt{}, false, nil
		}
		return model.CompletionReceipt{JobID: "job-ok", Generation: 1, RunnerID: "runner-a", ResultHash: hash}, true, nil
	}
	s := New("secret")
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	idcovSeedDBRunningJob(t, s, f, "job-ok", "run-ok", "req-token")
	f.mu.Lock()
	j := f.jobs["job-ok"]
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, "different")
	f.jobs["job-ok"] = j
	f.mu.Unlock()
	body := `{"runner_id":"runner-a","lease_token":"req-token","lease_generation":1,"status":"failure"}`
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/jobs/job-ok/complete", []byte(body), "secret", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("stale replay = %d, want 204: %s", w.Code, w.Body.String())
	}
}

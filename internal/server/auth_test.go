package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

const approvalPipeline = `version: 1
jobs:
  deploy:
    runtime: container
    image: ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      approval: true
    steps:
      - run: echo hi
`

// storeServer builds a server whose API auth comes from the given store
// principals; adminToken may be "" to exercise store-only mode.
func storeServer(t *testing.T, adminToken string, tokens map[string]auth.Principal) *Server {
	t.Helper()
	s := New("")
	s.AdminToken = adminToken
	for raw, p := range tokens {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestSubmitAuthorizedViaStorePrincipal(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"ci-token": {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	c := newTestClient(t, s.Handler(), "ci-token")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit via store principal: want 202 got %d: %s", w.Code, w.Body.String())
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	got := s.runs[run.ID]
	s.mu.Unlock()
	if got.Trusted {
		t.Fatal("store-principal submission must be untrusted")
	}
}

// modelRunID is a minimal decode target for run responses.
type modelRunID struct {
	ID string `json:"id"`
}

func TestSubmitForbiddenWithoutRunRole(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	c := newTestClient(t, s.Handler(), "read-token")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("submit without run role: want 403 got %d: %s", w.Code, w.Body.String())
	}
}

func TestStoreModeRejectsMissingAndBadTokens(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"ci-token": {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	h := s.Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token in store mode: want 401 got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer wrong")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token in store mode: want 401 got %d", w.Code)
	}
}

func TestAdminStorePrincipalOnAdminRoutes(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"ops-token": {Subject: "ops", Roles: []auth.Role{auth.RoleAdmin}},
		"ci-token":  {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	h := s.Handler()
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"admin store principal", "ops-token", http.StatusOK},
		{"run-only principal denied", "ci-token", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("%s: want %d got %d", tc.name, tc.want, w.Code)
		}
	}
}

func TestLegacyAdminTokenStillAuthorizesActions(t *testing.T) {
	// Dev mode (empty store): the AdminToken bearer maps to the admin
	// principal and passes every action.
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("admin token submit: want 202 got %d: %s", w.Code, w.Body.String())
	}
	w = c.do(http.MethodGet, "/api/v1/runs", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin token list: want 200 got %d", w.Code)
	}
}

func TestApproveIgnoresActorHeader(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for raw, p := range map[string]auth.Principal{
		"reviewer": {Subject: "reviewer-bot", Roles: []auth.Role{auth.RoleApprove}},
		"ops":      {Subject: "ops", Roles: []auth.Role{auth.RoleAdmin}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestClient(t, s.Handler(), "admin-tok")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: approvalPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: want 202 got %d: %s", w.Code, w.Body.String())
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	var jobID string
	for _, j := range s.jobs {
		if j.RunID == run.ID && j.ApprovalRequired {
			jobID = j.ID
		}
	}
	s.mu.Unlock()
	if jobID == "" {
		t.Fatal("no approval-required job enqueued")
	}

	// The approval comes from the store principal; the X-Kiwi-Actor header
	// must be ignored entirely.
	c2 := newTestClient(t, s.Handler(), "reviewer")
	w = c2.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/approve", nil, map[string]string{"X-Kiwi-Actor": "mallory"})
	if w.Code != http.StatusOK {
		t.Fatalf("approve: want 200 got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "mallory") {
		t.Fatalf("X-Kiwi-Actor header leaked into response: %s", w.Body.String())
	}
	var job struct {
		ApprovedBy string `json:"approved_by"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.ApprovedBy != "reviewer-bot" {
		t.Fatalf("approved_by = %q, want reviewer-bot (header must be ignored)", job.ApprovedBy)
	}

	// The audit trail records the principal subject as actor.
	c3 := newTestClient(t, s.Handler(), "ops")
	w = c3.do(http.MethodGet, "/api/v1/audit?limit=100", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list audit: want 200 got %d: %s", w.Code, w.Body.String())
	}
	var events []struct {
		Action string `json:"action"`
		Actor  string `json:"actor"`
		JobID  string `json:"job_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "job.approved" && e.JobID == jobID && e.Actor == "reviewer-bot" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no job.approved audit event with actor reviewer-bot: %+v", events)
	}
}

func TestCancelUsesPrincipalSubject(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"bot-token": {Subject: "canceller", Roles: []auth.Role{auth.RoleRun, auth.RoleCancel}},
	})
	c := newTestClient(t, s.Handler(), "bot-token")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: want 202 got %d", w.Code)
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	w = c.do(http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", nil, map[string]string{"X-Kiwi-Actor": "mallory"})
	if w.Code != http.StatusOK {
		t.Fatalf("cancel: want 200 got %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	got := s.runs[run.ID]
	var reason string
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			reason = j.Error
		}
	}
	s.mu.Unlock()
	if got.Status != "cancelled" {
		t.Fatalf("run not cancelled: %s", got.Status)
	}
	if reason != "cancelled by canceller" {
		t.Fatalf("cancel reason = %q, want principal subject (header ignored)", reason)
	}
}

func TestCancelForbiddenWithoutCancelRole(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"run-token": {Subject: "runner-bot", Roles: []auth.Role{auth.RoleRun}},
		"ops-token": {Subject: "ops", Roles: []auth.Role{auth.RoleAdmin}},
	})
	c := newTestClient(t, s.Handler(), "run-token")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: want 202 got %d", w.Code)
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	w = c.do(http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", nil, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cancel without role: want 403 got %d", w.Code)
	}
	// An admin principal can still cancel.
	c2 := newTestClient(t, s.Handler(), "ops-token")
	w = c2.do(http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin cancel: want 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestRerunRequiresRerunRole(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"run-token": {Subject: "runner-bot", Roles: []auth.Role{auth.RoleRun}},
		"ops-token": {Subject: "ops", Roles: []auth.Role{auth.RoleAdmin}},
	})
	c := newTestClient(t, s.Handler(), "run-token")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: want 202 got %d", w.Code)
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	w = c.do(http.MethodPost, "/api/v1/runs/"+run.ID+"/rerun", nil, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("rerun without role: want 403 got %d", w.Code)
	}
	c2 := newTestClient(t, s.Handler(), "ops-token")
	w = c2.do(http.MethodPost, "/api/v1/runs/"+run.ID+"/rerun", nil, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("admin rerun: want 202 got %d: %s", w.Code, w.Body.String())
	}
}

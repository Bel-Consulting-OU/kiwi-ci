package server

// Finding 3: a re-registration must revoke the predecessor incarnation's
// leases (capacity, reservations, durable-write credentials) as part of the
// same swap, and the sensitive durable-write endpoints must enforce the
// current incarnation even while a lease token still validates.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// TestRegisterRevokesPredecessorLeasesDB drives the atomic registration swap
// through the RunnerRegistrationStore capability: the running lease held by
// the predecessor incarnation is requeued, its capacity slot released, and
// the new incarnation installed.
func TestRegisterRevokesPredecessorLeasesDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	ctx := context.Background()
	exp := time.Now().UTC().Add(time.Minute)
	f.mu.Lock()
	f.runners["r1"] = model.Runner{ID: "r1", Capacity: 1, ActiveJobs: []string{"j1"}}
	f.runs["run1"] = model.Run{ID: "run1", RepoFullName: "o/r", Ref: "main", Status: model.StatusRunning}
	f.jobs["j1"] = model.Job{
		ID: "j1", RunID: "run1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "r1", LeaseTokenHash: hashLeaseToken(s.leaseKey, "tok1"),
		LeaseExpiresAt: &exp, Attempts: 0, MaxInfraRetries: 1,
	}
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"id":"r1","name":"r1","protocol_min":3,"protocol_max":3,"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d: %s", w.Code, w.Body.String())
	}
	var ack registerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Incarnation == "" {
		t.Fatal("registration did not mint an incarnation")
	}
	if len(ack.ActiveJobs) != 0 {
		t.Fatalf("registration ACK still reports revoked leases as active: %v", ack.ActiveJobs)
	}

	j, err := f.GetJob(ctx, "j1")
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusQueued || j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("predecessor lease not revoked: %+v", j)
	}
	if !strings.Contains(j.Error, "superseded") {
		t.Fatalf("revocation reason not recorded: %q", j.Error)
	}
	ri, err := f.GetRunner(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner capacity slot not released: %+v", ri)
	}
	if ri.Incarnation == "" {
		t.Fatal("runner row carries no new incarnation")
	}
}

// TestRegisterRevokesPredecessorLeasesMemory pins the single-process
// counterpart: the in-memory revocation requeues the predecessor's lease and
// the old incarnation can no longer poll.
func TestRegisterRevokesPredecessorLeasesMemory(t *testing.T) {
	s := New("runner-tok")
	h := s.Handler()
	register := func() registerResponse {
		t.Helper()
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok",
			`{"id":"r1","name":"r1","protocol_min":3,"protocol_max":3,"capacity":1}`)
		if w.Code != http.StatusOK {
			t.Fatalf("register = %d: %s", w.Code, w.Body.String())
		}
		var out registerResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := register()

	exp := time.Now().UTC().Add(time.Minute)
	s.mu.Lock()
	ri := s.runners["r1"]
	ri.ActiveJobs = []string{"j1"}
	ri.Busy = true
	s.runners["r1"] = ri
	s.runs["run1"] = model.Run{ID: "run1", Status: model.StatusRunning}
	s.jobs["j1"] = model.Job{
		ID: "j1", RunID: "run1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "r1", LeaseTokenHash: hashLeaseToken(s.leaseKey, "tok1"),
		LeaseExpiresAt: &exp, Attempts: 0, MaxInfraRetries: 1,
	}
	s.mu.Unlock()

	second := register()
	if second.Incarnation == first.Incarnation {
		t.Fatal("re-registration reused the predecessor incarnation")
	}
	s.mu.Lock()
	j := s.jobs["j1"]
	ri = s.runners["r1"]
	s.mu.Unlock()
	if j.Status != model.StatusQueued || j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("predecessor lease not revoked in memory: %+v", j)
	}
	if len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner capacity slot not released in memory: %+v", ri)
	}
	if len(second.ActiveJobs) != 0 {
		t.Fatalf("registration ACK reports revoked leases: %v", second.ActiveJobs)
	}

	next := func(incarnation string) int {
		req, err := http.NewRequest(http.MethodPost, "/api/v1/runners/r1/next", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(RunnerIncarnationHeader, incarnation)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if code := next(first.Incarnation); code != http.StatusConflict {
		t.Fatalf("superseded incarnation next = %d, want 409", code)
	}
	if code := next(second.Incarnation); code == http.StatusConflict {
		t.Fatalf("current incarnation next = %d, want the request admitted", code)
	}
}

// TestSupersededIncarnationRefusedOnSensitiveEndpoints pins the durable-write
// incarnation gate: with a still-valid lease token, the predecessor
// incarnation is refused on OIDC issuance, secret delivery and artifact/
// snapshot/cache upload while the current incarnation is admitted.
func TestSupersededIncarnationRefusedOnSensitiveEndpoints(t *testing.T) {
	const (
		incA = "incarnation-A"
		incB = "incarnation-B"
	)
	pinIncarnation := func(s *Server) {
		s.mu.Lock()
		s.runners["runner-1"] = model.Runner{ID: "runner-1", Incarnation: incB, Capacity: 1}
		s.mu.Unlock()
		// Two recorded registrations make the modern session superseded:
		// protocol-3 headerless requests are refused too.
		s.recordRunnerRegistration("runner-1", 3)
		s.recordRunnerRegistration("runner-1", 3)
	}

	t.Run("oidc", func(t *testing.T) {
		s := newOIDCTestServer(t, false)
		_, jobID := seedOIDCJob(t, s, "lease1")
		pinIncarnation(s)
		c := newTestClient(t, s.Handler(), "lease1")
		body := map[string]any{"audience": "https://aud.example.com"}

		w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", body, map[string]string{RunnerIncarnationHeader: incA})
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
			t.Fatalf("superseded OIDC issuance = %d %q, want 409 superseded", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), `"value"`) {
			t.Fatal("refused issuance leaked a token")
		}
		w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", body, map[string]string{RunnerIncarnationHeader: incB})
		if w.Code != http.StatusOK {
			t.Fatalf("current incarnation OIDC issuance = %d %q, want 200", w.Code, w.Body.String())
		}
	})

	t.Run("secret", func(t *testing.T) {
		s := New("secret")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		pinIncarnation(s)
		c := newTestClient(t, s.Handler(), "secret")
		_, pub := ephemeralKey(t)
		in := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub}

		w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/secrets", in, map[string]string{RunnerIncarnationHeader: incA})
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
			t.Fatalf("superseded secret delivery = %d %q, want 409 superseded", w.Code, w.Body.String())
		}
		w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/secrets", in, map[string]string{RunnerIncarnationHeader: incB})
		if w.Code != http.StatusOK {
			t.Fatalf("current incarnation secret delivery = %d %q, want 200", w.Code, w.Body.String())
		}
	})

	t.Run("artifact snapshot cache", func(t *testing.T) {
		s := NewPersistentServerForTest(t)
		jobID, runnerID, token, gen := seedJob(t, s, true, nil)
		pinIncarnation(s)
		h := s.Handler()
		do := func(method, path, incarnation string) *httptest.ResponseRecorder {
			req, err := http.NewRequest(method, path, strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer t")
			req.Header.Set("X-Kiwi-Runner-ID", runnerID)
			req.Header.Set("X-Kiwi-Lease-Token", token)
			req.Header.Set("X-Kiwi-Lease-Generation", strconv.FormatInt(gen, 10))
			req.Header.Set(RunnerIncarnationHeader, incarnation)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			return w
		}
		cases := []struct {
			method, path string
		}{
			{http.MethodPut, "/api/v1/jobs/" + jobID + "/artifacts/bin"},
			{http.MethodPost, "/api/v1/jobs/" + jobID + "/snapshots"},
			{http.MethodPut, "/api/v1/jobs/" + jobID + "/cache/key1"},
		}
		for _, tc := range cases {
			w := do(tc.method, tc.path, incA)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
				t.Fatalf("%s %s with predecessor incarnation = %d %q, want 409 superseded", tc.method, tc.path, w.Code, w.Body.String())
			}
			// The current incarnation passes the incarnation gate (later
			// endpoint-specific refusals are fine, a 409 superseded is not).
			w = do(tc.method, tc.path, incB)
			if w.Code == http.StatusConflict && strings.Contains(w.Body.String(), "superseded") {
				t.Fatalf("%s %s with current incarnation was refused as superseded: %s", tc.method, tc.path, w.Body.String())
			}
		}
	})
}

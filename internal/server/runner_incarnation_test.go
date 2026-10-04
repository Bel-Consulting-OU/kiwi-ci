package server

// Registration-session (incarnation) regressions: re-registering a stable
// runner identity supersedes the previous session, so an older process
// holding the same credentials stops polling instead of operating alongside
// the new one.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunnerIncarnationSupersedesOldSession(t *testing.T) {
	s := New("runner-tok")
	h := s.Handler()
	const runnerID = "runner-incarnation-test"

	register := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"id": runnerID, "name": "r", "capacity": 1,
			"protocol_min": 3, "protocol_max": 3,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("register = %d: %s", w.Code, w.Body.String())
		}
		var out registerResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Incarnation == "" {
			t.Fatal("registration did not return an incarnation")
		}
		return out.Incarnation
	}
	next := func(inc string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/"+runnerID+"/next", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		if inc != "" {
			req.Header.Set(RunnerIncarnationHeader, inc)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	first := register()
	if code := next(first); code == http.StatusConflict {
		t.Fatalf("first incarnation was refused: %d", code)
	}

	second := register()
	if second == first {
		t.Fatal("re-registration reused the incarnation")
	}
	if code := next(first); code != http.StatusConflict {
		t.Fatalf("superseded incarnation poll = %d, want 409", code)
	}
	if code := next(second); code == http.StatusConflict {
		t.Fatalf("current incarnation refused: %d", code)
	}
	// Compatibility is tied to the negotiated PROTOCOL: this runner
	// negotiated protocol 3, so a headerless (legacy-style) request is
	// refused — an old client cannot ride a superseded modern session by
	// dropping the header.
	if code := next(""); code != http.StatusConflict {
		t.Fatalf("protocol-3 headerless poll = %d, want 409", code)
	}
	// The heartbeat gate uses the same authority.
	ctx := context.Background()
	if s.runnerIncarnationCurrent(ctx, runnerID, first) {
		t.Fatal("superseded incarnation treated as current")
	}
	if !s.runnerIncarnationCurrent(ctx, runnerID, second) {
		t.Fatal("current incarnation rejected")
	}
	if s.runnerIncarnationCurrent(ctx, runnerID, "") {
		t.Fatal("protocol-3 headerless heartbeat accepted")
	}
}

// registerProtoAt registers runnerID with the given protocol range.
func registerProtoAt(t *testing.T, s *Server, runnerID string, min, max int) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id": runnerID, "name": "r", "capacity": 1,
		"protocol_min": min, "protocol_max": max,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer runner-tok")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register(%d-%d) = %d: %s", min, max, w.Code, w.Body.String())
	}
	var out registerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Incarnation
}

func headerlessNext(t *testing.T, s *Server, runnerID string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/"+runnerID+"/next", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer runner-tok")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code
}

// TestModernHeaderlessRefusedAfterSupersession is the modern-session
// fencing contract: a modern (protocol 3) identity that has been superseded
// refuses headerless session calls, so an old client can neither ride the
// superseded session nor re-register and keep operating headerless. The
// first registration keeps the dev rolling-upgrade tolerance, and
// production refuses headerless unconditionally.
func TestModernHeaderlessRefusedAfterSupersession(t *testing.T) {
	s := New("runner-tok")
	registerProtoAt(t, s, "modern-runner", 3, 3)
	if code := headerlessNext(t, s, "modern-runner"); code == http.StatusConflict {
		t.Fatalf("first-registration headerless poll refused in dev: %d", code)
	}
	registerProtoAt(t, s, "modern-runner", 3, 3) // supersede
	if code := headerlessNext(t, s, "modern-runner"); code != http.StatusConflict {
		t.Fatalf("superseded modern headerless poll = %d, want 409", code)
	}
	if s.runnerIncarnationCurrent(context.Background(), "modern-runner", "") {
		t.Fatal("superseded modern headerless heartbeat accepted")
	}

	prod := New("runner-tok")
	prod.RequireRunnerIncarnation = true
	registerProtoAt(t, prod, "modern-runner", 3, 3)
	if code := headerlessNext(t, prod, "modern-runner"); code != http.StatusConflict {
		t.Fatalf("production headerless poll = %d, want 409", code)
	}
	if prod.runnerIncarnationCurrent(context.Background(), "modern-runner", "") {
		t.Fatal("production headerless heartbeat accepted")
	}
}

// TestUnknownProtocolHeaderlessOnlyOutsideProduction: a runner unknown to
// this process (cross-replica/pre-upgrade) keeps the dev tolerance but is
// refused headerless in production.
func TestUnknownProtocolHeaderlessOnlyOutsideProduction(t *testing.T) {
	s := New("runner-tok")
	if !s.runnerIncarnationCurrent(context.Background(), "never-registered", "") {
		t.Fatal("dev headerless tolerance missing for an unknown runner")
	}
	prod := New("runner-tok")
	prod.RequireRunnerIncarnation = true
	if prod.runnerIncarnationCurrent(context.Background(), "never-registered", "") {
		t.Fatal("production granted headerless compatibility to an unknown runner")
	}
}

// TestCompletionRefusedForSupersededIncarnation pins the completion gate: an
// older registration session cannot drive a completion at all (the lease
// fence remains the second line of defense).
func TestCompletionRefusedForSupersededIncarnation(t *testing.T) {
	s := New("runner-tok")
	h := s.Handler()
	const runnerID = "runner-complete-incarnation"

	register := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"id": runnerID, "name": "r", "capacity": 1,
			"protocol_min": 3, "protocol_max": 3,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("register = %d: %s", w.Code, w.Body.String())
		}
		var out registerResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Incarnation
	}
	complete := func(inc string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"runner_id": runnerID, "lease_token": "stale", "lease_generation": 1, "status": "success",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/nonexistent-job/complete", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		if inc != "" {
			req.Header.Set(RunnerIncarnationHeader, inc)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	first := register()
	_ = register() // supersede
	w := complete(first)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
		t.Fatalf("superseded completion = %d %q, want the incarnation refusal", w.Code, w.Body.String())
	}
	// A protocol-3 runner completing headerless is refused as superseded
	// (compatibility is protocol-tied, not header-absence-tied).
	if w := complete(""); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "superseded") {
		t.Fatalf("protocol-3 headerless completion = %d %q, want superseded", w.Code, w.Body.String())
	}
}

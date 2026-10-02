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
	// Legacy runners during a rolling upgrade omit the header: accepted.
	if code := next(""); code == http.StatusConflict {
		t.Fatalf("headerless legacy poll = %d, want accepted", code)
	}
	// The heartbeat gate uses the same authority.
	ctx := context.Background()
	if s.runnerIncarnationCurrent(ctx, runnerID, first) {
		t.Fatal("superseded incarnation treated as current")
	}
	if !s.runnerIncarnationCurrent(ctx, runnerID, second) {
		t.Fatal("current incarnation rejected")
	}
	if !s.runnerIncarnationCurrent(ctx, runnerID, "") {
		t.Fatal("headerless legacy heartbeat rejected")
	}
}

package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDisabledRunnerExitsNonzero drives a full Runner.Run against a control
// plane stub that disables the runner on the first poll: the runner must
// exit with the disabled/revoked sentinel instead of looping re-registering.
func TestDisabledRunnerExitsNonzero(t *testing.T) {
	t.Run("X-Kiwi-Disabled on next", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/runners/register":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"runner-1","name":"runner-1","capacity":1,"disabled":true}`))
			case strings.HasSuffix(r.URL.Path, "/next"):
				w.Header().Set("X-Kiwi-Disabled", "true")
				w.WriteHeader(http.StatusNoContent)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()
		assertRunnerExitsDisabled(t, ts.URL)
	})
	t.Run("403 on next (certificate revoked)", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/runners/register":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"runner-1","name":"runner-1","capacity":1}`))
			case strings.HasSuffix(r.URL.Path, "/next"):
				http.Error(w, "runner identity mismatch", http.StatusForbidden)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()
		assertRunnerExitsDisabled(t, ts.URL)
	})
	t.Run("403 on register", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "runner identity mismatch", http.StatusForbidden)
		}))
		defer ts.Close()
		assertRunnerExitsDisabled(t, ts.URL)
	})
}

func assertRunnerExitsDisabled(t *testing.T, serverURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := &Runner{Cfg: Config{Server: serverURL, Token: "runner-tok", Poll: 10 * time.Millisecond}, ID: "runner-1"}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("disabled runner exited cleanly, want nonzero exit")
		}
		if !errors.Is(err, ErrRunnerDisabledOrRevoked) {
			t.Fatalf("error = %v, want the disabled/revoked sentinel", err)
		}
		if !strings.Contains(err.Error(), "re-enroll required") {
			t.Fatalf("error = %v, missing re-enroll guidance", err)
		}
	case <-ctx.Done():
		t.Fatal("runner did not exit after being disabled")
	}
}

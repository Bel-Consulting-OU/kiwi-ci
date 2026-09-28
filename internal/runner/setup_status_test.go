package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// setupStatusServer serves a dependency download that never finishes its
// body (it blocks until the request context dies) and records every terminal
// completion status the runner posts.
type setupStatusServer struct {
	mu       sync.Mutex
	complete []model.Status
	depSeen  chan struct{}
	release  chan struct{}
}

func newSetupStatusServer() *setupStatusServer {
	return &setupStatusServer{depSeen: make(chan struct{}, 1), release: make(chan struct{})}
}

func (s *setupStatusServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/dependencies/"):
			select {
			case s.depSeen <- struct{}{}:
			default:
			}
			w.Header().Set("Content-Type", "application/gzip")
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-s.release:
			}
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			s.mu.Lock()
			s.complete = append(s.complete, c.Status)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
}

func (s *setupStatusServer) statuses() []model.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Status{}, s.complete...)
}

// dependencyPipeline declares one producer and one consumer with a
// dependency download, so execute reaches restoreDownloads.
func dependencyPipeline() string {
	return "version: 1\njobs:\n  producer:\n    steps:\n      - run: echo build\n  consumer:\n    needs: [producer]\n    downloads:\n      - from: producer\n        name: bin\n        path: deps\n    steps:\n      - run: echo run\n"
}

// TestDependencyRestoreJobDeadlineReportsCancelled pins the unified setup
// status rule: a deadline that expires while a dependency download is in
// flight is a CANCELLATION, exactly like a deadline during checkout. Before
// the fix the same setupCtx condition was reported as failure here and as
// cancelled for checkout.
func TestDependencyRestoreJobDeadlineReportsCancelled(t *testing.T) {
	srv := newSetupStatusServer()
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	defer close(srv.release)

	r := testRunnerFor(t, ts, Config{})
	checkedOut := false
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		checkedOut = true
		return nil
	}
	task := basicTask(dependencyPipeline())
	task.Job.Key = "consumer"
	task.Job.BaseKey = "consumer"
	task.Job.JobTimeout = 150 * time.Millisecond

	start := time.Now()
	r.execute(context.Background(), task)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("execute took %v; the job deadline did not end the dependency download", elapsed)
	}
	if !checkedOut {
		t.Fatal("checkout never ran")
	}
	select {
	case <-srv.depSeen:
	default:
		t.Fatal("dependency download was never requested")
	}
	statuses := srv.statuses()
	if len(statuses) == 0 || statuses[len(statuses)-1] != model.StatusCancelled {
		t.Fatalf("completion statuses = %v, want cancelled", statuses)
	}
}

// TestDependencyRestoreSetupDeadlineReportsCancelled is the legacy variant:
// with no persisted JobTimeout the configurable setup ceiling bounds the
// download, and its expiry must also report cancelled.
func TestDependencyRestoreSetupDeadlineReportsCancelled(t *testing.T) {
	srv := newSetupStatusServer()
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	defer close(srv.release)

	r := testRunnerFor(t, ts, Config{SetupTimeout: 150 * time.Millisecond})
	checkedOut := false
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		checkedOut = true
		return nil
	}
	task := basicTask(dependencyPipeline())
	task.Job.Key = "consumer"
	task.Job.BaseKey = "consumer"
	task.Job.JobTimeout = 0

	r.execute(context.Background(), task)
	if !checkedOut {
		t.Fatal("checkout never ran")
	}
	statuses := srv.statuses()
	if len(statuses) == 0 || statuses[len(statuses)-1] != model.StatusCancelled {
		t.Fatalf("completion statuses = %v, want cancelled", statuses)
	}
}

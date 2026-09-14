package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestQueueReasonsPersistedViaStoreDBMode(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Seed a runner and two queued jobs: one waiting on a dependency, one
	// needing a label the runner lacks.
	f.mu.Lock()
	f.runners["runner1"] = model.Runner{ID: "runner1", Name: "runner1", Labels: []string{"container"}, Capacity: 1}
	f.runs["run1"] = model.Run{ID: "run1", Status: model.StatusQueued}
	f.jobs["job-dep"] = model.Job{ID: "job-dep", RunID: "run1", Key: "waits", Status: model.StatusQueued, Needs: []string{"job-done"}, CreatedAt: time.Now().UTC()}
	f.jobs["job-done"] = model.Job{ID: "job-done", RunID: "run1", Key: "done", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	f.jobs["job-label"] = model.Job{ID: "job-label", RunID: "run1", Key: "label", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, CreatedAt: time.Now().UTC()}
	f.mu.Unlock()
	// A lease attempt finds no candidates and persists the reasons.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("job-dep"); got != "WAITING_DEPENDENCY" {
		t.Fatalf("job-dep reason = %q, want WAITING_DEPENDENCY", got)
	}
	if got := f.queueReason("job-label"); got != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("job-label reason = %q, want NO_COMPATIBLE_RUNNER", got)
	}
	// The store failure path logs instead of breaking the lease miss.
	f.mu.Lock()
	f.queueReasonsErrs = 1
	f.mu.Unlock()
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next with store failure = %d", w.Code)
	}
}

func TestQueueReasonStoreFakeRoundTrip(t *testing.T) {
	f := newDBFakeStore()
	if err := f.SetQueueReasons(context.Background(), map[string]string{"a": "WAITING_DEPENDENCY"}); err != nil {
		t.Fatal(err)
	}
	if got := f.queueReason("a"); got != "WAITING_DEPENDENCY" {
		t.Fatalf("round trip = %q", got)
	}
}

var _ = storage.ErrNotFound

package scheduler

import (
	"testing"
	"time"

	"github.com/kiwici/kiwi/internal/model"
)

func TestLeaseExpiry(t *testing.T) {
	now := time.Now().UTC()
	if exp := LeaseExpiry(now, 0); !exp.Equal(now.Add(DefaultLeaseDuration)) {
		t.Errorf("LeaseExpiry(0) = %v, want default lease duration", exp)
	}
	if exp := LeaseExpiry(now, -time.Minute); !exp.Equal(now.Add(DefaultLeaseDuration)) {
		t.Errorf("LeaseExpiry(negative) = %v, want default lease duration", exp)
	}
	if exp := LeaseExpiry(now, 2*time.Minute); !exp.Equal(now.Add(2 * time.Minute)) {
		t.Errorf("LeaseExpiry(2m) = %v", exp)
	}
}

func TestEnvironmentAtCapacity(t *testing.T) {
	base := func() map[string]model.Job {
		return map[string]model.Job{
			"self":  {ID: "self", Environment: "prod"},
			"run1":  {ID: "run1", Environment: "prod", Status: model.StatusRunning},
			"other": {ID: "other", Environment: "staging", Status: model.StatusRunning},
			"done":  {ID: "done", Environment: "prod", Status: model.StatusSuccess},
		}
	}
	// no environment restriction at all
	if EnvironmentAtCapacity(model.Job{ID: "self"}, base()) {
		t.Error("job without environment must never be at capacity")
	}
	// zero concurrency means no limit
	if EnvironmentAtCapacity(model.Job{ID: "self", Environment: "prod"}, base()) {
		t.Error("zero concurrency must never be at capacity")
	}
	// one active run, limit 1: at capacity (run1 counts)
	if !EnvironmentAtCapacity(model.Job{ID: "self", Environment: "prod", EnvironmentConcurrency: 1}, base()) {
		t.Error("one active run against limit 1 must be at capacity")
	}
	// limit 2: not at capacity
	if EnvironmentAtCapacity(model.Job{ID: "self", Environment: "prod", EnvironmentConcurrency: 2}, base()) {
		t.Error("one active run against limit 2 must not be at capacity")
	}
	// two active runs, limit 2: at capacity; staging and terminal ignored
	two := base()
	two["run2"] = model.Job{ID: "run2", Environment: "prod", Status: model.StatusRunning}
	if !EnvironmentAtCapacity(model.Job{ID: "self", Environment: "prod", EnvironmentConcurrency: 2}, two) {
		t.Error("two active runs against limit 2 must be at capacity")
	}
	// staging jobs do not count against prod
	one := base()
	delete(one, "run1")
	if EnvironmentAtCapacity(model.Job{ID: "self", Environment: "prod", EnvironmentConcurrency: 1}, one) {
		t.Error("staging/terminal jobs must not count against prod capacity")
	}
}

package server

// Unit regression for the registration path's last_seen ownership: a
// create=true profile write (registration) stamps last_seen through the
// narrow RunnerHeartbeatStore capability, while drain/enable profile writes
// (create=false) leave it entirely to the heartbeat touch.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestRegistrationTouchesRunnerLastSeenNarrowly(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.mu.Lock()
	f.runners["r-touch"] = model.Runner{ID: "r-touch", Name: "old", Capacity: 2, LastSeen: time.Now().UTC().Add(-2 * time.Hour)}
	f.mu.Unlock()

	stale := model.Runner{ID: "r-touch", Name: "new", Capacity: 2, LastSeen: time.Now().UTC().Add(-time.Hour)}
	if err := s.writeRunnerProfileDB(ctx, stale, model.Runner{ID: "r-touch"}, true); err != nil {
		t.Fatalf("registration write: %v", err)
	}
	f.mu.Lock()
	touches := append([]string(nil), f.touchRunnerCalls...)
	got := f.runners["r-touch"]
	f.mu.Unlock()
	if len(touches) != 1 || touches[0] != "r-touch" {
		t.Fatalf("registration last-seen touches = %v, want exactly one narrow touch", touches)
	}
	if got.Name != "new" {
		t.Fatalf("registration did not apply the profile change: %+v", got)
	}
	if got.LastSeen.Before(stale.LastSeen) {
		t.Fatalf("registration did not advance last_seen: %v (stale %v)", got.LastSeen, stale.LastSeen)
	}

	// Drain/enable (create=false) must not touch last_seen.
	before := got.LastSeen
	profile := got
	profile.Draining = true
	if err := s.writeRunnerProfileDB(ctx, profile, got, false); err != nil {
		t.Fatalf("drain write: %v", err)
	}
	f.mu.Lock()
	touches = append([]string(nil), f.touchRunnerCalls...)
	got = f.runners["r-touch"]
	f.mu.Unlock()
	if len(touches) != 1 {
		t.Fatalf("non-registration profile write touched last_seen: %v", touches)
	}
	if !got.Draining || !got.LastSeen.Equal(before) {
		t.Fatalf("drain write changed the wrong fields: %+v (before %v)", got, before)
	}
}

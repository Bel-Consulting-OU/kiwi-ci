package server

// Live-profile resolution on the server: the in-memory lease path
// (liveRunnerLocked), the memory queue explainer, the DB queue explainer
// (the scheduler's EffectiveRunner) and the real PostgreSQL end-to-end path
// all resolve the runner-ID binding through the ONE shared precedence, so a
// profile edit takes effect on the next decision without re-registration.

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
)

// seedLiveRunner installs one registration snapshot in the memory-mode
// runner map.
func seedLiveRunner(t *testing.T, s *Server, ri model.Runner) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runners[ri.ID] = ri
}

// liveRunnerForTest calls the memory-mode live resolver under the server
// mutex.
func liveRunnerForTest(t *testing.T, s *Server, ri model.Runner) (model.Runner, bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.liveRunnerLocked(ri)
}

// TestMemoryLiveRunnerUsesRunnerIDBinding: the memory lease path
// resolves the runner-ID binding, honors live profile edits without
// re-registration, follows certificate precedence, and falls back to the
// snapshot on unbind and on a dangling runner-ID binding.
func TestMemoryLiveRunnerUsesRunnerIDBinding(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"bound"}, Region: "east", Repositories: []string{"github.com/o/allowed"}, MaxCapacity: 2, CostPerHour: 3, PowerWatts: 40})
	bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
	snapshot := model.Runner{ID: "runner-a", Capacity: 9, Labels: []string{"snapshot"}, Region: "west", CostPerHour: 9}
	seedLiveRunner(t, s, snapshot)

	eff, linked := liveRunnerForTest(t, s, snapshot)
	if !linked || eff.Capacity != 2 || eff.CostPerHour != 3 || eff.PowerWatts != 40 {
		t.Fatalf("bound effective = (%+v, linked=%v), want the live runner-ID profile", eff, linked)
	}
	if len(eff.Labels) != 1 || eff.Labels[0] != "bound" || eff.Region != "east" {
		t.Fatalf("bound effective labels/region = (%v, %q)", eff.Labels, eff.Region)
	}
	if len(eff.AllowedRepositories) != 1 || eff.AllowedRepositories[0] != "github.com/o/allowed" {
		t.Fatalf("bound effective repositories = %v", eff.AllowedRepositories)
	}

	// Edit takes effect on the next resolution, no re-registration.
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"edited"}, MaxCapacity: 4})
	eff, linked = liveRunnerForTest(t, s, snapshot)
	if !linked || eff.Capacity != 4 || len(eff.Labels) != 1 || eff.Labels[0] != "edited" {
		t.Fatalf("edited effective = (%+v, linked=%v), want capacity 4 and label edited", eff, linked)
	}

	// Unbind: the registration snapshot applies again.
	if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}
	eff, linked = liveRunnerForTest(t, s, snapshot)
	if linked || eff.Capacity != 9 || eff.CostPerHour != 9 || len(eff.Labels) != 1 || eff.Labels[0] != "snapshot" {
		t.Fatalf("unbound effective = (%+v, linked=%v), want the snapshot", eff, linked)
	}

	// A dangling runner-ID binding resolves as "no profile" (the snapshot).
	bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
	s.mu.Lock()
	delete(s.profiles, "p")
	s.mu.Unlock()
	eff, linked = liveRunnerForTest(t, s, snapshot)
	if linked || eff.Capacity != 9 || len(eff.Labels) != 1 || eff.Labels[0] != "snapshot" {
		t.Fatalf("dangling runner-ID effective = (%+v, linked=%v), want the snapshot", eff, linked)
	}
}

// TestMemoryLiveRunnerCertPrecedence: an explicit certificate binding
// wins over the runner-ID binding, a serial without a cert binding falls
// through, and a dangling cert binding fails closed (capacity 0) even with a
// live runner-ID binding.
func TestMemoryLiveRunnerCertPrecedence(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{ID: "cert-p", Labels: []string{"cert"}, MaxCapacity: 3})
	createProfile(t, s, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 5})
	bindSerial(t, s, "cert-p", "serial-1")
	bindRunnerProfile(t, s, "id-p", "runner-a", "admin-tok")
	withSerial := model.Runner{ID: "runner-a", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "serial-1"}
	seedLiveRunner(t, s, withSerial)
	eff, linked := liveRunnerForTest(t, s, withSerial)
	if !linked || eff.Capacity != 3 || len(eff.Labels) != 1 || eff.Labels[0] != "cert" {
		t.Fatalf("cert-precedence effective = (%+v, linked=%v), want the cert profile", eff, linked)
	}

	// The runner presents a serial with no cert binding: runner-ID applies.
	unboundSerial := withSerial
	unboundSerial.CertSerial = "serial-unbound"
	seedLiveRunner(t, s, unboundSerial)
	eff, linked = liveRunnerForTest(t, s, unboundSerial)
	if !linked || eff.Capacity != 5 || len(eff.Labels) != 1 || eff.Labels[0] != "id" {
		t.Fatalf("serial fallthrough effective = (%+v, linked=%v), want the runner-ID profile", eff, linked)
	}

	// Dangling cert binding: fail closed even though the runner-ID binding
	// is live. The admin surface refuses to bind an unknown profile, so bind
	// the existing cert profile to a second serial and then delete the
	// profile row (the profile-delete path).
	bindSerial(t, s, "cert-p", "serial-dangling")
	s.mu.Lock()
	delete(s.profiles, "cert-p")
	s.mu.Unlock()
	dangling := withSerial
	dangling.CertSerial = "serial-dangling"
	seedLiveRunner(t, s, dangling)
	eff, linked = liveRunnerForTest(t, s, dangling)
	if !linked || eff.Capacity != 0 {
		t.Fatalf("dangling cert effective = (%+v, linked=%v), want capacity 0 fail closed", eff, linked)
	}
}

// TestMemoryQueueReasonUsesRunnerIDBinding: the memory-mode queue
// explainer evaluates the fleet with the live runner-ID profile, so a
// profile edit changes the persisted reason.
func TestMemoryQueueReasonUsesRunnerIDBinding(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"bound"}, MaxCapacity: 1})
	bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
	ri := model.Runner{ID: "runner-a", Capacity: 1, Labels: []string{"snapshot"}}
	seedLiveRunner(t, s, ri)
	s.mu.Lock()
	s.jobs["job-q"] = model.Job{ID: "job-q", RunID: "run-q", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"bound"}, RepoID: "github.com/o/r"}
	s.mu.Unlock()

	s.mu.Lock()
	s.applyQueueReasonsMemoryLocked(ri)
	reason := s.jobs["job-q"].QueueReason
	s.mu.Unlock()
	if reason != string(queue.None) {
		t.Fatalf("bound-label reason = %q, want %q (the live runner-ID profile satisfies it)", reason, queue.None)
	}

	// Edit the profile away from the required label: the explainer reports
	// the incompatibility on the next pass.
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"edited"}, MaxCapacity: 1})
	s.mu.Lock()
	s.applyQueueReasonsMemoryLocked(ri)
	reason = s.jobs["job-q"].QueueReason
	s.mu.Unlock()
	if reason != string(queue.NoCompatibleRunner) {
		t.Fatalf("edited-label reason = %q, want %q", reason, queue.NoCompatibleRunner)
	}
}

// TestDBExplainUsesRunnerIDBinding: the DB queue explainer consumes
// the scheduler's effective runner view, which must resolve the runner-ID
// binding; a profile edit changes the reason without re-registration.
func TestDBExplainUsesRunnerIDBinding(t *testing.T) {
	ctx := context.Background()
	s, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.profiles["p"] = model.RunnerProfile{ID: "p", Labels: []string{"bound"}, MaxCapacity: 1}
	f.runnerProfiles["runner-a"] = "p"
	f.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", Capacity: 1, Labels: []string{"snapshot"}}
	f.jobs["job-q"] = model.Job{ID: "job-q", RunID: "run-q", Key: "build", Status: model.StatusQueued, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RequiredLabels: []string{"bound"}}
	f.mu.Unlock()

	ri := model.Runner{ID: "runner-a", Capacity: 1, Labels: []string{"snapshot"}}
	got, err := f.GetRunner(ctx, "runner-a")
	if err != nil {
		t.Fatal(err)
	}
	if eff := s.Sched.EffectiveRunner(ctx, got); len(eff.Labels) != 1 || eff.Labels[0] != "bound" {
		t.Fatalf("db effective labels = %v, want the live runner-ID profile", eff.Labels)
	}
	s.applyQueueReasonsDB(ctx, ri)
	if got := f.queueReason("job-q"); got != string(queue.None) {
		t.Fatalf("db bound-label reason = %q, want %q", got, queue.None)
	}

	// Profile edit: the explainer sees the new labels on the next pass.
	f.mu.Lock()
	f.profiles["p"] = model.RunnerProfile{ID: "p", Labels: []string{"edited"}, MaxCapacity: 1}
	f.mu.Unlock()
	s.applyQueueReasonsDB(ctx, ri)
	if got := f.queueReason("job-q"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("db edited-label reason = %q, want %q", got, queue.NoCompatibleRunner)
	}
}

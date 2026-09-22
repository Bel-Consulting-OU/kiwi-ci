package scheduler

// The scheduler's lease prefilter (effectiveRunner / EffectiveRunner, which
// the queue-reason explainers also consume) resolves the SAME live profile
// the claim does: certificate-serial binding first, then the runner-ID
// binding (runner_profile_links), then the registration snapshot — so a
// profile edit takes effect on the next lease without re-registration and a
// dangling certificate binding is presented fail-closed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// liveProfileLeaseFixture seeds one queued job requiring labels and one runner
// whose registration snapshot carries snapshotLabels/snapshotCapacity.
func liveProfileLeaseFixture(t *testing.T, st *atomicFakeStore, jobID string, labels []string, runnerID string, snapshotLabels []string, snapshotCapacity int) time.Time {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.InsertRun(ctx, model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, model.Job{
		ID: jobID, RunID: "run1", Key: jobID, Status: model.StatusQueued,
		RequiredLabels: labels, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		RepoID: "github.com/o/r", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: snapshotCapacity, Labels: snapshotLabels}); err != nil {
		t.Fatal(err)
	}
	st.setLeader(true, nil)
	return now
}

// TestLeaseEffectiveRunnerUsesRunnerIDBinding: the prefilter's
// effective view (and therefore the queue explainers) uses the live
// runner-ID profile, and a profile edit changes the next decision without
// re-registration.
func TestLeaseEffectiveRunnerUsesRunnerIDBinding(t *testing.T) {
	ctx := context.Background()
	st := newAtomicFakeStore()
	now := liveProfileLeaseFixture(t, st, "job1", []string{"bound"}, "r1", []string{"snapshot"}, 4)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "p1", Labels: []string{"bound"}, MaxCapacity: 0, CostPerHour: 2.5}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkRunnerProfile(ctx, "r1", "p1"); err != nil {
		t.Fatal(err)
	}
	s := NewDB(st, time.Minute, nil, nil)

	got, err := st.GetRunner(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	eff := s.EffectiveRunner(ctx, got)
	if len(eff.Labels) != 1 || eff.Labels[0] != "bound" {
		t.Fatalf("effective labels = %v, want the live runner-ID profile labels", eff.Labels)
	}
	if eff.Capacity != 0 {
		t.Fatalf("effective capacity = %d, want the live profile capacity 0", eff.Capacity)
	}
	if _, _, _, err := s.Lease(ctx, "r1", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease under zero-capacity bound profile = %v, want ErrNoJobs", err)
	}

	// Edit the live profile: capacity 2 and rates change; the NEXT lease
	// honors the edit without re-registration.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "p1", Labels: []string{"bound"}, MaxCapacity: 2, CostPerHour: 4.5}); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetRunner(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if eff := s.EffectiveRunner(ctx, got); eff.Capacity != 2 || eff.CostPerHour != 4.5 {
		t.Fatalf("effective after edit = (capacity %d, cost %v), want (2, 4.5)", eff.Capacity, eff.CostPerHour)
	}
	j, _, _, err := s.Lease(ctx, "r1", now)
	if err != nil {
		t.Fatalf("lease after profile edit = %v", err)
	}
	if j.CostRate != 4.5 {
		t.Fatalf("frozen rate = %v, want 4.5 from the edited live profile", j.CostRate)
	}
}

// TestLeaseCertBindingBeatsRunnerIDBinding: the prefilter resolves an
// explicit certificate-serial binding first, and the serial-without-binding
// case falls through to the runner-ID binding.
func TestLeaseCertBindingBeatsRunnerIDBinding(t *testing.T) {
	ctx := context.Background()
	st := newAtomicFakeStore()
	now := liveProfileLeaseFixture(t, st, "job1", []string{"id"}, "r1", []string{"snapshot"}, 4)
	if err := st.UpsertRunner(ctx, model.Runner{ID: "r1", Name: "r1", Capacity: 4, Labels: []string{"snapshot"}, CertSerial: "cert-1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "cert-p", Labels: []string{"cert"}, MaxCapacity: 3}); err != nil {
		t.Fatal(err)
	}
	if err := st.BindCertProfile(ctx, "cert-1", "cert-p"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 5}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkRunnerProfile(ctx, "r1", "id-p"); err != nil {
		t.Fatal(err)
	}
	s := NewDB(st, time.Minute, nil, nil)
	got, err := st.GetRunner(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if eff := s.EffectiveRunner(ctx, got); len(eff.Labels) != 1 || eff.Labels[0] != "cert" || eff.Capacity != 3 {
		t.Fatalf("effective = (labels %v, capacity %d), want the cert-serial profile", eff.Labels, eff.Capacity)
	}
	if _, _, _, err := s.Lease(ctx, "r1", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("runner-ID label under cert precedence = %v, want ErrNoJobs", err)
	}

	// A serial with no cert binding: the runner-ID binding applies.
	st2 := newAtomicFakeStore()
	now2 := liveProfileLeaseFixture(t, st2, "job2", []string{"id"}, "r2", []string{"snapshot"}, 4)
	if err := st2.UpsertRunner(ctx, model.Runner{ID: "r2", Name: "r2", Capacity: 4, Labels: []string{"snapshot"}, CertSerial: "cert-unbound"}); err != nil {
		t.Fatal(err)
	}
	if err := st2.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := st2.LinkRunnerProfile(ctx, "r2", "id-p"); err != nil {
		t.Fatal(err)
	}
	s2 := NewDB(st2, time.Minute, nil, nil)
	if _, _, _, err := s2.Lease(ctx, "r2", now2); err != nil {
		t.Fatalf("serial-without-cert-binding lease = %v, want the runner-ID binding", err)
	}
}

// TestLeaseDanglingBindingsPrefilter: a dangling certificate binding
// fails the prefilter closed (zero capacity, no candidates) even when a live
// runner-ID binding exists; a dangling runner-ID binding resolves as "no
// profile" (the registration snapshot).
func TestLeaseDanglingBindingsPrefilter(t *testing.T) {
	ctx := context.Background()
	st := newAtomicFakeStore()
	now := liveProfileLeaseFixture(t, st, "job1", []string{"snapshot"}, "r1", []string{"snapshot"}, 4)
	if err := st.UpsertRunner(ctx, model.Runner{ID: "r1", Name: "r1", Capacity: 4, Labels: []string{"snapshot"}, CertSerial: "cert-dangling"}); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.certProfiles["cert-dangling"] = "99999999999999999999999999999999"
	st.mu.Unlock()
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "id-p", Labels: []string{"id"}, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkRunnerProfile(ctx, "r1", "id-p"); err != nil {
		t.Fatal(err)
	}
	s := NewDB(st, time.Minute, nil, nil)
	got, err := st.GetRunner(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if eff := s.EffectiveRunner(ctx, got); eff.Capacity != 0 {
		t.Fatalf("dangling cert binding effective capacity = %d, want 0 (fail closed)", eff.Capacity)
	}
	if _, _, _, err := s.Lease(ctx, "r1", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("dangling cert binding lease = %v, want ErrNoJobs", err)
	}

	// Dangling runner-ID binding: the snapshot applies (not fail closed, and
	// never the deleted profile).
	st2 := newAtomicFakeStore()
	now2 := liveProfileLeaseFixture(t, st2, "job2", []string{"snapshot"}, "r2", []string{"snapshot"}, 1)
	if err := st2.LinkRunnerProfile(ctx, "r2", "ghost-p"); err != nil {
		t.Fatal(err)
	}
	s2 := NewDB(st2, time.Minute, nil, nil)
	if _, _, _, err := s2.Lease(ctx, "r2", now2); err != nil {
		t.Fatalf("dangling runner-ID binding lease = %v, want the registration snapshot", err)
	}
	got2, err := st2.GetRunner(ctx, "r2")
	if err != nil {
		t.Fatal(err)
	}
	if eff := s2.EffectiveRunner(ctx, got2); eff.Capacity != 1 {
		t.Fatalf("dangling runner-ID effective capacity = %d, want the snapshot 1", eff.Capacity)
	}
}

package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// resolverErrStore implements the LiveProfileResolver contract but always
// fails, so the prefilter's best-effort error arm returns the registration
// snapshot unchanged.
type resolverErrStore struct{ storage.Store }

func (resolverErrStore) ResolveLiveRunnerProfile(ctx context.Context, runnerID, serial string) (storage.LiveProfileResolution, error) {
	return storage.LiveProfileResolution{}, errors.New("resolve boom")
}

// composeStore deliberately does NOT implement LiveProfileResolver (embedding
// the interface hides no methods beyond storage.Store's set), so the scheduler
// falls back to composing the precedence from ProfileForSerial /
// ProfileForRunnerID. The sentinel serial/runner produce lookup errors.
type composeStore struct {
	storage.Store
	storage.ProfileStore
	storage.RunnerProfileLinkStore
}

func (c composeStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	if serial == "boom" {
		return model.RunnerProfile{}, false, errors.New("serial boom")
	}
	ps, ok := c.Store.(storage.ProfileStore)
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	return ps.ProfileForSerial(ctx, serial)
}

func (c composeStore) ProfileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error) {
	if runnerID == "boom" {
		return model.RunnerProfile{}, false, errors.New("runner boom")
	}
	ls, ok := c.Store.(storage.RunnerProfileLinkStore)
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	return ls.ProfileForRunnerID(ctx, runnerID)
}

// TestEffectiveRunnerComposeFallback pins the prefilter's per-runner fallback
// for stores without the LiveProfileResolver contract: the composed
// precedence overlays a runner-ID profile, a certificate-serial profile, a
// dangling binding (fail closed) and a read error (snapshot unchanged).
func TestEffectiveRunnerComposeFallback(t *testing.T) {
	ctx := context.Background()
	fake := newFakeStore()
	if err := fake.UpsertProfile(ctx, model.RunnerProfile{ID: "p1", Labels: []string{"live"}, MaxCapacity: 3}); err != nil {
		t.Fatal(err)
	}
	if err := fake.LinkRunnerProfile(ctx, "r1", "p1"); err != nil {
		t.Fatal(err)
	}
	if err := fake.BindCertProfile(ctx, "cert-1", "p1"); err != nil {
		t.Fatal(err)
	}
	if err := fake.LinkRunnerProfile(ctx, "r-dangling", "missing"); err != nil {
		t.Fatal(err)
	}
	s := NewDB(composeStore{Store: fake, ProfileStore: fake, RunnerProfileLinkStore: fake}, time.Minute, nil, nil)

	snap := model.Runner{ID: "r1", Capacity: 9, Labels: []string{"snapshot"}}
	if got := s.EffectiveRunner(ctx, snap); got.Capacity != 3 || len(got.Labels) != 1 || got.Labels[0] != "live" {
		t.Fatalf("runner-ID compose = (cap %d labels %v), want the live profile", got.Capacity, got.Labels)
	}

	serial := model.Runner{ID: "r1", Capacity: 9, Labels: []string{"snapshot"}, CertSerial: "cert-1"}
	if got := s.EffectiveRunner(ctx, serial); got.Capacity != 3 || got.Labels[0] != "live" {
		t.Fatalf("cert compose = (cap %d labels %v), want the live profile", got.Capacity, got.Labels)
	}

	// The composed fallback has no dangling detection (the per-source read
	// contracts report only found/not-found), so the snapshot is preserved;
	// the claim transaction remains authoritative for dangling bindings.
	dangling := model.Runner{ID: "r-dangling", Capacity: 9, Labels: []string{"snapshot"}}
	if got := s.EffectiveRunner(ctx, dangling); got.Capacity != 9 {
		t.Fatalf("dangling compose capacity = %d, want the snapshot 9", got.Capacity)
	}

	// No binding at all: the snapshot is preserved (the default overlay arm).
	plain := model.Runner{ID: "r-none", Capacity: 7, Labels: []string{"snapshot"}}
	if got := s.EffectiveRunner(ctx, plain); got.Capacity != 7 || got.Labels[0] != "snapshot" {
		t.Fatalf("no-binding compose = %+v, want the snapshot", got)
	}

	// Lookup errors fall back to the snapshot.
	if got := s.EffectiveRunner(ctx, model.Runner{ID: "r1", Capacity: 9, CertSerial: "boom"}); got.Capacity != 9 {
		t.Fatalf("serial error compose capacity = %d, want snapshot 9", got.Capacity)
	}
	if got := s.EffectiveRunner(ctx, model.Runner{ID: "boom", Capacity: 9}); got.Capacity != 9 {
		t.Fatalf("runner error compose capacity = %d, want snapshot 9", got.Capacity)
	}
}

// TestEffectiveRunnerResolverError pins the resolver-contract error arm: a
// read failure returns the registration snapshot unchanged.
func TestEffectiveRunnerResolverError(t *testing.T) {
	s := NewDB(resolverErrStore{Store: newFakeStore()}, time.Minute, nil, nil)
	ri := model.Runner{ID: "r1", Capacity: 5, Labels: []string{"snap"}}
	if got := s.EffectiveRunner(context.Background(), ri); got.Capacity != 5 || got.Labels[0] != "snap" {
		t.Fatalf("resolver error = %+v, want the untouched snapshot", got)
	}
}

// fleetFakeStore adds the set-based fleet-view contract on top of fakeStore so
// the batch entry points and their error arms are exercised in memory.
type fleetFakeStore struct {
	*fakeStore
	storage.ResourceReservationStore
	bindings map[string]storage.FleetRunnerBinding
	sums     map[string]model.ResourceCapacity
	reserved map[string]model.ResourceCapacity
	fleetErr error
	sumsErr  error
	resErr   error
}

func (f *fleetFakeStore) FleetRunnerProfileBindings(ctx context.Context) (map[string]storage.FleetRunnerBinding, error) {
	if f.fleetErr != nil {
		return nil, f.fleetErr
	}
	return f.bindings, nil
}

func (f *fleetFakeStore) RunnerReservationSums(ctx context.Context) (map[string]model.ResourceCapacity, error) {
	if f.sumsErr != nil {
		return nil, f.sumsErr
	}
	return f.sums, nil
}

func (f *fleetFakeStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	if f.resErr != nil {
		return model.ResourceCapacity{}, f.resErr
	}
	return f.reserved[runnerID], nil
}

// TestEffectiveRunnerBatchAndReserved pins both batched fleet-view entry
// points and their fallback/error arms: a binding is overlaid, a runner
// missing from the batch is resolved per-runner, and a batch read error asks
// the caller to fall back.
func TestEffectiveRunnerBatchAndReserved(t *testing.T) {
	ctx := context.Background()
	fake := newFakeStore()
	if err := fake.UpsertProfile(ctx, model.RunnerProfile{ID: "p1", Labels: []string{"live"}, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	fleet := &fleetFakeStore{
		fakeStore: fake,
		bindings: map[string]storage.FleetRunnerBinding{
			"r1": {Runner: storage.FleetProfileBinding{Linked: true, Found: true, Profile: model.RunnerProfile{ID: "p1", Labels: []string{"live"}, MaxCapacity: 2}}},
		},
		sums:     map[string]model.ResourceCapacity{"r1": {CPU: 1.5, Memory: 128}},
		reserved: map[string]model.ResourceCapacity{"r1": {CPU: 2.5}},
	}
	s := NewDB(fleet, time.Minute, nil, nil)

	out, ok := s.EffectiveRunnerBatch(ctx, []model.Runner{
		{ID: "r1", Capacity: 9, Labels: []string{"snap"}},
		{ID: "r2", Capacity: 7, Labels: []string{"snap"}},
	})
	if !ok {
		t.Fatal("EffectiveRunnerBatch: ok=false, want true")
	}
	if out["r1"].Capacity != 2 || len(out["r1"].Labels) != 1 || out["r1"].Labels[0] != "live" {
		t.Fatalf("batched r1 = %+v, want the live binding", out["r1"])
	}
	if out["r2"].Capacity != 7 {
		t.Fatalf("batched r2 = %+v, want the per-runner snapshot", out["r2"])
	}

	sums, ok := s.ReservedResourcesBatch(ctx)
	if !ok || sums["r1"].CPU != 1.5 || sums["r1"].Memory != 128 {
		t.Fatalf("ReservedResourcesBatch = %v, %v", sums, ok)
	}
	if got := s.ReservedResources(ctx, "r1"); got.CPU != 2.5 {
		t.Fatalf("ReservedResources = %+v, want CPU 2.5", got)
	}

	fleet.fleetErr = errors.New("fleet boom")
	if _, ok := s.EffectiveRunnerBatch(ctx, nil); ok {
		t.Fatal("EffectiveRunnerBatch with a batch error: ok=true, want false")
	}
	fleet.sumsErr = errors.New("sums boom")
	if _, ok := s.ReservedResourcesBatch(ctx); ok {
		t.Fatal("ReservedResourcesBatch with a batch error: ok=true, want false")
	}
	fleet.resErr = errors.New("reserved boom")
	if got := s.ReservedResources(ctx, "r1"); got != (model.ResourceCapacity{}) {
		t.Fatalf("ReservedResources with a read error = %+v, want zero", got)
	}
}

// TestEffectiveRunnerBatchNoContract pins that a store without the fleet-view
// contract asks the caller to fall back to per-runner resolution.
func TestEffectiveRunnerBatchNoContract(t *testing.T) {
	s := NewDB(newFakeStore(), time.Minute, nil, nil)
	if _, ok := s.EffectiveRunnerBatch(context.Background(), []model.Runner{{ID: "r1"}}); ok {
		t.Fatal("EffectiveRunnerBatch without a fleet contract: ok=true, want false")
	}
	if _, ok := s.ReservedResourcesBatch(context.Background()); ok {
		t.Fatal("ReservedResourcesBatch without a fleet contract: ok=true, want false")
	}
}

// TestEnvironmentAtCapacityReached pins the environment concurrency ceiling.
func TestEnvironmentAtCapacityReached(t *testing.T) {
	candidate := model.Job{ID: "j1", Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusRunning, RepoID: "github.com/o/r"}
	jobs := map[string]model.Job{
		"j2": {ID: "j2", Environment: "prod", EnvironmentConcurrency: 1, Status: model.StatusRunning, RepoID: "github.com/o/r"},
	}
	if !EnvironmentAtCapacity(candidate, jobs) {
		t.Fatal("EnvironmentAtCapacity = false, want true at the concurrency limit")
	}
	// Baseline: an empty environment imposes no limit.
	if EnvironmentAtCapacity(model.Job{ID: "j3", EnvironmentConcurrency: 1}, jobs) {
		t.Fatal("an empty environment must not be capacity-limited")
	}
}

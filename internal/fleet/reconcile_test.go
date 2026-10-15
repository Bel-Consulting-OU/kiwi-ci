package fleet

import (
	"context"
	"errors"
	"testing"
)

type recProvider struct {
	name       string
	cap        map[string]Capacity
	capErr     error
	provisionN int
	drainN     int
	quarantine int
	provisionE error
	drainErr   error
	unhealthy  []string
	healthErr  error
	provision  bool
	drain      bool
}

func (f *recProvider) Name() string { return f.name }
func (f *recProvider) Capacity(context.Context) (map[string]Capacity, error) {
	if f.capErr != nil {
		return nil, f.capErr
	}
	out := map[string]Capacity{}
	for k, v := range f.cap {
		out[k] = v
	}
	return out, nil
}
func (f *recProvider) Provision(_ context.Context, p Profile, want int) ([]Instance, error) {
	if f.provisionE != nil {
		return nil, f.provisionE
	}
	f.provision = true
	f.provisionN += want
	var out []Instance
	for i := 0; i < want; i++ {
		out = append(out, Instance{ID: f.name + "-p" + string(rune('a'+i)), Profile: p.Name, State: StatePending})
	}
	return out, nil
}
func (f *recProvider) Drain(_ context.Context, ids []string) error {
	f.drain = true
	f.quarantine += len(ids)
	return f.drainErr
}
func (f *recProvider) DrainN(_ context.Context, _ string, n int) error {
	if f.drainErr != nil {
		return f.drainErr
	}
	f.drain = true
	f.drainN += n
	return nil
}
func (f *recProvider) Unhealthy(context.Context, string) ([]string, error) {
	return f.unhealthy, f.healthErr
}
func (f *recProvider) Terminate(context.Context, []string) error { return nil }
func (f *recProvider) Cost(context.Context, string) (float64, error) {
	return 0.01, nil
}
func (f *recProvider) Capabilities(context.Context, string) ([]string, error) {
	return nil, nil
}
func (f *recProvider) Attestation(context.Context, string) ([]byte, error) { return nil, nil }

var (
	_ Provisioner   = (*recProvider)(nil)
	_ CountDrainer  = (*recProvider)(nil)
	_ HealthScanner = (*recProvider)(nil)
)

func pool(min, max, warm int) Profile {
	return Profile{Name: "pool", Min: min, Max: max, Warm: warm}
}

// Capacity failure is fail-closed: no provision, no drain, report carries
// the error. Unknown state must never drive scale decisions.
func TestReconcileCapacityFailureIsFailClosed(t *testing.T) {
	p := &recProvider{name: "p1", capErr: errors.New("api down")}
	m := NewManager()
	m.Register(p)
	rep := m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 1), Want: 5}})
	if rep.Errors == 0 {
		t.Fatal("capacity failure must be an error")
	}
	if p.provision || p.drain {
		t.Fatalf("acted on unknown state: provision=%v drain=%v", p.provision, p.drain)
	}
}

// Under target provisions the gap; pending counts toward the target so a
// slow provisioner is never double-fed.
func TestReconcileProvisionsGapAndCountsPending(t *testing.T) {
	p := &recProvider{name: "p1", cap: map[string]Capacity{"pool": {Ready: 1, Pending: 2, Max: 10}}}
	m := NewManager()
	m.Register(p)
	rep := m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 5}})
	if p.provisionN != 2 {
		t.Fatalf("provisioned %d, want 2 (5 - 1 ready - 2 pending)", p.provisionN)
	}
	if rep.Errors != 0 {
		t.Fatalf("errors = %d", rep.Errors)
	}
	// Second pass over the same state is idempotent when capacity is unchanged.
	p.provisionN = 0
	m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 5}})
	// Capacity still reports 1+2 so it provisions 2 again — providers must
	// refresh Capacity. Idempotence holds when the provider reports the new
	// pending total.
	p.cap = map[string]Capacity{"pool": {Ready: 1, Pending: 4, Max: 10}}
	p.provisionN = 0
	m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 5}})
	if p.provisionN != 0 {
		t.Fatalf("double-fed after pending accounted: %d", p.provisionN)
	}
}

// Never provisions above Max (profile or provider).
func TestReconcileClampsToMax(t *testing.T) {
	p := &recProvider{name: "p1", cap: map[string]Capacity{"pool": {Ready: 0, Max: 3}}}
	m := NewManager()
	m.Register(p)
	m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 50, 0), Want: 50}})
	if p.provisionN != 3 {
		t.Fatalf("provisioned %d, want 3 (provider Max)", p.provisionN)
	}
}

// Idle+DrainIdle scales down to Min, including scale-to-zero at Min=0.
func TestReconcileScaleToZero(t *testing.T) {
	p := &recProvider{name: "p1", cap: map[string]Capacity{"pool": {Ready: 4, Max: 10}}}
	m := NewManager()
	m.Register(p)
	rep := m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 4, Idle: true, DrainIdle: true}})
	if p.drainN != 4 {
		t.Fatalf("drained %d, want 4", p.drainN)
	}
	if p.provision {
		t.Fatal("scale-to-zero must not provision")
	}
	if rep.Errors != 0 {
		t.Fatalf("errors = %d", rep.Errors)
	}
}

// Idle without DrainIdle keeps the Min floor (warm pool).
func TestReconcileIdleKeepsWarmFloor(t *testing.T) {
	p := &recProvider{name: "p1", cap: map[string]Capacity{"pool": {Ready: 6, Max: 10}}}
	m := NewManager()
	m.Register(p)
	m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(3, 10, 3), Want: 6, Idle: true}})
	if p.drainN != 3 {
		t.Fatalf("drained %d, want 3 (down to Min=3)", p.drainN)
	}
}

// Unhealthy instances are quarantined BEFORE the scale decision and do not
// count as READY.
func TestReconcileQuarantinesBeforeScale(t *testing.T) {
	p := &recProvider{
		name:      "p1",
		cap:       map[string]Capacity{"pool": {Ready: 5, Max: 10}},
		unhealthy: []string{"bad-1", "bad-2"},
	}
	m := NewManager()
	m.Register(p)
	// Want 5: after quarantining 2, ready=3, so it provisions 2.
	m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 5}})
	if p.quarantine != 2 {
		t.Fatalf("quarantined %d, want 2", p.quarantine)
	}
	if p.provisionN != 2 {
		t.Fatalf("provisioned %d, want 2 (5 - 3 remaining ready)", p.provisionN)
	}
}

// A provider-scoped target never bleeds into another provider's same-named
// pool (the "wrong forge" class, capacity edition).
func TestReconcileDoesNotCrossProviders(t *testing.T) {
	a := &recProvider{name: "a", cap: map[string]Capacity{"pool": {Ready: 0, Max: 10}}}
	b := &recProvider{name: "b", cap: map[string]Capacity{"pool": {Ready: 9, Max: 10}}}
	m := NewManager()
	m.Register(a)
	m.Register(b)
	m.Reconcile(context.Background(), []Target{{Provider: "a", Profile: pool(0, 10, 0), Want: 2}})
	if a.provisionN != 2 {
		t.Fatalf("a provisioned %d, want 2", a.provisionN)
	}
	if b.provision || b.drain {
		t.Fatal("target for provider a must not touch provider b")
	}
}

// One provider's failure does not freeze the other's pass.
func TestReconcileContinuesPastFailure(t *testing.T) {
	a := &recProvider{name: "a", capErr: errors.New("down")}
	b := &recProvider{name: "b", cap: map[string]Capacity{"pool": {Ready: 0, Max: 10}}}
	m := NewManager()
	m.Register(a)
	m.Register(b)
	rep := m.Reconcile(context.Background(), []Target{
		{Provider: "a", Profile: pool(0, 10, 0), Want: 1},
		{Provider: "b", Profile: pool(0, 10, 0), Want: 1},
	})
	if rep.Errors == 0 {
		t.Fatal("a's failure must be recorded")
	}
	if b.provisionN != 1 {
		t.Fatalf("b must still provision despite a failing: %d", b.provisionN)
	}
}

// Provision failure is recorded; no phantom success change.
func TestReconcileProvisionFailureRecorded(t *testing.T) {
	p := &recProvider{name: "p1", cap: map[string]Capacity{"pool": {Ready: 0, Max: 10}}, provisionE: errors.New("quota")}
	m := NewManager()
	m.Register(p)
	rep := m.Reconcile(context.Background(), []Target{{Provider: "p1", Profile: pool(0, 10, 0), Want: 3}})
	if rep.Errors == 0 {
		t.Fatal("provision failure must be an error")
	}
}

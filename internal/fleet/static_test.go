package fleet

import (
	"context"
	"testing"
)

// A static pool never fabricates capacity: Provision adopts only what the
// inventory already holds.
func TestStaticProviderNeverFabricates(t *testing.T) {
	p := NewStaticProvider("static")
	if err := p.Add(Instance{ID: "h1", Profile: "pool", Labels: []string{"os:linux"}, CostPerHour: 0.01}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Instance{ID: "h2", Profile: "pool", Labels: []string{"os:linux"}}); err != nil {
		t.Fatal(err)
	}
	got, err := p.Provision(context.Background(), Profile{Name: "pool"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("adopted %d, want 2 (never fabricates)", len(got))
	}
	// Second provision adopts nothing more.
	got2, err := p.Provision(context.Background(), Profile{Name: "pool"}, 5)
	if err != nil || len(got2) != 0 {
		t.Fatalf("re-provision = %v err=%v, want 0", got2, err)
	}
	// Capacity reflects the adopted state.
	caps, err := p.Capacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps["pool"].Max != 2 {
		t.Fatalf("capacity = %+v", caps)
	}
}

// Duplicate ids and empty ids are refused.
func TestStaticProviderRegistrationGuards(t *testing.T) {
	p := NewStaticProvider("static")
	if err := p.Add(Instance{ID: ""}); err == nil {
		t.Fatal("empty id must be refused")
	}
	if err := p.Add(Instance{ID: "h1", Profile: "pool"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Instance{ID: "h1", Profile: "pool"}); err == nil {
		t.Fatal("duplicate id must be refused")
	}
}

// Quarantine removes a host from the READY set before Reconcile scales.
func TestStaticProviderQuarantine(t *testing.T) {
	p := NewStaticProvider("static")
	if err := p.Add(Instance{ID: "h1", Profile: "pool"}); err != nil {
		t.Fatal(err)
	}
	p.Quarantine([]string{"h1"})
	bad, err := p.Unhealthy(context.Background(), "pool")
	if err != nil || len(bad) != 1 || bad[0] != "h1" {
		t.Fatalf("unhealthy = %v err=%v", bad, err)
	}
	caps, _ := p.Capacity(context.Background())
	if caps["pool"].Ready != 0 {
		t.Fatalf("quarantined host must not be READY: %+v", caps)
	}
}

// DrainN drains by count without inventing IDs.
func TestStaticProviderDrainN(t *testing.T) {
	p := NewStaticProvider("static")
	for _, id := range []string{"h1", "h2", "h3"} {
		if err := p.Add(Instance{ID: id, Profile: "pool"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.DrainN(context.Background(), "pool", 2); err != nil {
		t.Fatal(err)
	}
	caps, _ := p.Capacity(context.Background())
	if caps["pool"].Draining != 2 {
		t.Fatalf("capacity = %+v, want 2 draining", caps)
	}
	// Terminate removes them entirely.
	if err := p.Terminate(context.Background(), []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	caps, _ = p.Capacity(context.Background())
	if caps["pool"].Max != 1 {
		t.Fatalf("after terminate: %+v", caps)
	}
}

// A static provider plugged into Reconcile converges toward the target
// without fabricating.
func TestStaticProviderWithReconcile(t *testing.T) {
	p := NewStaticProvider("static")
	for _, id := range []string{"h1", "h2"} {
		_ = p.Add(Instance{ID: id, Profile: "pool", State: StateReady})
	}
	m := NewManager()
	if err := m.Register(p); err != nil {
		t.Fatal(err)
	}
	rep := m.Reconcile(context.Background(), []Target{{
		Provider: "static",
		Profile:  Profile{Name: "pool", Min: 0, Max: 10},
		Want:     5,
	}})
	if rep.Errors != 0 {
		t.Fatalf("reconcile errors: %+v", rep.Changes)
	}
	// Adopted 2 of 5 requested: a static pool never invents the rest.
	adopted := 0
	for _, c := range rep.Changes {
		if c.Action == "provision" {
			adopted += c.Count
		}
	}
	if adopted != 2 {
		t.Fatalf("adopted %d, want 2", adopted)
	}
}

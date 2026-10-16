package fleet

import (
	"context"
	"fmt"
	"sync"
)

// StaticProvider is the production baseline: a fixed pool of pre-provisioned
// hosts. It is the first real provider behind the SPI — not a test fake.
// Provision() may only "adopt" hosts already registered in its inventory
// (a static pool never creates infrastructure); Drain/Terminate mark them
// and remove them from the adoptable set.
type StaticProvider struct {
	name string

	mu        sync.Mutex
	inventory map[string]Instance
	inUse     map[string]bool
}

// NewStaticProvider builds an empty static pool.
func NewStaticProvider(name string) *StaticProvider {
	return &StaticProvider{
		name:      name,
		inventory: map[string]Instance{},
		inUse:     map[string]bool{},
	}
}

func (p *StaticProvider) Name() string { return p.name }

// Add registers a pre-provisioned host into the adoptable inventory.
func (p *StaticProvider) Add(inst Instance) error {
	if inst.ID == "" {
		return fmt.Errorf("fleet/static: instance id is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.inventory[inst.ID]; exists {
		return fmt.Errorf("fleet/static: instance %q already registered", inst.ID)
	}
	if inst.State == "" {
		inst.State = StateReady
	}
	p.inventory[inst.ID] = inst
	return nil
}

// Capacity reports the pool's live shape. READY counts only ADOPTED hosts
// (inUse && StateReady): an idle inventory entry is available capacity, not
// running capacity. Counting idle entries as Ready made Reconcile believe
// the target was already met and skip Provision — the host stayed idle and
// the pool silently under-delivered.
func (p *StaticProvider) Capacity(context.Context) (map[string]Capacity, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]Capacity{}
	for _, inst := range p.inventory {
		c := out[inst.Profile]
		switch inst.State {
		case StateReady:
			if p.inUse[inst.ID] {
				c.Ready++
			}
		case StatePending:
			c.Pending++
		case StateDraining:
			c.Draining++
		}
		c.Max++
		out[inst.Profile] = c
	}
	return out, nil
}

// Provision adopts up to want idle hosts from the inventory. A static pool
// never fabricates capacity: if the inventory cannot cover want, it adopts
// what it has and reports no error (the reconciler sees the shortfall via
// Capacity and may raise the target elsewhere).
func (p *StaticProvider) Provision(_ context.Context, profile Profile, want int) ([]Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Instance
	for id, inst := range p.inventory {
		if len(out) >= want {
			break
		}
		if inst.Profile != profile.Name || p.inUse[id] {
			continue
		}
		if inst.State != StateReady {
			continue
		}
		p.inUse[id] = true
		out = append(out, inst)
	}
	return out, nil
}

// Drain marks adopted hosts as draining and frees them from the adoptable
// set.
func (p *StaticProvider) Drain(_ context.Context, ids []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		inst, ok := p.inventory[id]
		if !ok {
			return fmt.Errorf("fleet/static: unknown instance %q", id)
		}
		inst.State = StateDraining
		p.inventory[id] = inst
		delete(p.inUse, id)
	}
	return nil
}

// Terminate removes hosts from the inventory entirely.
func (p *StaticProvider) Terminate(_ context.Context, ids []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		if _, ok := p.inventory[id]; !ok {
			return fmt.Errorf("fleet/static: unknown instance %q", id)
		}
		delete(p.inventory, id)
		delete(p.inUse, id)
	}
	return nil
}

// Cost is operator-declared per host (0 when unknown).
func (p *StaticProvider) Cost(_ context.Context, id string) (float64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.inventory[id]
	if !ok {
		return 0, fmt.Errorf("fleet/static: unknown instance %q", id)
	}
	return inst.CostPerHour, nil
}

// Capabilities returns the host's label set.
func (p *StaticProvider) Capabilities(_ context.Context, id string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.inventory[id]
	if !ok {
		return nil, fmt.Errorf("fleet/static: unknown instance %q", id)
	}
	return append([]string(nil), inst.Labels...), nil
}

// Attestation returns the host's identity evidence (empty when none).
func (p *StaticProvider) Attestation(_ context.Context, id string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inst, ok := p.inventory[id]
	if !ok {
		return nil, fmt.Errorf("fleet/static: unknown instance %q", id)
	}
	return append([]byte(nil), inst.Attestation...), nil
}

// Compile-time conformance.
var (
	_ Provisioner   = (*StaticProvider)(nil)
	_ CountDrainer  = (*StaticProvider)(nil)
	_ HealthScanner = (*StaticProvider)(nil)
)

// DrainN drains n adopted hosts of the named profile.
func (p *StaticProvider) DrainN(_ context.Context, profile string, n int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	drained := 0
	for id, inst := range p.inventory {
		if drained >= n {
			break
		}
		if inst.Profile != profile || inst.State != StateReady {
			continue
		}
		inst.State = StateDraining
		p.inventory[id] = inst
		delete(p.inUse, id)
		drained++
	}
	return nil
}

// Unhealthy reports hosts whose recorded state is quarantined (a static
// pool cannot probe liveness itself — the runner layer reports quarantine).
func (p *StaticProvider) Unhealthy(_ context.Context, profile string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for id, inst := range p.inventory {
		if inst.Profile == profile && inst.State == StateQuarantined {
			out = append(out, id)
		}
	}
	return out, nil
}

// Quarantine marks a host unhealthy so Reconcile will remove it from the
// READY set before any scale decision.
func (p *StaticProvider) Quarantine(ids []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		if inst, ok := p.inventory[id]; ok {
			inst.State = StateQuarantined
			p.inventory[id] = inst
			delete(p.inUse, id)
		}
	}
}

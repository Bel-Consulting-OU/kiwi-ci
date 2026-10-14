// Package fleet is the generalized Kiwi runner-capacity layer. Providers
// (static pools, Kubernetes, cloud VMs, custom) implement Provisioner; the
// scheduler asks for capacity profiles and never knows which infrastructure
// fulfils them. This is deliberately NOT a copy of any foreign CI backend:
// Kiwi placement already speaks labels/regions/resources, and fleet is the
// dynamic-fleet dimension beneath it.
package fleet

import (
	"context"
	"time"
)

// Profile is a capacity request. Placement already carries labels/regions;
// fleet adds the dynamic shape (size class, GPU, preemption, cost budget).
type Profile struct {
	// Name is the operator-facing pool name (e.g. "arm64-eu-west").
	Name string
	// Labels is the runner label set the provisioned instances must carry.
	Labels []string
	// Min/Max bound the pool. Scale-to-zero is Min=0.
	Min, Max int
	// Warm is the number of instances to keep pre-provisioned.
	Warm int
	// Architecture / GPU / MemoryBytes refine the instance shape.
	Architecture string
	GPU          bool
	MemoryBytes  int64
	// Spot requests preemptible/spot capacity when the provider supports it.
	Spot bool
	// Region is the provider placement region.
	Region string
	// CostBudget is a per-hour ceiling the provider should respect when
	// choosing instance types. Zero means no ceiling.
	CostBudget float64
}

// Instance is one provisioned runner host.
type Instance struct {
	ID          string
	Profile     string
	Labels      []string
	Region      string
	Arch        string
	State       InstanceState
	StartedAt   time.Time
	CostPerHour float64
	// Attestation is the provider's identity evidence for the instance
	// (cloud instance identity doc, TPM quote, …). Empty when unsupported.
	Attestation []byte
}

// InstanceState is the lifecycle of one fleet instance.
type InstanceState string

const (
	StatePending     InstanceState = "pending"
	StateReady       InstanceState = "ready"
	StateDraining    InstanceState = "draining"
	StateQuarantined InstanceState = "quarantined"
	StateTerminated  InstanceState = "terminated"
)

// Provisioner is the provider SPI. Implementations must be safe for
// concurrent use and must fail closed on authorization errors.
type Provisioner interface {
	// Name is the provider kind (e.g. "kubernetes", "aws", "static").
	Name() string
	// Capacity reports currently available/used instances per profile.
	Capacity(ctx context.Context) (map[string]Capacity, error)
	// Provision starts instances for the profile until want are ready.
	Provision(ctx context.Context, profile Profile, want int) ([]Instance, error)
	// Drain marks instances for graceful shutdown (no new leases).
	Drain(ctx context.Context, instanceIDs []string) error
	// Terminate destroys instances immediately.
	Terminate(ctx context.Context, instanceIDs []string) error
	// Cost reports the observed per-hour cost of an instance.
	Cost(ctx context.Context, instanceID string) (float64, error)
	// Capabilities reports the label/capability set of an instance.
	Capabilities(ctx context.Context, instanceID string) ([]string, error)
	// Attestation returns provider identity evidence for an instance.
	Attestation(ctx context.Context, instanceID string) ([]byte, error)
}

// Capacity is one profile's current usage.
type Capacity struct {
	Ready    int
	Pending  int
	Draining int
	Max      int
}

// Manager drives providers toward pool targets (scale-to-zero, warm pools,
// queue-aware provisioning, drain-on-upgrade, quarantine of unhealthy
// instances). It never executes work itself — the scheduler does.
type Manager struct {
	providers map[string]Provisioner
}

// NewManager builds an empty manager.
func NewManager() *Manager {
	return &Manager{providers: map[string]Provisioner{}}
}

// Register installs a provider under its Name().
func (m *Manager) Register(p Provisioner) {
	m.providers[p.Name()] = p
}

// Provider returns a registered provider.
func (m *Manager) Provider(name string) (Provisioner, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// Providers lists registered provider names (sorted by registration map
// iteration is avoided by the caller's own ordering when it matters).
func (m *Manager) Providers() []Provisioner {
	out := make([]Provisioner, 0, len(m.providers))
	for _, p := range m.providers {
		out = append(out, p)
	}
	return out
}

package fleet

import (
	"context"
	"fmt"
	"sort"
)

// Target is one pool's desired end-state for a single Reconcile pass. The
// scheduler (not fleet) decides how much work exists; fleet only shapes
// capacity toward these targets.
type Target struct {
	// Provider names the provisioner that owns this pool. Empty means
	// "every registered provider that reports this profile name" — never a
	// silent cross-provider fill of a same-named pool on the wrong host.
	Provider string
	// Profile is the pool shape and identity (Profile.Name).
	Profile Profile
	// Want is the number of READY+PENDING instances the pool converges to.
	// Clamped to [Profile.Min, Profile.Max] and to the provider's Max.
	Want int
	// Idle marks the pool as having no demand.
	Idle bool
	// Idle pools converge to Profile.Min (the warm floor). DrainIdle
	// releases even that floor and scales to zero.
	DrainIdle bool
}

// Change is one action Reconcile decided to take (or attempted and failed).
type Change struct {
	Provider string
	Profile  string
	Action   string // provision | drain | quarantine | capacity
	Count    int
	Err      error
}

// ReconcileReport is the outcome of one pass.
type ReconcileReport struct {
	Changes []Change
	// Errors counts failed provider actions. Non-zero means the fleet is
	// NOT converged; the caller must retry or alert.
	Errors int
}

// CountDrainer is an optional Provisioner extension: drain N instances of a
// named pool without the caller inventing IDs. Providers that only implement
// the ID form of Drain are left alone — Reconcile never fabricates instance
// IDs to feed Drain.
type CountDrainer interface {
	DrainN(ctx context.Context, profile string, n int) error
}

// HealthScanner is an optional Provisioner extension: report the IDs of
// instances that must leave the READY set (capability drift, attestation
// failure, liveness loss). Reconcile quarantines them BEFORE any scale
// decision so unhealthy hosts never count toward Want.
type HealthScanner interface {
	Unhealthy(ctx context.Context, profile string) ([]string, error)
}

// Reconcile drives every registered provider toward the given targets in one
// pass. It is idempotent: a second pass over unchanged state provisions
// nothing and drains nothing. Provider failures are recorded on the report
// and never abort the rest of the pass — one broken pool must not freeze
// the others.
//
// Authority order per target:
//  1. Capacity is read first. A provider that cannot report capacity is
//     failed closed: no provision/drain decisions on unknown state.
//  2. Unhealthy instances are quarantined before any scale decision.
//  3. READY+PENDING below Want provisions the gap, never above Max.
//  4. READY above Want (or above Min for DrainIdle pools) is drained.
//     Terminate is never called here — drain is the graceful path.
func (m *Manager) Reconcile(ctx context.Context, targets []Target) ReconcileReport {
	var rep ReconcileReport
	if m == nil || len(targets) == 0 {
		return rep
	}
	names := make([]string, 0, len(m.providers))
	for n := range m.providers {
		names = append(names, n)
	}
	sort.Strings(names)

	// Capacity is fetched once per provider per pass.
	type providerState struct {
		prov Provisioner
		cap  map[string]Capacity
		err  error
	}
	states := map[string]*providerState{}
	for _, n := range names {
		st := &providerState{prov: m.providers[n]}
		st.cap, st.err = st.prov.Capacity(ctx)
		states[n] = st
	}

	for _, t := range targets {
		if t.Profile.Name == "" {
			continue
		}
		for _, n := range names {
			if t.Provider != "" && t.Provider != n {
				continue
			}
			st := states[n]
			if st.err != nil {
				// Fail closed on unknown state. Emit one capacity error per
				// provider per pass, not one per target.
				if !capacityErrRecorded(&rep, n) {
					rep.Errors++
					rep.Changes = append(rep.Changes, Change{
						Provider: n, Action: "capacity",
						Err: fmt.Errorf("fleet: %s capacity: %w", n, st.err),
					})
				}
				continue
			}
			// If the target is provider-scoped and this provider does not
			// know the pool and reports no room for it, still try: a missing
			// pool is zero-capacity and Want>0 provisions it.
			m.reconcileOne(ctx, n, st.prov, t, st.cap, &rep)
		}
	}
	return rep
}

func capacityErrRecorded(rep *ReconcileReport, provider string) bool {
	for _, c := range rep.Changes {
		if c.Provider == provider && c.Action == "capacity" {
			return true
		}
	}
	return false
}

func (m *Manager) reconcileOne(ctx context.Context, name string, prov Provisioner, t Target, cap map[string]Capacity, rep *ReconcileReport) {
	p := t.Profile

	// Health scan first: unhealthy hosts must never count as READY.
	if hs, ok := prov.(HealthScanner); ok {
		bad, err := hs.Unhealthy(ctx, p.Name)
		if err != nil {
			rep.Errors++
			rep.Changes = append(rep.Changes, Change{
				Provider: name, Profile: p.Name, Action: "quarantine",
				Err: fmt.Errorf("fleet: %s health %s: %w", name, p.Name, err),
			})
		} else if len(bad) > 0 {
			if err := prov.Drain(ctx, bad); err != nil {
				rep.Errors++
				rep.Changes = append(rep.Changes, Change{
					Provider: name, Profile: p.Name, Action: "quarantine",
					Err: fmt.Errorf("fleet: %s quarantine %s: %w", name, p.Name, err),
				})
			} else {
				rep.Changes = append(rep.Changes, Change{
					Provider: name, Profile: p.Name, Action: "quarantine", Count: len(bad),
				})
				// They left the READY set.
				c := cap[p.Name]
				if c.Ready >= len(bad) {
					c.Ready -= len(bad)
				} else {
					c.Ready = 0
				}
				cap[p.Name] = c
			}
		}
	}

	c, ok := cap[p.Name]
	if !ok {
		c = Capacity{Max: p.Max}
	}
	if c.Max == 0 {
		c.Max = p.Max
	}
	if c.Max < 0 {
		c.Max = 0
	}

	want := t.Want
	if t.Idle && t.DrainIdle {
		// Explicit scale-to-zero: even a warm Min floor is released.
		want = 0
	} else if t.Idle {
		// Idle pool converges to its warm floor (Min), never below.
		want = p.Min
	}
	if want < p.Min && !(t.Idle && t.DrainIdle) {
		want = p.Min
	}
	if want > p.Max {
		want = p.Max
	}
	if c.Max > 0 && want > c.Max {
		want = c.Max
	}

	ready := c.Ready
	if ready < 0 {
		ready = 0
	}
	pending := c.Pending
	if pending < 0 {
		pending = 0
	}
	// Pending already counts toward the target so a slow provisioner is
	// never double-fed.
	effective := ready + pending

	if effective < want {
		n := want - effective
		inst, err := prov.Provision(ctx, p, n)
		if err != nil {
			rep.Errors++
			rep.Changes = append(rep.Changes, Change{
				Provider: name, Profile: p.Name, Action: "provision", Count: n,
				Err: fmt.Errorf("fleet: %s provision %s x%d: %w", name, p.Name, n, err),
			})
			return
		}
		rep.Changes = append(rep.Changes, Change{
			Provider: name, Profile: p.Name, Action: "provision", Count: len(inst),
		})
		return
	}

	if ready > want {
		surplus := ready - want
		if cd, ok := prov.(CountDrainer); ok {
			if err := cd.DrainN(ctx, p.Name, surplus); err != nil {
				rep.Errors++
				rep.Changes = append(rep.Changes, Change{
					Provider: name, Profile: p.Name, Action: "drain",
					Err: fmt.Errorf("fleet: %s drain %s x%d: %w", name, p.Name, surplus, err),
				})
			} else {
				rep.Changes = append(rep.Changes, Change{
					Provider: name, Profile: p.Name, Action: "drain", Count: surplus,
				})
			}
		}
		// No CountDrainer: leave the surplus rather than invent IDs.
	}
}

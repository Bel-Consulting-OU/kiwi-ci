package storage

// W3-A real-PostgreSQL integration tests for capability separation. They pin
// that the SQL claim (AcquireLeaseAtomic) and the in-memory claim make the
// SAME decision for the reported-hardware ∩ live-profile semantics, that the
// persisted registration snapshot carries the reported claim and enforcement
// marker, and that a live profile edit can never re-widen the runner past its
// reported hardware. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go
// file in this package.

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationCapabilityIntersectionClaimParity runs the W3-A capability
// matrix through BOTH claim implementations and asserts the same verdict.
func TestIntegrationCapabilityIntersectionClaimParity(t *testing.T) {
	runtimeJob := func(runID, jobID, runtime string) model.Job {
		j := pgITJob(runID, jobID, pgITRepo)
		j.CompiledJobPayload = compiledPayloadWithRuntime(runtime)
		return j
	}
	cases := []struct {
		name    string
		profile *model.RunnerProfile
		runner  func(runnerID, serial string) model.Runner
		runtime string
		want    bool
	}{
		{
			name:    "profile ceiling intersected with the reported hardware denies container",
			profile: &model.RunnerProfile{ID: "cap-parity-ceiling-" + pgITNewID(t), Capabilities: []string{"native", "container"}, MaxCapacity: 2},
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, CertSerial: serial,
					ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}
			},
			runtime: "container",
			want:    false,
		},
		{
			name:    "profile ceiling intersected with the reported hardware grants native",
			profile: &model.RunnerProfile{ID: "cap-parity-native-" + pgITNewID(t), Capabilities: []string{"native", "container"}, MaxCapacity: 2},
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, CertSerial: serial,
					ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}
			},
			runtime: "native",
			want:    true,
		},
		{
			name:    "empty profile ceiling denies every runtime",
			profile: &model.RunnerProfile{ID: "cap-parity-empty-" + pgITNewID(t), MaxCapacity: 1},
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial,
					ReportedCapabilities: []string{"native"}}
			},
			runtime: "native",
			want:    false,
		},
		{
			name:    "empty reported claim denies every runtime",
			profile: &model.RunnerProfile{ID: "cap-parity-noclaim-" + pgITNewID(t), Capabilities: []string{"container"}, MaxCapacity: 2},
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, CertSerial: serial,
					ReportedCapabilities: []string{}, CapabilitiesEnforced: true}
			},
			runtime: "container",
			want:    false,
		},
		{
			name: "legacy unlinked empty list stays unrestricted",
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 2}
			},
			runtime: "tart",
			want:    true,
		},
		{
			name: "legacy unlinked non-empty list still has to contain the runtime",
			runner: func(runnerID, serial string) model.Runner {
				return model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, Capabilities: []string{"container"}}
			},
			runtime: "tart",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runnerID, runID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
			serial := "cap-parity-serial-" + pgITNewID(t)
			job := runtimeJob(runID, jobID, tc.runtime)
			claim := raceClaim(jobID, runnerID, 1)
			claim.Runtime = tc.runtime
			assertClaimCaseParity(t, claimCase{
				runner:  tc.runner(runnerID, serial),
				job:     job,
				claim:   claim,
				serial:  serial,
				profile: tc.profile,
				want:    tc.want,
			})
		})
	}
}

// TestIntegrationCapabilitySnapshotLiveAtomicPostgres pins the registration
// snapshot vs live profile vs AtomicLeaseStore parity on real PostgreSQL: the
// persisted snapshot carries reported_capabilities/capabilities_enforced, the
// claim recomputes the intersection from them on every lease, and a live
// profile widening cannot restore a runtime the registration proved absent.
func TestIntegrationCapabilitySnapshotLiveAtomicPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)

	// The registration snapshot exactly as the profile-linked registration
	// persists it: reported [native], effective [native], enforced.
	if err := st.UpsertRunner(ctx, model.Runner{
		ID: runnerID, Name: runnerID, Capacity: 2, CostPerHour: 9, Labels: []string{"snapshot"},
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true,
	}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	snapshot, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if !snapshot.CapabilitiesEnforced || !reflect.DeepEqual(snapshot.ReportedCapabilities, []string{"native"}) ||
		!reflect.DeepEqual(snapshot.Capabilities, []string{"native"}) {
		t.Fatalf("snapshot = caps %v enforced %v reported %v, want the persisted [native] claim",
			snapshot.Capabilities, snapshot.CapabilitiesEnforced, snapshot.ReportedCapabilities)
	}

	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "cap-live-pg", Capabilities: []string{"native"}, MaxCapacity: 2, CostPerHour: 3.5}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, "cap-live-pg"); err != nil {
		t.Fatalf("link: %v", err)
	}

	claimFor := func(jobID, runtime string, gen int64) LeaseClaim {
		return LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: gen,
			Runtime: runtime, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	}

	// profile [native] ∩ reported [native] = [native]: container denied.
	runC1, jobC1 := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runC1, jobC1, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, claimFor(jobC1, "container", 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("container claim under profile [native] = %v, want ErrNoCapacity", err)
	}
	// A native claim leases and freezes the LIVE profile's rate, proving the
	// live overlay (not the snapshot's 9) decided the lease.
	runN1, jobN1 := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runN1, jobN1, pgITRepo)
	leased, err := st.AcquireLeaseAtomic(ctx, claimFor(jobN1, "native", 1))
	if err != nil {
		t.Fatalf("native claim = %v, want the live [native] intersection", err)
	}
	if leased.CostRate != 3.5 {
		t.Fatalf("frozen cost rate = %v, want the live profile's 3.5", leased.CostRate)
	}

	// Widen the live profile back to [native,container]: the intersection is
	// recomputed from the REPORTED hardware, so container stays denied.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "cap-live-pg", Capabilities: []string{"native", "container"}, MaxCapacity: 2, CostPerHour: 3.5}); err != nil {
		t.Fatalf("widen profile: %v", err)
	}
	runC2, jobC2 := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runC2, jobC2, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, claimFor(jobC2, "container", 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("container claim after the profile widened = %v, want ErrNoCapacity", err)
	}
	runN2, jobN2 := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runN2, jobN2, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, claimFor(jobN2, "native", 1)); err != nil {
		t.Fatalf("native claim after the profile widened = %v, want the [native] intersection", err)
	}
}

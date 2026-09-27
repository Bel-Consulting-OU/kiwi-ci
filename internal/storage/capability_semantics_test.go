package storage

// W3-A capability-separation semantics over the in-memory claim path: the
// registration's REPORTED hardware claim is the ceiling the live profile
// intersects with, an ENFORCED empty set denies every runtime, and a legacy
// unprofiled runner keeps the historical "empty list = unrestricted"
// semantics. These cases pin the meanings the lease predicate, the SQL
// claim and the scheduler prefilter share.

import (
	"context"
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// capabilityJob builds a queued job carrying one runtime in its compiled
// payload (empty runtime means "no payload-derived runtime", the native
// default).
func capabilityJob(t *testing.T, id, runtime string) model.Job {
	t.Helper()
	j := liveProfileJob(id, "build-"+id, nil, "")
	if runtime != "" {
		j.CompiledJobPayload = compiledPayloadWithRuntime(runtime)
	}
	return j
}

// TestMemClaimNarrowsToReportedHardware is the W3-A regression for the live
// profile overwrite: the profile ceiling is [native,container] (and later
// widened), the registration reported [native], so the effective set is
// [native] on EVERY lease and the container job is never leased — even after
// the live profile widens back to container.
func TestMemClaimNarrowsToReportedHardware(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	const runnerID = "cccccccccccccccccccccccccccccc11"
	const serial = "cap-hardware-serial"
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "cap-p", Capabilities: []string{"native"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx, serial, "cap-p"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx, model.Runner{
		ID: runnerID, Capacity: 1, CertSerial: serial,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true,
	}); err != nil {
		t.Fatal(err)
	}

	// The live profile widens to [native,container]: the recomputed
	// intersection must stay [native].
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "cap-p", Capabilities: []string{"native", "container"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	container := capabilityJob(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa30", "container")
	if err := m.InsertJob(ctx, container); err != nil {
		t.Fatal(err)
	}
	if _, err := liveProfileClaim(m, container.ID, runnerID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("container lease under a [native]-reported runner = %v, want ErrNoCapacity (the live profile cannot widen the hardware)", err)
	}

	native := capabilityJob(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa31", "native")
	if err := m.InsertJob(ctx, native); err != nil {
		t.Fatal(err)
	}
	if _, err := liveProfileClaim(m, native.ID, runnerID); err != nil {
		t.Fatalf("native lease = %v, want the [native] intersection", err)
	}
}

// TestMemClaimEnforcedEmptySetsDenyEveryRuntime pins the two authoritative
// empty-set shapes: an empty profile ceiling and an empty reported claim both
// recompute to an enforced empty set that denies the job runtime.
func TestMemClaimEnforcedEmptySetsDenyEveryRuntime(t *testing.T) {
	t.Run("empty profile ceiling denies all", func(t *testing.T) {
		m := newMemStore()
		ctx := context.Background()
		const runnerID = "cccccccccccccccccccccccccccccc12"
		const serial = "cap-empty-profile"
		if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "empty-p", Capabilities: nil, MaxCapacity: 1}); err != nil {
			t.Fatal(err)
		}
		if err := m.BindCertProfile(ctx, serial, "empty-p"); err != nil {
			t.Fatal(err)
		}
		if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 1, CertSerial: serial, ReportedCapabilities: []string{"native"}}); err != nil {
			t.Fatal(err)
		}
		for i, runtime := range []string{"", "native", "container", "tart"} {
			job := capabilityJob(t, []string{
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa40",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa41",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa42",
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa43",
			}[i], runtime)
			if err := m.InsertJob(ctx, job); err != nil {
				t.Fatal(err)
			}
			if _, err := liveProfileClaim(m, job.ID, runnerID); !errors.Is(err, ErrNoCapacity) {
				t.Fatalf("runtime %q under an empty profile ceiling = %v, want ErrNoCapacity", runtime, err)
			}
		}
	})

	t.Run("empty reported claim denies all", func(t *testing.T) {
		m := newMemStore()
		ctx := context.Background()
		const runnerID = "cccccccccccccccccccccccccccccc13"
		const serial = "cap-empty-reported"
		if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: "container-p", Capabilities: []string{"container"}, MaxCapacity: 2}); err != nil {
			t.Fatal(err)
		}
		if err := m.BindCertProfile(ctx, serial, "container-p"); err != nil {
			t.Fatal(err)
		}
		if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 2, CertSerial: serial, ReportedCapabilities: []string{}, CapabilitiesEnforced: true}); err != nil {
			t.Fatal(err)
		}
		job := capabilityJob(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa44", "container")
		if err := m.InsertJob(ctx, job); err != nil {
			t.Fatal(err)
		}
		if _, err := liveProfileClaim(m, job.ID, runnerID); !errors.Is(err, ErrNoCapacity) {
			t.Fatalf("container lease under an empty reported claim = %v, want ErrNoCapacity", err)
		}
	})
}

// TestMemClaimLegacyUnprofiledEmptyListUnrestricted pins the deliberately
// retained historical semantics: an UNLINKED legacy runner whose declared
// capability list is empty imposes no runtime restriction.
func TestMemClaimLegacyUnprofiledEmptyListUnrestricted(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	const runnerID = "cccccccccccccccccccccccccccccc14"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 2}); err != nil {
		t.Fatal(err)
	}
	job := capabilityJob(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa45", "tart")
	if err := m.InsertJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := liveProfileClaim(m, job.ID, runnerID); err != nil {
		t.Fatalf("legacy unprofiled empty-list lease = %v, want unrestricted", err)
	}

	// A non-empty legacy list still has to contain the runtime.
	const otherID = "cccccccccccccccccccccccccccccc15"
	if err := m.UpsertRunner(ctx, model.Runner{ID: otherID, Capacity: 2, Capabilities: []string{"container"}}); err != nil {
		t.Fatal(err)
	}
	job2 := capabilityJob(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa46", "tart")
	if err := m.InsertJob(ctx, job2); err != nil {
		t.Fatal(err)
	}
	if _, err := liveProfileClaim(m, job2.ID, otherID); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("legacy non-empty-list lease = %v, want ErrNoCapacity", err)
	}
}

// TestLeasePredicateCapabilityMatrix pins the shared pure predicate over the
// three meanings of the capability set, including the native default for a
// payload-less job.
func TestLeasePredicateCapabilityMatrix(t *testing.T) {
	base := func(caps []string, enforced bool, runtime string) LeasePredicate {
		j := predicateJob()
		if runtime != "" {
			j.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: compiledRuntimeJSON(t, runtime)}
		}
		r := predicateRunner()
		r.Capabilities = caps
		r.CapabilitiesEnforced = enforced
		return LeasePredicate{Runner: r, Job: j}
	}
	cases := []struct {
		name     string
		caps     []string
		enforced bool
		runtime  string
		want     bool
	}{
		{"enforced intersection grants native", []string{"native"}, true, "native", true},
		{"enforced intersection denies container", []string{"native"}, true, "container", false},
		{"enforced empty denies native default", nil, true, "", false},
		{"enforced empty denies container", nil, true, "container", false},
		{"legacy empty list unrestricted", nil, false, "tart", true},
		{"legacy empty list unrestricted native default", nil, false, "", true},
		{"legacy non-empty list must contain", []string{"container"}, false, "native", false},
		{"legacy non-empty list contains", []string{"container"}, false, "container", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base(tc.caps, tc.enforced, tc.runtime).Allows(); got != tc.want {
				t.Fatalf("Allows = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClaimAllowsRunnerCapabilityMatrix pins the same meanings on the typed
// claim predicate the SQL claim uses, so the two paths cannot drift.
func TestClaimAllowsRunnerCapabilityMatrix(t *testing.T) {
	claim := LeaseClaim{JobID: "job", RunnerID: "runner", Runtime: "container", Generation: 1}
	r := model.Runner{Capacity: 4, Capabilities: []string{"native"}, CapabilitiesEnforced: true}
	if ClaimAllowsRunner(r, claim) {
		t.Fatal("enforced [native] runner admitted a container claim")
	}
	r.Capabilities = nil
	if ClaimAllowsRunner(r, claim) {
		t.Fatal("enforced empty runner admitted a container claim")
	}
	r.CapabilitiesEnforced = false
	if !ClaimAllowsRunner(r, claim) {
		t.Fatal("legacy empty runner must admit a container claim")
	}
	claim.Runtime = ""
	if !ClaimAllowsRunner(r, claim) {
		t.Fatal("legacy empty runner must admit the native default")
	}
	r.Capabilities = []string{"native"}
	if !ClaimAllowsRunner(r, claim) {
		t.Fatal("legacy [native] runner must admit the native default")
	}
	claim.Runtime = "container"
	if ClaimAllowsRunner(r, claim) {
		t.Fatal("legacy [native] runner admitted a container claim")
	}
}

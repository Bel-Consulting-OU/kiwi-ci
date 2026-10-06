package storage

// Tests for the job-scoped cgroup capability and the lease-claim envelope
// relaxation it enables: the profile flag propagates through
// ResolveRunnerProfile into the effective runner, LeaseClaim.RequestedResources
// drops the service envelope only when IgnoreServiceEnvelope is set, and the
// in-memory claim (which shares that one summation with the SQL claim) admits
// and reserves the job-only request under the relaxed rule.

import (
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestResolveRunnerProfileJobCgroup pins the propagation rules: the linked
// profile's flag wins (set or cleared) and an unlinked runner keeps its own
// registration value.
func TestResolveRunnerProfileJobCgroup(t *testing.T) {
	base := model.Runner{ID: leaseRunner, ReportedCapabilities: []string{"native"}}
	enabled := ResolveRunnerProfile(base, model.RunnerProfile{
		ID: leaseProf, Capabilities: []string{"native"}, MaxCapacity: 2, JobCgroup: true,
	}, true)
	if !enabled.JobCgroup {
		t.Fatal("linked profile with job_cgroup=true must set the effective runner's JobCgroup")
	}
	cleared := ResolveRunnerProfile(model.Runner{ID: leaseRunner, JobCgroup: true, ReportedCapabilities: []string{"native"}}, model.RunnerProfile{
		ID: leaseProf, Capabilities: []string{"native"}, MaxCapacity: 2, JobCgroup: false,
	}, true)
	if cleared.JobCgroup {
		t.Fatal("linked profile without job_cgroup must clear a stale registration value")
	}
	unlinked := ResolveRunnerProfile(model.Runner{ID: leaseRunner, JobCgroup: true}, model.RunnerProfile{}, false)
	if !unlinked.JobCgroup {
		t.Fatal("unlinked resolution must keep the registration snapshot unchanged")
	}
}

// TestLeaseClaimRequestedResourcesIgnoreServiceEnvelope pins the summation:
// the default is the job+envelope union (byte-identical to the pre-flag
// behavior) and IgnoreServiceEnvelope drops the envelope on every dimension.
func TestLeaseClaimRequestedResourcesIgnoreServiceEnvelope(t *testing.T) {
	job := model.ResourceCapacity{CPU: 3, Memory: 1024, Disk: 2048, PIDs: 5}
	env := model.ResourceCapacity{CPU: 2, Memory: 4096, Disk: 8192, PIDs: 7}
	c := LeaseClaim{CPURequest: job.CPU, MemoryRequest: job.Memory, DiskRequest: job.Disk, PIDsRequest: job.PIDs, ServiceEnvelopeRequest: env}
	if got := c.RequestedResources(); got != model.AddResourceCapacity(job, env) {
		t.Fatalf("union RequestedResources = %+v, want %+v", got, model.AddResourceCapacity(job, env))
	}
	c.IgnoreServiceEnvelope = true
	if got := c.RequestedResources(); got != job {
		t.Fatalf("relaxed RequestedResources = %+v, want job request %+v", got, job)
	}
}

// TestMemLeaseClaimIgnoreServiceEnvelopeReservation proves the in-memory
// claim honors the claim's rule end to end: the union (3+2) is rejected
// against a 4-CPU runner, the relaxed claim is admitted, and the ledger
// charges exactly the job's own request.
func TestMemLeaseClaimIgnoreServiceEnvelopeReservation(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{CPU: 4})
	resourceJob(t, m, "run-cgroup", "job-cgroup", model.ResourceCapacity{CPU: 3})

	claim := resourceClaim("job-cgroup", leaseRunner, model.ResourceCapacity{CPU: 3})
	claim.ServiceEnvelopeRequest = model.ResourceCapacity{CPU: 2}
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("union claim error = %v, want ErrResourceCapacity", err)
	}
	claim.IgnoreServiceEnvelope = true
	j, err := m.AcquireLeaseAtomic(ctx(), claim)
	if err != nil {
		t.Fatalf("relaxed claim: %v", err)
	}
	if j.ID != "job-cgroup" {
		t.Fatalf("leased job = %s, want job-cgroup", j.ID)
	}
	assertReserved(t, m, leaseRunner, model.ResourceCapacity{CPU: 3})
}

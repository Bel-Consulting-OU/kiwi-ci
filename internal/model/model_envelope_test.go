package model

// Pin tests for the aggregate service-envelope reservation computation: a
// job's lease reservation is its OWN request plus the aggregate service
// envelope, and the one summation (AddResourceCapacity) is shared with
// LeaseClaim.RequestedResources so admission and the ledger cannot disagree.

import (
	"encoding/json"
	"testing"
)

// TestJobReservedResourcesIncludesServiceEnvelope: ReservedResources adds the
// envelope to the job's own request dimension by dimension; a job without
// services reserves exactly its own request (the pre-envelope behavior).
func TestJobReservedResourcesIncludesServiceEnvelope(t *testing.T) {
	j := Job{
		CPURequest: 1.5, MemoryRequest: 3 << 30, DiskRequest: 4 << 30, PIDsRequest: 100,
		ServiceEnvelopeRequest: ResourceCapacity{CPU: 2, Memory: 2 << 30, PIDs: 512},
	}
	got := j.ReservedResources()
	want := ResourceCapacity{CPU: 3.5, Memory: 5 << 30, Disk: 4 << 30, PIDs: 612}
	if got != want {
		t.Fatalf("ReservedResources with services = %+v, want %+v", got, want)
	}
	plain := Job{CPURequest: 1.5, MemoryRequest: 3 << 30, DiskRequest: 4 << 30, PIDsRequest: 100}
	if got := plain.ReservedResources(); got != plain.ResourceRequest() {
		t.Fatalf("ReservedResources without services = %+v, want the own request %+v", got, plain.ResourceRequest())
	}
}

// TestAddResourceCapacityIsTheSharedSummation: the helper itself is a pure
// dimension-wise sum (used by Job.ReservedResources and
// LeaseClaim.RequestedResources).
func TestAddResourceCapacityIsTheSharedSummation(t *testing.T) {
	got := AddResourceCapacity(ResourceCapacity{CPU: 1, Memory: 2, Disk: 3, PIDs: 4}, ResourceCapacity{CPU: 10, Memory: 20, PIDs: 40})
	want := ResourceCapacity{CPU: 11, Memory: 22, Disk: 3, PIDs: 44}
	if got != want {
		t.Fatalf("AddResourceCapacity = %+v, want %+v", got, want)
	}
}

// TestJobPayloadServiceEnvelopeRoundTrip: the envelope is an additive payload
// field. A job marshaled with it round-trips to the same reservation, and a
// LEGACY payload persisted before the field (no service_envelope_request key)
// decodes to the zero envelope and therefore reserves exactly its own request
// — the documented backward-compatible behavior.
func TestJobPayloadServiceEnvelopeRoundTrip(t *testing.T) {
	j := Job{ID: "j", CPURequest: 1, MemoryRequest: 3 << 30, PIDsRequest: 50,
		ServiceEnvelopeRequest: ResourceCapacity{CPU: 2, Memory: 2 << 30, PIDs: 512}}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var back Job
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ReservedResources() != j.ReservedResources() {
		t.Fatalf("round-trip reservation = %+v, want %+v", back.ReservedResources(), j.ReservedResources())
	}

	legacy := `{"id":"legacy","cpu_request":1,"memory_request":3221225472,"pids_request":50}`
	var old Job
	if err := json.Unmarshal([]byte(legacy), &old); err != nil {
		t.Fatal(err)
	}
	if old.ServiceEnvelopeRequest != (ResourceCapacity{}) {
		t.Fatalf("legacy payload envelope = %+v, want zero", old.ServiceEnvelopeRequest)
	}
	if got, want := old.ReservedResources(), old.ResourceRequest(); got != want {
		t.Fatalf("legacy reservation = %+v, want the own request %+v", got, want)
	}
}

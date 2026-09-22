package storage

// Mem-store parity for the K6-B self-healing capacity fold and the K6-C
// legacy services-without-envelope policy. The SQL side is covered by the
// real-PostgreSQL integration tests (postgres_reservation_selfheal_it_test.go
// and postgres_reservation_guard_it_test.go); these pin that the in-memory
// store answers identically for the same job state.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemReservedResourcesIgnoresOrphanRows: an orphan ledger row (its job is
// no longer running) is visible in the raw listing but charges nothing, and
// the batched fold agrees with the per-runner read. The reconcile then
// removes it.
func TestMemReservedResourcesIgnoresOrphanRows(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	now := time.Now().UTC()
	runnerID := "abcdef0123456789abcdef0123456789"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r", Capacity: 8}); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertRun(ctx, model.Run{ID: "run-orphan", Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	// A job completed by an old-version replica: terminal, lease cleared, but
	// its reservation row survived.
	if err := m.InsertJob(ctx, model.Job{ID: "job-orphan", RunID: "run-orphan", Key: "o", Status: model.StatusSuccess,
		MemoryRequest: 4 << 30, LeaseRunnerID: "", LeaseGeneration: 0, CreatedAt: now, FinishedAt: &now}); err != nil {
		t.Fatal(err)
	}
	// A live running lease with its row.
	if err := m.InsertJob(ctx, model.Job{ID: "job-live", RunID: "run-orphan", Key: "l", Status: model.StatusRunning,
		MemoryRequest: 2 << 30, LeaseRunnerID: runnerID, LeaseGeneration: 3, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.reservations["job-orphan"] = ResourceReservation{JobID: "job-orphan", RunnerID: runnerID, Generation: 1, Memory: 4 << 30}
	m.reservations["job-live"] = ResourceReservation{JobID: "job-live", RunnerID: runnerID, Generation: 3, Memory: 2 << 30}
	m.mu.Unlock()

	got, err := m.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Memory != 2<<30 {
		t.Fatalf("reserved = %+v, want the live row's 2 GiB only", got)
	}
	sums, err := m.RunnerReservationSums(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sums[runnerID] != got {
		t.Fatalf("batched sum = %+v, per-runner sum = %+v: mem parity broken", sums[runnerID], got)
	}
	if list, _ := m.ListResourceReservations(ctx, runnerID); len(list) != 2 {
		t.Fatalf("raw listing rows = %d, want both rows visible", len(list))
	}

	res, err := m.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 1 || res.Running != 1 || res.Upserted != 1 {
		t.Fatalf("reconcile = %+v, want deleted=1 running=1 upserted=1", res)
	}
	if got, _ := m.RunnerReservedResources(ctx, runnerID); got.Memory != 2<<30 {
		t.Fatalf("reserved after sweep = %+v, want 2 GiB", got)
	}
}

// TestMemReconcileLegacyServiceEnvelope: the mem reconcile applies the K6-C
// conservative charge to a container job that declares services with no
// envelope (the zero struct is the decoded form of a payload that predates
// the field), leaves a native job's declared-but-never-started services at
// their own-request charge, and keeps a persisted envelope exact.
func TestMemReconcileLegacyServiceEnvelope(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	now := time.Now().UTC()
	runnerID := "abcdef0123456789abcdef0123456789"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r", Capacity: 8, ResourceCapacity: model.ResourceCapacity{Memory: 16 << 30}}); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertRun(ctx, model.Run{ID: "run-legacy-env", Status: model.StatusQueued, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	declared := map[string]any{"job": map[string]any{
		"runtime":  "container",
		"services": []any{map[string]any{"name": "db", "image": "postgres:16"}},
	}}
	native := map[string]any{"job": map[string]any{
		"runtime":  "native",
		"services": []any{map[string]any{"name": "db", "image": "postgres:16"}},
	}}
	jobs := map[string]model.Job{
		"job-legacy": {ID: "job-legacy", RunID: "run-legacy-env", Key: "a", Status: model.StatusRunning,
			MemoryRequest: 3 << 30, LeaseRunnerID: runnerID, LeaseGeneration: 1, CreatedAt: now,
			CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: declared}},
		"job-native": {ID: "job-native", RunID: "run-legacy-env", Key: "b", Status: model.StatusRunning,
			MemoryRequest: 2 << 30, LeaseRunnerID: runnerID, LeaseGeneration: 1, CreatedAt: now,
			CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: native}},
		"job-modern": {ID: "job-modern", RunID: "run-legacy-env", Key: "c", Status: model.StatusRunning,
			MemoryRequest: 1 << 30, ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 1 << 30},
			LeaseRunnerID: runnerID, LeaseGeneration: 1, CreatedAt: now},
	}
	for _, j := range jobs {
		if err := m.InsertJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}

	res, err := m.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Running != 3 || res.Upserted != 3 {
		t.Fatalf("reconcile = %+v, want running=3 upserted=3", res)
	}
	// 2x3 GiB (legacy own re-charged as envelope) + 2 GiB (native own only) +
	// 2 GiB (modern own+envelope) = 10 GiB.
	got, err := m.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Memory != 10<<30 {
		t.Fatalf("reserved = %d, want 10 GiB (legacy jobs charged conservatively)", got.Memory)
	}
}

// TestMemLegacyServiceEnvelopeChargeShapes pins the mem helper's per-shape
// answer, including the JSON-round-tripped map and the in-process struct
// forms of the effective compiled job.
func TestMemLegacyServiceEnvelopeChargeShapes(t *testing.T) {
	own := model.ResourceCapacity{CPU: 2, Memory: 1 << 30, PIDs: 64}
	cases := []struct {
		name string
		job  model.Job
		want bool
	}{
		{name: "no compiled payload", job: model.Job{CPURequest: own.CPU, MemoryRequest: own.Memory, PIDsRequest: own.PIDs}},
		{name: "container services map form", want: true, job: model.Job{CPURequest: own.CPU, MemoryRequest: own.Memory, PIDsRequest: own.PIDs,
			CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{"runtime": "container", "services": []any{map[string]any{"name": "db"}}}}}}},
		{name: "container services struct form", want: true, job: model.Job{CPURequest: own.CPU, MemoryRequest: own.Memory, PIDsRequest: own.PIDs,
			CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: `{"job":{"runtime":"container","services":[{"name":"db"}]}}`}}},
		{name: "native services are never started", job: model.Job{CPURequest: own.CPU, MemoryRequest: own.Memory,
			CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{"runtime": "native", "services": []any{map[string]any{"name": "db"}}}}}}},
		{name: "container without services", job: model.Job{CPURequest: own.CPU, MemoryRequest: own.Memory,
			CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{"runtime": "container"}}}}},
		{name: "envelope already persisted", job: model.Job{MemoryRequest: own.Memory,
			ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 1 << 20},
			CompiledJobPayload:     &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{"runtime": "container", "services": []any{map[string]any{"name": "db"}}}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra, ok := legacyServiceEnvelopeCharge(tc.job)
			if ok != tc.want {
				t.Fatalf("charge ok = %v, want %v", ok, tc.want)
			}
			if tc.want && extra != nonNegativeCapacity(tc.job.ResourceRequest()) {
				t.Fatalf("charge = %+v, want the job's own request %+v", extra, nonNegativeCapacity(tc.job.ResourceRequest()))
			}
			if !tc.want && extra != (model.ResourceCapacity{}) {
				t.Fatalf("charge = %+v, want zero", extra)
			}
		})
	}

	// A negative dimension is clamped to zero, matching the SQL guards: a
	// hostile legacy payload must never INFLATE the runner's capacity.
	hostile := model.Job{CPURequest: -4, MemoryRequest: -1024, DiskRequest: 1 << 20, PIDsRequest: -5,
		CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{
			"runtime": "container", "services": []any{map[string]any{"name": "db"}}}}}}
	extra, ok := legacyServiceEnvelopeCharge(hostile)
	if !ok {
		t.Fatal("hostile legacy payload was not charged conservatively")
	}
	if extra != (model.ResourceCapacity{Disk: 1 << 20}) {
		t.Fatalf("hostile charge = %+v, want only the positive disk dimension", extra)
	}
}

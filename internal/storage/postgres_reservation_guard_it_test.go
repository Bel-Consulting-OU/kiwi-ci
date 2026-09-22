package storage

// Real-PostgreSQL integration tests for the magnitude-safe, non-negative
// reservation guards (K6-A) and the legacy services-without-envelope policy
// (K6-C) of the leader-promotion reconciliation. Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
// K6-A defect: the reconcile's numeric reads were guarded only by a
// character-class regex, so `cpu_request: 1e999` (a cast overflow), an
// over-long digit string, or a negative value passed the guard and then
// RAISED on the cast. The raise aborted the reconcile transaction, the
// promotion gate never armed, and every lease poll fleet-wide answered 503
// until that job's lease ended. The guard must now reject out-of-range and
// negative values into the 0 default without raising, exactly as the Go
// formula's per-field decode default does.
//
// K6-C defect: old-enqueued jobs declare services with no
// service_envelope_request field, so a promoted leader reconstructed a zero
// envelope and could oversubscribe. Such a payload must instead be charged
// conservatively (the job's own request as the envelope).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITSetPayloadNumber replaces one payload key with a raw JSON number
// literal, simulating a payload written by a different (or corrupt) control
// plane.
func pgITSetPayloadNumber(t *testing.T, st *PostgresStore, jobID, key, literal string) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `UPDATE jobs SET payload = jsonb_set(payload, ARRAY[$2], $3::jsonb) WHERE id=$1`, jobID, key, literal); err != nil {
		t.Fatalf("set payload %s=%s on %s: %v", key, literal, jobID, err)
	}
}

// TestIntegrationResourceReconcileHostileRequestValuesPostgres (K6-A): a
// running job whose payload carries an out-of-range CPU value, an over-long
// memory/disk/pid value and negative dimensions reconciles without error —
// each unrepresentable or negative dimension contributes ZERO while the
// valid dimensions of the same job are still charged exactly — and lease
// issuance continues afterwards (the pass that used to wedge the fleet now
// arms the gate).
func TestIntegrationResourceReconcileHostileRequestValuesPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-guard-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8,
		model.ResourceCapacity{CPU: 4, Memory: 8 << 30, Disk: 100 << 30, PIDs: 1000})

	runID := pgITNewID(t)
	hostile, negative, negativeDisk, queued := pgITNewID(t), pgITNewID(t), pgITNewID(t), pgITNewID(t)
	oneMiB := model.ResourceCapacity{Disk: 1 << 20}
	// baseline: the valid dimensions that must survive the guards.
	pgITResourceEnqueue(t, st, runID, hostile, pgITRepo, model.ResourceCapacity{Memory: 1024})
	if err := st.InsertJob(ctx, pgITResourceJob(runID, negative, pgITRepo, oneMiB)); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITResourceJob(runID, negativeDisk, pgITRepo, model.ResourceCapacity{Memory: 2048})); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITResourceJob(runID, queued, pgITRepo, model.ResourceCapacity{Memory: 1 << 30})); err != nil {
		t.Fatal(err)
	}
	// hostile: 1e999 CPU (postgres stores jsonb numbers as numeric, so this
	// is a 1000-digit value that overflows a double-precision cast), an
	// over-long disk digit string (overflows BIGINT) and an over-long pid
	// count (overflows INTEGER).
	pgITSetPayloadNumber(t, st, hostile, "cpu_request", "1e999")
	pgITSetPayloadNumber(t, st, hostile, "disk_request", "99999999999999999999999999999999999999999")
	pgITSetPayloadNumber(t, st, hostile, "pids_request", "123456789012345678901234567890")
	// negative: negative CPU/memory/pids (the old regex accepted the '-' and
	// charged a negative reservation that inflated the runner) plus a
	// negative disk in a separate job, each keeping the valid dimensions.
	pgITSetPayloadNumber(t, st, negative, "cpu_request", "-4")
	pgITSetPayloadNumber(t, st, negative, "memory_request", "-1024")
	pgITSetPayloadNumber(t, st, negative, "pids_request", "-5")
	pgITSetPayloadNumber(t, st, negativeDisk, "disk_request", "-1")

	// An old-version leader leased the hostile jobs after the migration: the
	// ledger is empty and their payloads are the only record of the request.
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, hostile, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, negative, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, negativeDisk, 1)
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile with hostile request values (the K6-A wedge): %v", err)
	}
	if res.Running != 3 || res.Upserted != 3 || res.Deleted != 0 {
		t.Fatalf("reconcile result = %+v, want running=3 upserted=3 deleted=0", res)
	}
	// Only the representable, non-negative dimensions are charged: hostile
	// keeps its valid 1024 bytes of memory, negative its 1 MiB disk,
	// negativeDisk its 2048 bytes of memory.
	want := model.ResourceCapacity{Memory: 1024 + 2048, Disk: 1 << 20}
	pgITAssertReservations(t, st, runnerID, want, 3)

	// Lease issuance continues: the queued 1 GiB job fits the remaining
	// capacity and is claimed with a reservation row of its own.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(queued, runnerID, model.ResourceCapacity{Memory: 1 << 30})); err != nil {
		t.Fatalf("lease after hostile reconcile: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.AddResourceCapacity(want, model.ResourceCapacity{Memory: 1 << 30}), 4)

	// The guards are stable across passes (idempotent, still no raise).
	res2, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if res2.Running != 4 || res2.Deleted != 0 {
		t.Fatalf("second reconcile = %+v, want running=4 deleted=0", res2)
	}
}

// TestIntegrationResourceReconcileLegacyServiceEnvelopePostgres (K6-C): a
// payload that declares a container service but carries no
// service_envelope_request field is charged its own request a second time as
// the envelope — a conservative upper bound instead of the zero envelope that
// would let a promoted leader oversubscribe — while a native job (whose
// declared services never start) and a modern payload with a persisted
// envelope keep their exact charges.
func TestIntegrationResourceReconcileLegacyServiceEnvelopePostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-legacy-env-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 16 << 30})

	runID := pgITNewID(t)
	legacyRun, nativeRun := pgITNewID(t), pgITNewID(t)
	legacySvc, nativeSvc, modern := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	waiter7, waiter6 := pgITNewID(t), pgITNewID(t)
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	twoGiB := model.ResourceCapacity{Memory: 2 << 30}
	oneGiB := model.ResourceCapacity{Memory: 1 << 30}
	sevenGiB := model.ResourceCapacity{Memory: 7 << 30}
	sixGiB := model.ResourceCapacity{Memory: 6 << 30}

	// legacySvc: own 3 GiB, runtime container, one declared service, no
	// envelope field (the pre-envelope enqueue shape: the OLD binary did not
	// know the key at all).
	pgITEnqueueDeclaredServicesJob(t, st, legacyRun, legacySvc, "container", threeGiB)
	pgITStripEnvelopeField(t, st, legacySvc)
	// nativeSvc: own 2 GiB, runtime native, declared services that never
	// start -> the pre-envelope charge is exactly its own request.
	pgITEnqueueDeclaredServicesJob(t, st, nativeRun, nativeSvc, "native", twoGiB)
	pgITStripEnvelopeField(t, st, nativeSvc)
	// modern: own 1 GiB with a persisted 1 GiB envelope.
	pgITEnqueueEnvelopeJob(t, st, runID, modern, oneGiB, oneGiB)

	pgITSimulateOldLeaderRunningJob(t, st, runnerID, legacySvc, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, nativeSvc, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, modern, 1)
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Running != 3 || res.Upserted != 3 || res.Deleted != 0 {
		t.Fatalf("reconcile result = %+v, want running=3 upserted=3 deleted=0", res)
	}
	// 2x3 GiB (legacy own+envelope) + 2 GiB (native own only) + 2 GiB
	// (modern own+envelope) = 10 GiB.
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 10 << 30}, 3)

	// The conservative charge holds the line: a 7 GiB job does not fit
	// (10+7 > 16) and waits, while a 6 GiB job fills the runner exactly.
	if err := st.InsertJob(ctx, pgITResourceJob(runID, waiter7, pgITRepo, sevenGiB)); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITResourceJob(runID, waiter6, pgITRepo, sixGiB)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(waiter7, runnerID, sevenGiB)); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("7 GiB claim on a runner charged 10 GiB of 16 GiB = %v, want ErrResourceCapacity", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(waiter6, runnerID, sixGiB)); err != nil {
		t.Fatalf("6 GiB claim on the remaining 6 GiB: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 16 << 30}, 4)

	// Idempotent: the legacy policy re-derives the same charges.
	res2, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if res2.Running != 4 || res2.Upserted != 4 || res2.Deleted != 0 {
		t.Fatalf("second reconcile = %+v, want running=4 upserted=4 deleted=0", res2)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 16 << 30}, 4)
}

// pgITEnqueueDeclaredServicesJob enqueues one run/job whose persisted
// compiled job declares a service container and whose runtime is runtime —
// without any service_envelope_request field, the pre-envelope payload shape.
func pgITEnqueueDeclaredServicesJob(t *testing.T, st *PostgresStore, runID, jobID, runtime string, own model.ResourceCapacity) {
	t.Helper()
	j := pgITResourceJob(runID, jobID, pgITRepo, own)
	j.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: map[string]any{
		"job": map[string]any{
			"runtime":  runtime,
			"services": []any{map[string]any{"name": "db", "image": "postgres:16"}},
		},
	}}
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: j},
	}
	if err := st.InsertCompiledRun(context.Background(), req); err != nil {
		t.Fatalf("enqueue declared-services job %s: %v", jobID, err)
	}
}

// TestIntegrationResourceReconcileHostileEnvelopeValuesPostgres (K6-A,
// envelope half): a corrupt envelope value cannot wedge the pass either — the
// same guards apply to service_envelope_request.cpu/memory/pids, so a hostile
// or negative envelope contributes zero while the job's own request is still
// charged.
func TestIntegrationResourceReconcileHostileEnvelopeValuesPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-hostile-env-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})

	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueEnvelopeJob(t, st, runID, jobID, model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 64}, model.ResourceCapacity{CPU: 1, Memory: 1 << 30, PIDs: 32})
	for key, literal := range map[string]string{
		"{service_envelope_request,cpu}":    "1e999",
		"{service_envelope_request,memory}": "99999999999999999999999999999999999999999",
		"{service_envelope_request,pids}":   "-32",
	} {
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, $2::text[], $3::jsonb) WHERE id=$1`, jobID, key, literal); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, jobID, 1)

	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile with a hostile envelope: %v", err)
	}
	if res.Running != 1 || res.Upserted != 1 {
		t.Fatalf("reconcile result = %+v, want running=1 upserted=1", res)
	}
	// Only the job's own request survives: every envelope dimension is
	// unrepresentable or negative.
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 64}, 1)
}

// pgITStripEnvelopeField removes the service_envelope_request key from a
// persisted payload, the shape an OLD (pre-envelope) binary wrote: its
// CompiledJobPayload knows nothing of the field, whereas the current
// binary's payload always carries the key (encoding/json's omitempty does not
// drop a struct).
func pgITStripEnvelopeField(t *testing.T, st *PostgresStore, jobID string) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `UPDATE jobs SET payload = payload - 'service_envelope_request' WHERE id=$1`, jobID); err != nil {
		t.Fatalf("strip envelope field on %s: %v", jobID, err)
	}
}

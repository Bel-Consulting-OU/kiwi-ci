package storage

// Real-PostgreSQL integration tests for exactly-once usage accounting. They
// follow the package convention: gated on KIWI_TEST_POSTGRES_URL through
// pgITStore/pgITDSN (skipped when unset and in -short mode) and every test
// owns a throwaway schema that is dropped on cleanup.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRecordUsageOnceIntegrationSequential proves the conditional UPDATE is
// the arbiter: the first record wins and persists the amounts, the replay
// reports false and leaves the payload untouched, and an unknown job records
// nothing.
func TestRecordUsageOnceIntegrationSequential(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	const cost, energy = 1.25, 250.5
	won, err := st.RecordUsageOnce(ctx, jobID, cost, energy)
	if err != nil || !won {
		t.Fatalf("first RecordUsageOnce = %v, %v; want true, nil", won, err)
	}
	first, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob after first record: %v", err)
	}
	if !first.UsageRecorded || first.Cost != cost || first.EnergyWh != energy {
		t.Fatalf("job after first record = %+v, want usage_recorded cost=%v energy=%v", first, cost, energy)
	}

	// A replay loses and must not move the stored amounts.
	won, err = st.RecordUsageOnce(ctx, jobID, 99, 99)
	if err != nil || won {
		t.Fatalf("replay RecordUsageOnce = %v, %v; want false, nil", won, err)
	}
	second, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob after replay: %v", err)
	}
	if second.UsageRecorded != first.UsageRecorded || second.Cost != first.Cost || second.EnergyWh != first.EnergyWh {
		t.Fatalf("job after replay = %+v, want payload unchanged from %+v", second, first)
	}

	// An unknown job records nothing and is not an error.
	if won, err := st.RecordUsageOnce(ctx, pgITNewID(t), 1, 1); err != nil || won {
		t.Fatalf("unknown job RecordUsageOnce = %v, %v; want false, nil", won, err)
	}
}

// TestRecordUsageOnceIntegrationConcurrent races 8 callers for one job
// through the real conditional UPDATE: exactly one wins, the rest report
// false without error, and the persisted payload holds the winner's amounts.
func TestRecordUsageOnceIntegrationConcurrent(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	const callers = 8
	type outcome struct {
		cost, energy float64
		won          bool
		err          error
	}
	results := make(chan outcome, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cost := float64(i + 1)
			energy := cost * 10
			won, err := st.RecordUsageOnce(ctx, jobID, cost, energy)
			results <- outcome{cost: cost, energy: energy, won: won, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	var winners []outcome
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent RecordUsageOnce: %v", r.err)
		}
		if r.won {
			winners = append(winners, r)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("concurrent winners = %d, want exactly 1", len(winners))
	}
	win := winners[0]
	got, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob after race: %v", err)
	}
	if !got.UsageRecorded || got.Cost != win.cost || got.EnergyWh != win.energy {
		t.Fatalf("job after race = %+v, want winner cost=%v energy=%v recorded", got, win.cost, win.energy)
	}
}

// TestRecordUsageOnceIntegrationPayloadAndUsageSum proves the stored payload
// fields match exactly and the store's RecentUsage sum counts the job's
// amounts once, even after a replayed record call.
func TestRecordUsageOnceIntegrationPayloadAndUsageSum(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	const cost, energy = 3.75, 420.25
	won, err := st.RecordUsageOnce(ctx, jobID, cost, energy)
	if err != nil || !won {
		t.Fatalf("RecordUsageOnce = %v, %v; want true, nil", won, err)
	}

	// Mark the job finished through the store API: RecentUsage sums jobs
	// finished since the cutoff, so a completed job is the realistic case.
	j, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	finished := time.Now().UTC()
	j.Status = model.StatusSuccess
	j.FinishedAt = &finished
	if err := st.UpdateJob(ctx, j); err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}

	got, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob after update: %v", err)
	}
	if !got.UsageRecorded || got.Cost != cost || got.EnergyWh != energy {
		t.Fatalf("payload fields = recorded=%v cost=%v energy=%v, want true/%v/%v", got.UsageRecorded, got.Cost, got.EnergyWh, cost, energy)
	}
	if got.FinishedAt == nil {
		t.Fatal("finished_at was not persisted")
	}

	sumCost, sumEnergy, err := st.RecentUsage(ctx, finished.Add(-time.Minute))
	if err != nil {
		t.Fatalf("RecentUsage: %v", err)
	}
	if sumCost != cost || sumEnergy != energy {
		t.Fatalf("RecentUsage = %v/%v, want %v/%v (job counted once)", sumCost, sumEnergy, cost, energy)
	}

	// A replayed record call must not double-count in the sum.
	if won, err := st.RecordUsageOnce(ctx, jobID, 50, 50); err != nil || won {
		t.Fatalf("replay RecordUsageOnce = %v, %v; want false, nil", won, err)
	}
	sumCost, sumEnergy, err = st.RecentUsage(ctx, finished.Add(-time.Minute))
	if err != nil {
		t.Fatalf("RecentUsage after replay: %v", err)
	}
	if sumCost != cost || sumEnergy != energy {
		t.Fatalf("RecentUsage after replay = %v/%v, want %v/%v", sumCost, sumEnergy, cost, energy)
	}
}

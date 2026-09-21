package storage

// Real-PostgreSQL integration tests for resource-capacity admission and the
// per-lease reservation ledger (migration 0030). Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const pgITResourceSerial = "cert-resource-serial"

// pgITResourceProfileRunner seeds a profile carrying both a job-count
// capacity and resource capacities, binds it to a certificate serial and
// registers a runner with that serial. The live profile is what the claim
// resolves, so a profile edit takes effect immediately.
func pgITResourceProfileRunner(t *testing.T, st *PostgresStore, runnerID, profileID string, countCapacity int, capacity model.ResourceCapacity) {
	t.Helper()
	if err := st.UpsertProfile(context.Background(), model.RunnerProfile{
		ID: profileID, MaxCapacity: countCapacity,
		MaxCPU: capacity.CPU, MaxMemory: capacity.Memory, MaxDisk: capacity.Disk, MaxPIDs: capacity.PIDs,
	}); err != nil {
		t.Fatalf("upsert resource profile: %v", err)
	}
	if err := st.BindCertProfile(context.Background(), pgITResourceSerial, profileID); err != nil {
		t.Fatalf("bind profile: %v", err)
	}
	if err := st.UpsertRunner(context.Background(), model.Runner{ID: runnerID, Name: runnerID, Capacity: countCapacity, CertSerial: pgITResourceSerial}); err != nil {
		t.Fatalf("register runner: %v", err)
	}
}

// pgITResourceJob builds a queued job carrying the given requests.
func pgITResourceJob(runID, jobID, repo string, request model.ResourceCapacity) model.Job {
	j := pgITJob(runID, jobID, repo)
	j.CPURequest, j.MemoryRequest, j.DiskRequest, j.PIDsRequest = request.CPU, request.Memory, request.Disk, request.PIDs
	return j
}

// pgITResourceClaim builds the atomic claim for one requested job.
func pgITResourceClaim(jobID, runnerID string, request model.ResourceCapacity) LeaseClaim {
	return LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		Runtime:    "container",
		CPURequest: request.CPU, MemoryRequest: request.Memory, DiskRequest: request.Disk, PIDsRequest: request.PIDs,
	}
}

// pgITResourceEnqueue enqueues one run with one resource-requesting job.
func pgITResourceEnqueue(t *testing.T, st *PostgresStore, runID, jobID, repo string, request model.ResourceCapacity) {
	t.Helper()
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: pgITResourceJob(runID, jobID, repo, request)},
	}
	if err := st.InsertCompiledRun(context.Background(), req); err != nil {
		t.Fatalf("enqueue %s/%s: %v", runID, jobID, err)
	}
}

// pgITAssertReservations asserts the runner's reservation sum and ledger.
func pgITAssertReservations(t *testing.T, st *PostgresStore, runnerID string, want model.ResourceCapacity, wantRows int) {
	t.Helper()
	got, err := st.RunnerReservedResources(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("reserved resources: %v", err)
	}
	if got != want {
		t.Fatalf("reserved = %+v, want %+v", got, want)
	}
	list, err := st.ListResourceReservations(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("list reservations: %v", err)
	}
	if len(list) != wantRows {
		t.Fatalf("ledger rows = %d, want %d (%+v)", len(list), wantRows, list)
	}
}

// TestIntegrationResourceAdmissionOversubscriptionPostgres (D2-B): a runner
// with an 8 GiB memory capacity cannot lease two 5 GiB jobs. The second
// claim is rejected with ErrResourceCapacity inside the claim transaction
// (nothing persisted, job stays queued); completion of the first frees the
// capacity and the second is then leased.
func TestIntegrationResourceAdmissionOversubscriptionPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-prof-"+pgITRandomHex(t, 6)
	runID, job1, job2 := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	pgITResourceEnqueue(t, st, runID, job1, pgITRepo, fiveGiB)
	if err := st.InsertJob(ctx, pgITResourceJob(runID, job2, pgITRepo, fiveGiB)); err != nil {
		t.Fatalf("insert second job: %v", err)
	}

	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(job1, runnerID, fiveGiB)); err != nil {
		t.Fatalf("first lease: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, fiveGiB, 1)

	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(job2, runnerID, fiveGiB)); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("second lease error = %v, want ErrResourceCapacity", err)
	}
	j, err := st.GetJob(ctx, job2)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusQueued || j.Attempts != 0 {
		t.Fatalf("rejected job = %s/attempts %d, want queued/0", j.Status, j.Attempts)
	}
	pgITAssertReservations(t, st, runnerID, fiveGiB, 1)

	receipt := model.CompletionReceipt{JobID: job1, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, job1, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete first: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(job2, runnerID, fiveGiB)); err != nil {
		t.Fatalf("second lease after completion: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, fiveGiB, 1)
}

// TestIntegrationResourceAdmissionCapacityLessRunnerPostgres (D2-B): a
// runner without configured resource capacities keeps the pre-0030
// count-only behavior.
func TestIntegrationResourceAdmissionCapacityLessRunnerPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, runID := pgITNewID(t), pgITNewID(t)
	job1, job2 := pgITNewID(t), pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 3, 0, 0)
	huge := model.ResourceCapacity{CPU: 128, Memory: 512 << 30, Disk: 1 << 40, PIDs: 100000}
	pgITResourceEnqueue(t, st, runID, job1, pgITRepo, huge)
	if err := st.InsertJob(ctx, pgITResourceJob(runID, job2, pgITRepo, huge)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{job1, job2} {
		if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(id, runnerID, huge)); err != nil {
			t.Fatalf("capacity-less runner lease %s: %v", id, err)
		}
	}
	want := model.ResourceCapacity{CPU: 256, Memory: 1024 << 30, Disk: 2 << 40, PIDs: 200000}
	pgITAssertReservations(t, st, runnerID, want, 2)
}

// TestIntegrationResourceReservationReleaseLifecyclePostgres (D2-B): every
// lease-ending path releases the reservation exactly once — completion,
// cancellation, lease recovery (requeue and terminal), runner revocation,
// runner disable, supersession, legacy release and queue-timeout expiry —
// with replayed releases leaving the ledger empty (no leak, no double
// release). A raw count query pins the table contents, not only the sums.
func TestIntegrationResourceReservationReleaseLifecyclePostgres(t *testing.T) {
	request := model.ResourceCapacity{CPU: 2, Memory: 2 << 30, Disk: 3 << 30, PIDs: 100}
	capacity := model.ResourceCapacity{CPU: 4, Memory: 4 << 30, Disk: 6 << 30, PIDs: 200}

	// pgITLifecycleEnvGroup prepares a migrated, fence-armed store with one
	// profile-linked runner and one leased resource job. group, when set,
	// stamps the job's run so a superseding enqueue can match it.
	pgITLifecycleEnvGroup := func(t *testing.T, group string) (*PostgresStore, string, string) {
		t.Helper()
		st := pgITStore(t)
		runnerID, profileID := pgITNewID(t), "res-life-"+pgITRandomHex(t, 6)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITResourceProfileRunner(t, st, runnerID, profileID, 8, capacity)
		req := InsertCompiledRunRequest{
			Run:  model.Run{ID: runID, Repo: pgITRepo, ConcurrencyGroup: group, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			Jobs: map[string]model.Job{jobID: pgITResourceJob(runID, jobID, pgITRepo, request)},
		}
		if err := st.InsertCompiledRun(context.Background(), req); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := st.AcquireLeaseAtomic(context.Background(), pgITResourceClaim(jobID, runnerID, request)); err != nil {
			t.Fatalf("lease: %v", err)
		}
		pgITAssertReservations(t, st, runnerID, request, 1)
		return st, runnerID, jobID
	}
	pgITLifecycleEnv := func(t *testing.T) (*PostgresStore, string, string) {
		t.Helper()
		return pgITLifecycleEnvGroup(t, "")
	}
	assertZero := func(t *testing.T, st *PostgresStore, runnerID string) {
		t.Helper()
		pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)
		var rows int
		if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM job_resource_reservations`).Scan(&rows); err != nil {
			t.Fatalf("count reservations: %v", err)
		}
		if rows != 0 {
			t.Fatalf("reservation table holds %d rows, want 0", rows)
		}
	}

	t.Run("completion", func(t *testing.T) {
		st, runnerID, jobID := pgITLifecycleEnv(t)
		receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}
		if err := st.CompleteJob(context.Background(), jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
			t.Fatal(err)
		}
		assertZero(t, st, runnerID)
		if err := st.CompleteJob(context.Background(), jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
			t.Fatalf("replayed completion: %v", err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("failure completion", func(t *testing.T) {
		st, runnerID, jobID := pgITLifecycleEnv(t)
		receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}
		if err := st.CompleteJob(context.Background(), jobID, 1, runnerID, model.StatusFailure, "boom", nil, receipt); err != nil {
			t.Fatal(err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("run cancellation", func(t *testing.T) {
		st, runnerID, jobID := pgITLifecycleEnv(t)
		j, err := st.GetJob(context.Background(), jobID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.CancelRunJobs(context.Background(), j.RunID, "cancelled"); err != nil {
			t.Fatal(err)
		}
		assertZero(t, st, runnerID)
		if _, err := st.CancelRunJobs(context.Background(), j.RunID, "cancelled again"); err != nil {
			t.Fatalf("replayed cancellation: %v", err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("lease expiry", func(t *testing.T) {
		st, runnerID, jobID := pgITLifecycleEnv(t)
		if err := st.RecoverExpiredLease(context.Background(), jobID, 1, time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatalf("recover expired lease: %v", err)
		}
		assertZero(t, st, runnerID)
		if err := st.RecoverExpiredLease(context.Background(), jobID, 1, time.Now().UTC().Add(time.Hour)); err != nil {
			t.Fatalf("replayed recovery: %v", err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("runner revocation", func(t *testing.T) {
		st, runnerID, _ := pgITLifecycleEnv(t)
		revoked, err := st.RevokeRunnerLeases(context.Background(), runnerID, "runner disabled")
		if err != nil || len(revoked) != 1 {
			t.Fatalf("revoke = %v err=%v", revoked, err)
		}
		assertZero(t, st, runnerID)
		if _, err := st.RevokeRunnerLeases(context.Background(), runnerID, "runner disabled again"); err != nil {
			t.Fatalf("replayed revoke: %v", err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("runner disable and revoke cert", func(t *testing.T) {
		st, runnerID, _ := pgITLifecycleEnv(t)
		if _, err := st.DisableRunnerAndRevokeCert(context.Background(), runnerID, pgITResourceSerial, "admin"); err != nil {
			t.Fatal(err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("legacy release runner job", func(t *testing.T) {
		st, runnerID, jobID := pgITLifecycleEnv(t)
		if err := st.ReleaseRunnerJob(context.Background(), runnerID, jobID, model.StatusFailure); err != nil {
			t.Fatal(err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("supersession", func(t *testing.T) {
		st, runnerID, _ := pgITLifecycleEnvGroup(t, "res-grp")
		newRun, newJob := pgITNewID(t), pgITNewID(t)
		req := InsertCompiledRunRequest{
			Run:       model.Run{ID: newRun, Repo: pgITRepo, ConcurrencyGroup: "res-grp", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			Jobs:      map[string]model.Job{newJob: pgITResourceJob(newRun, newJob, pgITRepo, request)},
			Supersede: &SupersedePolicy{RepoID: pgITRepoID, ConcurrencyGroup: "res-grp"},
		}
		if err := st.InsertCompiledRun(context.Background(), req); err != nil {
			t.Fatalf("superseding enqueue: %v", err)
		}
		assertZero(t, st, runnerID)
	})

	t.Run("queue timeout", func(t *testing.T) {
		st := pgITStore(t)
		runnerID, profileID := pgITNewID(t), "res-qto-"+pgITRandomHex(t, 6)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITResourceProfileRunner(t, st, runnerID, profileID, 8, capacity)
		pgITResourceEnqueue(t, st, runID, jobID, pgITRepo, request)
		deadline := time.Now().UTC().Add(-time.Minute)
		if _, err := st.pool.Exec(context.Background(), `UPDATE jobs SET queue_deadline=$2 WHERE id=$1`, jobID, deadline); err != nil {
			t.Fatal(err)
		}
		if err := st.ExpireQueuedJob(context.Background(), jobID, deadline); err != nil {
			t.Fatalf("expire queued job: %v", err)
		}
		assertZero(t, st, runnerID)
		if err := st.ExpireQueuedJob(context.Background(), jobID, deadline); err != nil {
			t.Fatalf("replayed expiry: %v", err)
		}
		assertZero(t, st, runnerID)
	})
}

// TestIntegrationResourceReservationConcurrentClaimsPostgres (D2-B): two
// replicas claiming concurrently over the same schema can never
// oversubscribe a runner's resource capacity. With an 8 GiB runner and four
// 3 GiB jobs, exactly two claims succeed (3+3 <= 8 < 3+3+3) no matter how
// the goroutines interleave.
func TestIntegrationResourceReservationConcurrentClaimsPostgres(t *testing.T) {
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	pgITArmFence(t, stA)
	stB := env.open(t)
	pgITArmFence(t, stB)

	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-race-"+pgITRandomHex(t, 6)
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	pgITResourceProfileRunner(t, stA, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID := pgITNewID(t)
	jobIDs := make([]string, 4)
	for i := range jobIDs {
		jobIDs[i] = pgITNewID(t)
		if i == 0 {
			pgITResourceEnqueue(t, stA, runID, jobIDs[i], pgITRepo, threeGiB)
			continue
		}
		if err := stA.InsertJob(ctx, pgITResourceJob(runID, jobIDs[i], pgITRepo, threeGiB)); err != nil {
			t.Fatal(err)
		}
	}

	stores := []*PostgresStore{stA, stB}
	var wg sync.WaitGroup
	var mu sync.Mutex
	leases := 0
	for _, st := range stores {
		for _, jobID := range jobIDs {
			wg.Add(1)
			go func(st *PostgresStore, jobID string) {
				defer wg.Done()
				_, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(jobID, runnerID, threeGiB))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					leases++
				case errors.Is(err, ErrResourceCapacity), errors.Is(err, ErrLeaseConflict), errors.Is(err, ErrNoCapacity):
				default:
					t.Errorf("unexpected concurrent claim error: %v", err)
				}
			}(st, jobID)
		}
	}
	wg.Wait()
	if leases != 2 {
		t.Fatalf("concurrent claims leased %d jobs, want exactly 2 (6 GiB of an 8 GiB runner)", leases)
	}
	pgITAssertReservations(t, stA, runnerID, model.ResourceCapacity{Memory: 6 << 30}, 2)
	// The runner's count capacity (8) is untouched: exactly two slots used.
	ri, err := stA.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ri.ActiveJobs) != 2 {
		t.Fatalf("runner active jobs = %d, want 2", len(ri.ActiveJobs))
	}
}

// TestIntegrationResourceCapacityProfileRoundTripPostgres (D2-B): the four
// capacity columns persist and round-trip through the profile APIs (Get,
// List, ProfileForSerial); a profile that never sets them reads back as
// unconstrained zeros (the documented default), and the migration that adds
// them is applied.
func TestIntegrationResourceCapacityProfileRoundTripPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	profileID, serial := "res-cap-"+pgITRandomHex(t, 6), "cert-cap-"+pgITRandomHex(t, 6)
	want := model.RunnerProfile{
		ID: profileID, Labels: []string{"container"}, Region: "eu", Capabilities: []string{"container"},
		MaxCapacity: 4, MaxCPU: 16.5, MaxMemory: 64 << 30, MaxDisk: 128 << 30, MaxPIDs: 4096,
		CostPerHour: 1.25, PowerWatts: 42,
	}
	if err := st.UpsertProfile(ctx, want); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, serial, profileID); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetProfile(ctx, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxCPU != want.MaxCPU || got.MaxMemory != want.MaxMemory || got.MaxDisk != want.MaxDisk || got.MaxPIDs != want.MaxPIDs {
		t.Fatalf("profile capacities = %+v, want cpu=%v mem=%d disk=%d pids=%d", got, want.MaxCPU, want.MaxMemory, want.MaxDisk, want.MaxPIDs)
	}
	bySerial, found, err := st.ProfileForSerial(ctx, serial)
	if err != nil || !found {
		t.Fatalf("profile for serial: found=%v err=%v", found, err)
	}
	if bySerial.MaxCPU != want.MaxCPU || bySerial.MaxMemory != want.MaxMemory || bySerial.MaxDisk != want.MaxDisk || bySerial.MaxPIDs != want.MaxPIDs {
		t.Fatalf("serial profile capacities = %+v", bySerial)
	}
	listed, err := st.ListProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundListed := false
	for _, p := range listed {
		if p.ID == profileID {
			foundListed = true
			if p.MaxMemory != want.MaxMemory {
				t.Fatalf("listed profile memory = %d, want %d", p.MaxMemory, want.MaxMemory)
			}
		}
	}
	if !foundListed {
		t.Fatal("profile missing from ListProfiles")
	}
	// Unset capacities are unconstrained zeros.
	legacy := "res-legacy-" + pgITRandomHex(t, 6)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: legacy, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	gotLegacy, err := st.GetProfile(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if gotLegacy.MaxCPU != 0 || gotLegacy.MaxMemory != 0 || gotLegacy.MaxDisk != 0 || gotLegacy.MaxPIDs != 0 {
		t.Fatalf("legacy profile capacities = %+v, want all zero (unconstrained)", gotLegacy)
	}
	// The migration is applied and the columns exist.
	version, err := st.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version < 30 {
		t.Fatalf("schema version = %d, want >= 30", version)
	}
	var columns int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name='runner_profiles' AND column_name IN ('max_cpu','max_memory','max_disk','max_pids')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 4 {
		t.Fatalf("runner_profiles capacity columns = %d, want 4", columns)
	}
	var ledgerExists bool
	if err := st.pool.QueryRow(ctx, `SELECT to_regclass('job_resource_reservations') IS NOT NULL`).Scan(&ledgerExists); err != nil {
		t.Fatal(err)
	}
	if !ledgerExists {
		t.Fatal("job_resource_reservations table missing after migration")
	}
}

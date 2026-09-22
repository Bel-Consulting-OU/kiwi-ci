package app

// Tests for the operator storage repair command. The unit cases run without a
// database; the repair pass itself is exercised against a throwaway real
// PostgreSQL database (skipped when KIWI_TEST_POSTGRES_URL is unset).

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestStorageReconcileReservationsFlagErrors(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	if err := storageReconcileReservations(ctx, nil, &out); err == nil || !strings.Contains(err.Error(), "--database-url is required") {
		t.Fatalf("no URL = %v", err)
	}
	if err := storageReconcileReservations(ctx, []string{"--database-url", "postgres://127.0.0.1:1/none"}, &out); err == nil {
		t.Fatal("unreachable database URL must fail the repair command")
	}
	if err := storageReconcileReservations(ctx, []string{"--database-url", "postgres://127.0.0.1:1/none", "extra"}, &out); err == nil || !strings.Contains(err.Error(), "takes no arguments") {
		t.Fatalf("positional argument = %v", err)
	}
}

// TestStorageReconcileReservationsRepairsLedger drives the operator command
// end to end against real PostgreSQL: a job that an OLD replica completed
// (finished row, cleared lease) but whose reservation row survived is swept,
// a running job that an OLD leader leased without a row is charged, and the
// command reports the operator-facing counters.
func TestStorageReconcileReservationsRepairsLedger(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	ctx := context.Background()
	st, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// The command adopts the durable epoch; the test seeds it the same way an
	// operator's store would read it.
	runnerID, profileID := pgID("runner"), pgID("profile")
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 8, MaxMemory: 8 << 30}); err != nil {
		t.Fatal(err)
	}
	if err := st.BindCertProfile(ctx, "repair-serial", profileID); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8, CertSerial: "repair-serial"}); err != nil {
		t.Fatal(err)
	}
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	runID := pgID("run")
	liveJob, leakedJob, queuedJob := pgID("live"), pgID("leaked"), pgID("queued")
	jobs := map[string]model.Job{
		liveJob:   {ID: liveJob, RunID: runID, Key: "live", RepoURL: pgRepo, Status: model.StatusRunning, MemoryRequest: fiveGiB.Memory, LeaseRunnerID: runnerID, LeaseGeneration: 1, CreatedAt: time.Now().UTC()},
		leakedJob: {ID: leakedJob, RunID: runID, Key: "leaked", RepoURL: pgRepo, Status: model.StatusSuccess, MemoryRequest: 2 << 30, CreatedAt: time.Now().UTC()},
		queuedJob: {ID: queuedJob, RunID: runID, Key: "queued", RepoURL: pgRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
	}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: jobs,
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	// An old replica's completion left the ledger row behind, and the old
	// leader's lease left no row for the live job. The orphan row is planted
	// with a direct connection (the leak is precisely the state the store API
	// never produces).
	if err := st.Close(); err != nil {
		t.Fatalf("close seeding store: %v", err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for the orphan row: %v", err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1,$2,1,0,$3,0,0)`, leakedJob, runnerID, 2<<30); err != nil {
		t.Fatalf("plant leaked row: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatalf("close orphan-row connection: %v", err)
	}

	var out bytes.Buffer
	if err := storageReconcileReservations(ctx, []string{"--database-url", dsn}, &out); err != nil {
		t.Fatalf("repair command: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "resource reservations reconciled: running=1 upserted=1 deleted=1") {
		t.Fatalf("repair report = %q", got)
	}

	st2, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	reserved, err := st2.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved != fiveGiB {
		t.Fatalf("reserved after repair = %+v, want the live job's 5 GiB only", reserved)
	}
	list, err := st2.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].JobID != liveJob || list[0].Generation != 1 {
		t.Fatalf("ledger after repair = %+v, want exactly the live job", list)
	}
}

const pgRepo = "https://github.com/kiwi-it/repair.git"

// pgID builds a valid 32-hex identifier for the seeded rows.
func pgID(label string) string {
	return fmt.Sprintf("%032x", []byte(label))
}

package storage

// Round-trip integration tests for the PostgresStore surface: every method
// is driven once against a real PostgreSQL schema, so the SQL, the scanners
// and the validation helpers execute end to end. Error branches use the
// closed-pool and invalid-input paths that need no fault injection.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

func pgITRun(runID string, status model.Status) model.Run {
	return model.Run{ID: runID, Repo: pgITRepo, RepoFullName: "kiwi-it/repo", RepoID: pgITRepoID, Status: status, CreatedAt: time.Now().UTC()}
}

func TestPostgresNewStoreOptions(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// WithMaxConnections applies positive values and ignores non-positive.
	withCap, err := NewPostgresOpt(context.Background(), dsn, WithMaxConnections(3))
	if err != nil {
		t.Fatalf("NewPostgresOpt: %v", err)
	}
	if withCap.pool.Config().MaxConns != 3 {
		t.Fatalf("MaxConns = %d, want 3", withCap.pool.Config().MaxConns)
	}
	_ = withCap.Close()
	noCap, err := NewPostgresOpt(context.Background(), dsn, WithMaxConnections(0))
	if err != nil {
		t.Fatalf("NewPostgresOpt zero: %v", err)
	}
	if noCap.pool.Config().MaxConns == 0 {
		t.Fatal("non-positive max connections must keep the pool default")
	}
	_ = noCap.Close()
	// A malformed DSN fails at parse time.
	if _, err := NewPostgres(context.Background(), ":::not-a-dsn:::"); err == nil {
		t.Fatal("malformed DSN must fail")
	}
	// An unreachable server fails at ping time.
	if _, err := NewPostgres(context.Background(), "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("unreachable server must fail to ping")
	}
}

func TestPostgresIntegrationRunsRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)

	if err := st.InsertRun(ctx, pgITRun(runID, model.StatusQueued)); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := st.InsertRun(ctx, pgITRun(runID, model.StatusQueued)); err == nil {
		t.Fatal("duplicate run must fail")
	}
	if err := st.InsertRun(ctx, model.Run{ID: "not-an-id"}); err == nil {
		t.Fatal("invalid run id must fail")
	}
	got, err := st.GetRun(ctx, runID)
	if err != nil || got.ID != runID || got.Status != model.StatusQueued {
		t.Fatalf("GetRun = %+v, %v", got, err)
	}
	if _, err := st.GetRun(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run = %v, want ErrNotFound", err)
	}
	if _, err := st.GetRun(ctx, "bad"); err == nil {
		t.Fatal("invalid run id must fail")
	}

	started := time.Now().UTC().Truncate(time.Microsecond)
	finished := started.Add(time.Second)
	if err := st.UpdateRunStatus(ctx, runID, model.StatusSuccess, &started, &finished); err != nil {
		t.Fatalf("UpdateRunStatus: %v", err)
	}
	got, _ = st.GetRun(ctx, runID)
	if got.Status != model.StatusSuccess || got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("run after update = %+v", got)
	}
	// Nil times preserve the stored columns.
	if err := st.UpdateRunStatus(ctx, runID, model.StatusFailure, nil, nil); err != nil {
		t.Fatalf("UpdateRunStatus nil times: %v", err)
	}
	got, _ = st.GetRun(ctx, runID)
	if got.Status != model.StatusFailure || got.StartedAt == nil {
		t.Fatalf("nil times must preserve start: %+v", got)
	}
	if err := st.UpdateRunStatus(ctx, "ffffffffffffffffffffffffffffffff", model.StatusSuccess, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run status = %v", err)
	}
	if err := st.UpdateRunStatus(ctx, "bad", model.StatusSuccess, nil, nil); err == nil {
		t.Fatal("invalid run id must fail")
	}

	runs, err := st.ListRuns(ctx, 0)
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns default = %v, %v", runs, err)
	}
	if runs, err = st.ListRuns(ctx, -3); err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns negative = %v, %v", runs, err)
	}
	if runs, err = st.ListRuns(ctx, 10001); err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns overflow = %v, %v", runs, err)
	}
	if runs, err = st.ListRuns(ctx, 1); err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns limit = %v, %v", runs, err)
	}
}

func TestPostgresIntegrationJobsRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	childID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	if err := st.InsertJob(ctx, pgITJob(runID, jobID, pgITRepo)); err == nil {
		t.Fatal("duplicate job must fail")
	}
	if err := st.InsertJob(ctx, model.Job{ID: "bad", RunID: runID}); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := st.InsertJob(ctx, model.Job{ID: pgITNewID(t), RunID: "bad"}); err == nil {
		t.Fatal("invalid run id must fail")
	}

	got, err := st.GetJob(ctx, jobID)
	if err != nil || got.ID != jobID || got.Key != "build" {
		t.Fatalf("GetJob = %+v, %v", got, err)
	}
	if _, err := st.GetJob(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job = %v", err)
	}
	if _, err := st.GetJob(ctx, "bad"); err == nil {
		t.Fatal("invalid job id must fail")
	}
	jobs, err := st.ListJobsByRun(ctx, runID)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListJobsByRun = %v, %v", jobs, err)
	}
	if _, err := st.ListJobsByRun(ctx, "bad"); err == nil {
		t.Fatal("invalid run id must fail")
	}
	queued, err := st.ListQueuedJobs(ctx)
	if err != nil || len(queued) != 1 {
		t.Fatalf("ListQueuedJobs = %v, %v", queued, err)
	}

	// Environment listing reads the payload fields.
	envJob := pgITJob(runID, childID, pgITRepo)
	envJob.Environment = "prod"
	if err := st.InsertJob(ctx, envJob); err != nil {
		t.Fatalf("insert env job: %v", err)
	}
	byEnv, err := st.ListJobsByEnvironment(ctx, pgITRepoID, "prod")
	if err != nil || len(byEnv) != 1 || byEnv[0].ID != childID {
		t.Fatalf("ListJobsByEnvironment = %v, %v", byEnv, err)
	}
	if byEnv, err = st.ListJobsByEnvironment(ctx, pgITRepoID, "missing"); err != nil || len(byEnv) != 0 {
		t.Fatalf("ListJobsByEnvironment missing = %v, %v", byEnv, err)
	}

	// The runner list observes only running jobs with the matching lease.
	if byRunner, err := st.ListJobsByRunner(ctx, pgITNewID(t)); err != nil || len(byRunner) != 0 {
		t.Fatalf("ListJobsByRunner empty = %v, %v", byRunner, err)
	}
	if _, err := st.ListJobsByRunner(ctx, "bad"); err == nil {
		t.Fatal("invalid runner id must fail")
	}

	// UpdateJob upserts and rewrites dependency edges.
	envJob.Status = model.StatusRunning
	envJob.LeaseRunnerID = pgITNewID(t)
	envJob.Attempts = 2
	envJob.Outputs = map[string]string{"k": "v"}
	envJob.Needs = []string{jobID}
	if err := st.UpdateJob(ctx, envJob); err != nil {
		t.Fatalf("UpdateJob: %v", err)
	}
	got, _ = st.GetJob(ctx, childID)
	if got.Status != model.StatusRunning || got.Attempts != 2 || got.Outputs["k"] != "v" || len(got.Needs) != 1 {
		t.Fatalf("job after update = %+v", got)
	}
	byRunner, err := st.ListJobsByRunner(ctx, envJob.LeaseRunnerID)
	if err != nil || len(byRunner) != 1 {
		t.Fatalf("ListJobsByRunner = %v, %v", byRunner, err)
	}
	if err := st.UpdateJob(ctx, model.Job{ID: "bad", RunID: runID}); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := st.UpdateJob(ctx, model.Job{ID: pgITNewID(t), RunID: "bad"}); err == nil {
		t.Fatal("invalid run id must fail")
	}
}

func TestPostgresIntegrationPlainLeaseRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	if _, err := st.AcquireLease(ctx, "bad", pgITNewID(t), nil, 1, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if _, err := st.AcquireLease(ctx, jobID, "", nil, 1, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("empty runner id must fail")
	}
	if _, err := st.AcquireLease(ctx, "ffffffffffffffffffffffffffffffff", pgITNewID(t), nil, 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("missing job lease = %v, want ErrLeaseConflict", err)
	}
	runnerID := pgITNewID(t)
	expires := time.Now().UTC().Add(time.Minute)
	leased, err := st.AcquireLease(ctx, jobID, runnerID, []byte("tok"), 1, expires)
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if leased.Status != model.StatusRunning || leased.Attempts != 1 || leased.StartedAt == nil {
		t.Fatalf("leased job = %+v", leased)
	}
	if _, err := st.AcquireLease(ctx, jobID, runnerID, nil, 2, expires); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("re-lease = %v, want ErrLeaseConflict", err)
	}

	if err := st.HeartbeatLease(ctx, "bad", runnerID, 1, expires); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := st.HeartbeatLease(ctx, "ffffffffffffffffffffffffffffffff", runnerID, 1, expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("heartbeat missing = %v", err)
	}
	if err := st.HeartbeatLease(ctx, jobID, pgITNewID(t), 1, expires); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("heartbeat wrong runner = %v", err)
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 9, expires); !errors.Is(err, ErrGenerationMismatch) {
		t.Fatalf("heartbeat wrong generation = %v", err)
	}
	later := expires.Add(time.Minute)
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 1, later); err != nil {
		t.Fatalf("HeartbeatLease: %v", err)
	}
	got, _ := st.GetJob(ctx, jobID)
	if got.LeaseExpiresAt == nil || !got.LeaseExpiresAt.Equal(later.Truncate(time.Microsecond)) {
		t.Fatalf("heartbeat expiry = %v", got.LeaseExpiresAt)
	}
}

func TestPostgresIntegrationRunnersRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	jobID := pgITNewID(t)
	runID := pgITNewID(t)

	if _, err := st.GetRunner(ctx, runnerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing runner = %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r1", Capacity: 2, Labels: []string{"linux"}, CostPerHour: 1.5, PowerWatts: 20, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("UpsertRunner: %v", err)
	}
	got, err := st.GetRunner(ctx, runnerID)
	if err != nil || got.Capacity != 2 || got.CostPerHour != 1.5 || len(got.ActiveJobs) != 0 {
		t.Fatalf("GetRunner = %+v, %v", got, err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r2", Capacity: 5, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("UpsertRunner update: %v", err)
	}
	got, _ = st.GetRunner(ctx, runnerID)
	if got.Name != "r2" || got.Capacity != 5 {
		t.Fatalf("runner after update = %+v", got)
	}
	runners, err := st.ListRunners(ctx)
	if err != nil || len(runners) != 1 {
		t.Fatalf("ListRunners = %v, %v", runners, err)
	}

	// ReleaseRunnerJob moves counters and clears the slot.
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 2, ActiveJobs: []string{jobID}, CurrentJob: jobID, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("seed active runner: %v", err)
	}
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); err != nil {
		t.Fatalf("ReleaseRunnerJob: %v", err)
	}
	got, _ = st.GetRunner(ctx, runnerID)
	if got.CurrentJob != "" || len(got.ActiveJobs) != 0 || got.Failed != 1 || got.Busy {
		t.Fatalf("runner after release = %+v", got)
	}
	// A deregistered runner reports ErrNotFound after releasing the job's
	// repository-scoped quota slot.
	if err := st.ReleaseRunnerJob(ctx, "ffffffffffffffffffffffffffffffff", jobID, model.StatusSuccess); !errors.Is(err, ErrNotFound) {
		t.Fatalf("release on missing runner = %v, want ErrNotFound", err)
	}
}

func TestPostgresIntegrationArtifactsRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", Name: "bin", Path: "/tmp/bin", Size: 5, SHA256: "abc", LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	if err := st.InsertArtifact(ctx, art); err != nil {
		t.Fatalf("InsertArtifact: %v", err)
	}
	if err := st.InsertArtifact(ctx, art); err == nil {
		t.Fatal("duplicate artifact id must fail")
	}
	arts, err := st.ListArtifacts(ctx, runID)
	if err != nil || len(arts) != 1 || arts[0].SHA256 != "abc" {
		t.Fatalf("ListArtifacts = %+v, %v", arts, err)
	}
	if arts, err = st.ListArtifacts(ctx, pgITNewID(t)); err != nil || len(arts) != 0 {
		t.Fatalf("ListArtifacts other = %+v, %v", arts, err)
	}
	got, err := st.GetArtifact(ctx, art.ID)
	if err != nil || got.ID != art.ID {
		t.Fatalf("GetArtifact = %+v, %v", got, err)
	}
	if _, err := st.GetArtifact(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact = %v", err)
	}

	// Idempotent insert: same digest returns the stored row, a different
	// digest is a conflict.
	stored, created, err := st.InsertArtifactOnce(ctx, art)
	if err != nil || created || stored.ID != art.ID {
		t.Fatalf("InsertArtifactOnce replay = %+v, %v, %v", stored, created, err)
	}
	conflict := art
	conflict.SHA256 = "different"
	if _, _, err := st.InsertArtifactOnce(ctx, conflict); !errors.Is(err, ErrArtifactDigestConflict) {
		t.Fatalf("digest conflict = %v", err)
	}
	fresh := art
	fresh.ID = pgITNewID(t)
	fresh.Name = "other"
	stored, created, err = st.InsertArtifactOnce(ctx, fresh)
	if err != nil || !created || stored.ID != fresh.ID {
		t.Fatalf("InsertArtifactOnce fresh = %+v, %v, %v", stored, created, err)
	}
	// A jobless artifact key has no idempotency tuple and always inserts.
	noJob := art
	noJob.ID = pgITNewID(t)
	noJob.JobID = ""
	noJob.Name = "nojob"
	if _, created, err := st.InsertArtifactOnce(ctx, noJob); err != nil || !created {
		t.Fatalf("jobless artifact = %v, %v", created, err)
	}

	if err := st.SetArtifactSidecars(ctx, art.ID, "sbom.json", "s1", "sig.json", "s2"); err != nil {
		t.Fatalf("SetArtifactSidecars: %v", err)
	}
	got, _ = st.GetArtifact(ctx, art.ID)
	if got.SBOMPath != "sbom.json" || got.SBOMSHA256 != "s1" || got.SigstorePath != "sig.json" || got.SigstoreSHA256 != "s2" {
		t.Fatalf("sidecars = %+v", got)
	}
	// Empty values leave the stored references untouched.
	if err := st.SetArtifactSidecars(ctx, art.ID, "", "", "", ""); err != nil {
		t.Fatalf("SetArtifactSidecars empty: %v", err)
	}
	got, _ = st.GetArtifact(ctx, art.ID)
	if got.SBOMPath != "sbom.json" {
		t.Fatalf("empty sidecars clobbered stored values: %+v", got)
	}
	// A missing artifact id updates no row and is not an error.
	if err := st.SetArtifactSidecars(ctx, "ffffffffffffffffffffffffffffffff", "x", "", "", ""); err != nil {
		t.Fatalf("sidecars missing = %v", err)
	}
	if err := st.SetArtifactSidecars(ctx, "bad", "x", "", "", ""); err == nil {
		t.Fatal("invalid artifact id must fail")
	}
}

func TestPostgresIntegrationReportsLogsAuditRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	otherRun := pgITNewID(t)

	reports := []model.TestReport{
		{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", Path: "/tmp/r1", Tests: 3, CreatedAt: time.Now().UTC()},
		{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", Path: "/tmp/r2", Tests: 1, CreatedAt: time.Now().UTC()},
		{ID: pgITNewID(t), RunID: otherRun, JobID: jobID, JobKey: "build", Path: "/tmp/r3", Tests: 2, CreatedAt: time.Now().UTC()},
	}
	for _, rep := range reports {
		if err := st.InsertTestReport(ctx, rep); err != nil {
			t.Fatalf("InsertTestReport: %v", err)
		}
	}
	got, err := st.ListTestReports(ctx, runID)
	if err != nil || len(got) != 2 {
		t.Fatalf("ListTestReports = %v, %v", got, err)
	}
	if got, err = st.ListTestReports(ctx, pgITNewID(t)); err != nil || len(got) != 0 {
		t.Fatalf("ListTestReports empty = %v, %v", got, err)
	}
	all, err := st.ListTestReportsAll(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListTestReportsAll = %v, %v", all, err)
	}

	for i := int64(1); i <= 3; i++ {
		if err := st.AppendLog(ctx, model.LogEntry{Seq: i, RunID: runID, JobID: jobID, Line: fmt.Sprintf("line-%d", i), CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("AppendLog: %v", err)
		}
	}
	if err := st.AppendLog(ctx, model.LogEntry{Seq: 4, RunID: otherRun, Line: "other", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("AppendLog other: %v", err)
	}
	logs, err := st.ReadLogs(ctx, runID, 0, 0)
	if err != nil || len(logs) != 3 {
		t.Fatalf("ReadLogs = %v, %v", logs, err)
	}
	logs, err = st.ReadLogs(ctx, runID, 1, 10001)
	if err != nil || len(logs) != 2 || logs[0].Seq != 2 {
		t.Fatalf("ReadLogs after/limit = %v, %v", logs, err)
	}
	logs, err = st.ReadLogs(ctx, runID, 0, 1)
	if err != nil || len(logs) != 1 || logs[0].Seq != 1 {
		t.Fatalf("ReadLogs limit = %v, %v", logs, err)
	}
	if _, err := st.ReadLogs(ctx, "bad", 0, 1); err == nil {
		t.Fatal("invalid run id must fail")
	}

	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "test", Actor: "tester", RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	audit, err := st.ReadAudit(ctx, 10001)
	if err != nil || len(audit) != 3 {
		t.Fatalf("ReadAudit = %v, %v", audit, err)
	}
	audit, err = st.ReadAudit(ctx, 1)
	if err != nil || len(audit) != 1 {
		t.Fatalf("ReadAudit limit = %v, %v", audit, err)
	}
	audit, err = st.ReadAudit(ctx, 0)
	if err != nil || len(audit) != 3 {
		t.Fatalf("ReadAudit default = %v, %v", audit, err)
	}
}

func TestPostgresIntegrationReceiptsAndDeliveries(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)

	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash"}
	if err := st.InsertCompletionReceipt(ctx, receipt); err != nil {
		t.Fatalf("InsertCompletionReceipt: %v", err)
	}
	// A duplicate receipt is idempotent (ON CONFLICT DO NOTHING).
	if err := st.InsertCompletionReceipt(ctx, receipt); err != nil {
		t.Fatalf("InsertCompletionReceipt replay: %v", err)
	}
	got, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || got.ResultHash != "hash" {
		t.Fatalf("HasCompletionReceipt = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := st.HasCompletionReceipt(ctx, jobID, 2, runnerID); err != nil || ok {
		t.Fatalf("missing receipt = %v, %v", ok, err)
	}

	if err := st.UpsertDelivery(ctx, "github", "d1", runID, "digest-1"); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}
	// An update replaces the stored run/digest pair.
	if err := st.UpsertDelivery(ctx, "github", "d1", runID, "digest-2"); err != nil {
		t.Fatalf("UpsertDelivery update: %v", err)
	}
	gotRun, ok, err := st.FindDelivery(ctx, "github", "d1")
	if err != nil || !ok || gotRun != runID {
		t.Fatalf("FindDelivery = %q, %v, %v", gotRun, ok, err)
	}
	if _, ok, err := st.FindDelivery(ctx, "github", "missing"); err != nil || ok {
		t.Fatalf("FindDelivery missing = %v, %v", ok, err)
	}
}

func TestPostgresIntegrationOutboxRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	id1, id2 := "o1-"+suffix, "o2-"+suffix
	first := OutboxItem{ID: id1, Kind: "k1", Payload: []byte(`{"a":1}`), CreatedAt: now}
	if err := st.OutboxAppend(ctx, first); err != nil {
		t.Fatalf("OutboxAppend: %v", err)
	}
	// Idempotent by ID: a replay with IDENTICAL content (lost ACK) succeeds
	// without creating a second row; the same ID with DIFFERENT content is
	// an invariant failure.
	if err := st.OutboxAppend(ctx, first); err != nil {
		t.Fatalf("identical replay must succeed: %v", err)
	}
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id1, Kind: "k1", Payload: []byte(`{"a":2}`), CreatedAt: now}); err == nil {
		t.Fatal("same id with different content must fail")
	}
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id2, Kind: "k2", CreatedAt: now}); err != nil {
		t.Fatalf("OutboxAppend second: %v", err)
	}
	pending, err := st.OutboxPending(ctx)
	if err != nil || len(pending) != 2 || pending[0].ID != id1 {
		t.Fatalf("OutboxPending = %+v, %v", pending, err)
	}

	if _, err := st.ClaimOutbox(ctx, "", 5); err == nil {
		t.Fatal("empty claimer must fail")
	}
	if claimed, err := st.ClaimOutbox(ctx, "flusher", 0); err != nil || claimed != nil {
		t.Fatalf("zero limit = %v, %v", claimed, err)
	}
	claimed, err := st.ClaimOutbox(ctx, "flusher", 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != id1 {
		t.Fatalf("ClaimOutbox = %+v, %v", claimed, err)
	}
	// A fresh claim is invisible to another flusher.
	again, err := st.ClaimOutbox(ctx, "other", 5)
	if err != nil || len(again) != 1 || again[0].ID != id2 {
		t.Fatalf("second flusher = %+v, %v", again, err)
	}
	// Releasing the claim makes the row claimable again immediately.
	if err := st.ReleaseOutboxClaim(ctx, id1, "flusher"); err != nil {
		t.Fatalf("ReleaseOutboxClaim: %v", err)
	}
	reclaimed, err := st.ClaimOutbox(ctx, "other", 1)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != id1 {
		t.Fatalf("reclaim after release = %+v, %v", reclaimed, err)
	}
	// Releasing a wrong claimer is a no-op.
	if err := st.ReleaseOutboxClaim(ctx, id2, "wrong"); err != nil {
		t.Fatalf("ReleaseOutboxClaim wrong: %v", err)
	}
	if err := st.OutboxAck(ctx, id1); err != nil {
		t.Fatalf("OutboxAck: %v", err)
	}
	pending, _ = st.OutboxPending(ctx)
	if len(pending) != 1 || pending[0].ID != id2 {
		t.Fatalf("after ack = %+v", pending)
	}
}

func TestPostgresIntegrationSchedulesRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	created := time.Now().UTC().Truncate(time.Microsecond)
	sched := Schedule{ID: pgITNewID(t), Repository: "kiwi-it/repo", RepoID: pgITRepoID, RepoURL: pgITRepo, Forge: "github", Spec: "@daily", Enabled: true, CreatedAt: created, CreatedBy: "admin"}

	if _, err := st.ListSchedules(ctx); err != nil {
		t.Fatalf("ListSchedules empty: %v", err)
	}
	if err := st.UpsertSchedule(ctx, sched); err != nil {
		t.Fatalf("UpsertSchedule: %v", err)
	}
	// A zero CreatedAt preserves the stored creation time.
	sched.CreatedAt = time.Time{}
	sched.Spec = "@hourly"
	if err := st.UpsertSchedule(ctx, sched); err != nil {
		t.Fatalf("UpsertSchedule update: %v", err)
	}
	schedules, err := st.ListSchedules(ctx)
	if err != nil || len(schedules) != 1 || schedules[0].Spec != "@hourly" || !schedules[0].CreatedAt.Equal(created) {
		t.Fatalf("ListSchedules = %+v, %v", schedules, err)
	}

	nominal := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.UpsertSchedule(ctx, Schedule{ID: "", Spec: "x"}); err == nil {
		t.Fatal("empty schedule id must fail")
	}
	claimed, err := st.ClaimScheduleOccurrence(ctx, sched.ID, nominal, runID)
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if claimed, err = st.ClaimScheduleOccurrence(ctx, sched.ID, nominal, runID); err != nil || !claimed {
		t.Fatalf("idempotent claim = %v, %v", claimed, err)
	}
	if claimed, err = st.ClaimScheduleOccurrence(ctx, sched.ID, nominal, pgITNewID(t)); err != nil || claimed {
		t.Fatalf("conflicting claim = %v, %v", claimed, err)
	}
	if _, err := st.ClaimScheduleOccurrence(ctx, "", nominal, runID); err == nil {
		t.Fatal("empty schedule id must fail")
	}
	occurrences, err := st.ListOccurrences(ctx, sched.ID)
	if err != nil || len(occurrences) != 1 || occurrences[0].RunID != runID {
		t.Fatalf("ListOccurrences = %+v, %v", occurrences, err)
	}
	if occurrences, err = st.ListOccurrences(ctx, pgITNewID(t)); err != nil || len(occurrences) != 0 {
		t.Fatalf("ListOccurrences empty = %+v, %v", occurrences, err)
	}
}

func TestPostgresIntegrationDeploymentsAndSnapshots(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	depID := pgITNewID(t)
	snapID := pgITNewID(t)

	dep := model.Deployment{ID: depID, RunID: runID, JobID: jobID, Repository: "kiwi-it/repo", Environment: "prod", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	if err := st.InsertDeployment(ctx, dep); err != nil {
		t.Fatalf("InsertDeployment: %v", err)
	}
	if err := st.InsertDeployment(ctx, dep); err == nil {
		t.Fatal("duplicate deployment id must fail")
	}
	deps, err := st.ListDeploymentsByRun(ctx, runID)
	if err != nil || len(deps) != 1 || deps[0].Environment != "prod" {
		t.Fatalf("ListDeploymentsByRun = %+v, %v", deps, err)
	}
	if deps, err = st.ListDeploymentsByRun(ctx, pgITNewID(t)); err != nil || len(deps) != 0 {
		t.Fatalf("ListDeploymentsByRun empty = %+v, %v", deps, err)
	}
	finished := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.UpdateDeploymentStatus(ctx, depID, model.StatusSuccess, &finished); err != nil {
		t.Fatalf("UpdateDeploymentStatus: %v", err)
	}
	deps, _ = st.ListDeploymentsByRun(ctx, runID)
	if deps[0].Status != model.StatusSuccess || deps[0].FinishedAt == nil {
		t.Fatalf("updated deployment = %+v", deps[0])
	}
	// Nil finished leaves the stored value untouched.
	if err := st.UpdateDeploymentStatus(ctx, depID, model.StatusFailure, nil); err != nil {
		t.Fatalf("UpdateDeploymentStatus nil: %v", err)
	}
	if err := st.UpdateDeploymentStatus(ctx, "ffffffffffffffffffffffffffffffff", model.StatusFailure, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deployment = %v", err)
	}

	rec := model.SnapshotRecord{ID: snapID, RunID: runID, JobID: jobID, JobKey: "build", Path: "/tmp/snap", Size: 9, SHA256: "sha", Version: 2, RootSHA256: "root", CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotRecord(ctx, rec); err != nil {
		t.Fatalf("InsertSnapshotRecord: %v", err)
	}
	snaps, err := st.ListSnapshotsByRun(ctx, runID)
	if err != nil || len(snaps) != 1 || snaps[0].RootSHA256 != "root" {
		t.Fatalf("ListSnapshotsByRun = %+v, %v", snaps, err)
	}
	if snaps, err = st.ListSnapshotsByRun(ctx, pgITNewID(t)); err != nil || len(snaps) != 0 {
		t.Fatalf("ListSnapshotsByRun empty = %+v, %v", snaps, err)
	}
}

func TestPostgresIntegrationContractsAndQueueReasons(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	contracts := map[string]ArtifactContract{"bundle": {Name: "bundle", Paths: []string{"dist/"}, Required: true, Retention: time.Hour, MaxSize: 100, SHA256: "sha"}}
	if err := st.InsertJobContracts(ctx, jobID, contracts); err != nil {
		t.Fatalf("InsertJobContracts: %v", err)
	}
	got, ok, err := st.GetJobContracts(ctx, jobID)
	if err != nil || !ok || got["bundle"].MaxSize != 100 || len(got["bundle"].Paths) != 1 {
		t.Fatalf("GetJobContracts = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := st.GetJobContracts(ctx, pgITNewID(t)); err != nil || ok {
		t.Fatalf("GetJobContracts missing = %v, %v", ok, err)
	}
	if err := st.InsertJobContracts(ctx, "bad", contracts); err == nil {
		t.Fatal("invalid job id must fail")
	}
	// Inserting an empty contract map clears the stored set but keeps the
	// presence marker.
	if err := st.InsertJobContracts(ctx, jobID, map[string]ArtifactContract{}); err != nil {
		t.Fatalf("InsertJobContracts empty: %v", err)
	}
	got, ok, err = st.GetJobContracts(ctx, jobID)
	if err != nil || !ok || len(got) != 0 {
		t.Fatalf("cleared contracts = %+v, %v, %v", got, ok, err)
	}

	if err := st.SetQueueReasons(ctx, map[string]string{jobID: "waiting for runner"}); err != nil {
		t.Fatalf("SetQueueReasons: %v", err)
	}
	job, _ := st.GetJob(ctx, jobID)
	if job.QueueReason != "waiting for runner" {
		t.Fatalf("queue reason = %q", job.QueueReason)
	}
	// An empty reason removes the stored value.
	if err := st.SetQueueReasons(ctx, map[string]string{jobID: ""}); err != nil {
		t.Fatalf("SetQueueReasons clear: %v", err)
	}
	job, _ = st.GetJob(ctx, jobID)
	if job.QueueReason != "" {
		t.Fatalf("queue reason not cleared: %q", job.QueueReason)
	}
	// Unknown job ids are ignored without failing the batch.
	if err := st.SetQueueReasons(ctx, map[string]string{pgITNewID(t): "x"}); err != nil {
		t.Fatalf("SetQueueReasons unknown: %v", err)
	}
	if err := st.SetQueueReasons(ctx, map[string]string{"bad": "x"}); err == nil {
		t.Fatal("invalid job id must fail")
	}
}

func TestPostgresIntegrationUsageQuotaAndCache(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)

	cost, energy, err := st.RecentUsage(ctx, time.Now().UTC().Add(-time.Hour))
	if err != nil || cost != 0 || energy != 0 {
		t.Fatalf("empty usage = %v, %v, %v", cost, energy, err)
	}
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	finished := time.Now().UTC().Add(-time.Minute)
	job, _ := st.GetJob(ctx, jobID)
	job.Status = model.StatusSuccess
	job.FinishedAt = &finished
	job.Cost = 3.5
	job.EnergyWh = 12
	if err := st.UpdateJob(ctx, job); err != nil {
		t.Fatalf("update job: %v", err)
	}
	cost, energy, err = st.RecentUsage(ctx, time.Now().UTC().Add(-time.Hour))
	if err != nil || cost != 3.5 || energy != 12 {
		t.Fatalf("usage = %v, %v, %v", cost, energy, err)
	}
	if cost, energy, err = st.RecentUsage(ctx, time.Now().UTC()); err != nil || cost != 0 || energy != 0 {
		t.Fatalf("usage before cutoff = %v, %v, %v", cost, energy, err)
	}

	if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/o/r', 0, 0), ('github.com/o', 0, 0) ON CONFLICT (key) DO NOTHING`); err != nil {
		t.Fatalf("seed quota rows: %v", err)
	}
	if err := st.AdjustQuotaCounter(ctx, "github.com/o/r", "github.com/o", 3, 4); err != nil {
		t.Fatalf("AdjustQuotaCounter: %v", err)
	}
	running, queued, err := st.QuotaCounts(ctx, "github.com/o/r", "github.com/o")
	if err != nil || running != 6 || queued != 8 {
		t.Fatalf("QuotaCounts = %d, %d, %v", running, queued, err)
	}
	// Negative deltas clamp at zero and empty keys are ignored.
	if err := st.AdjustQuotaCounter(ctx, "github.com/o/r", "", -100, -100); err != nil {
		t.Fatalf("AdjustQuotaCounter clamp: %v", err)
	}
	if running, queued, err = st.QuotaCounts(ctx, "github.com/o/r", ""); err != nil || running != 0 || queued != 0 {
		t.Fatalf("clamped QuotaCounts = %d, %d, %v", running, queued, err)
	}
	if err := st.AdjustQuotaCounter(ctx, "", "", 5, 5); err != nil {
		t.Fatalf("AdjustQuotaCounter empty keys: %v", err)
	}
	// Counters of an unknown key pair read as zero.
	if running, queued, err := st.QuotaCounts(ctx, "github.com/unknown/repo", "github.com/unknown"); err != nil || running != 0 || queued != 0 {
		t.Fatalf("unknown quota counts = %d, %d, %v", running, queued, err)
	}
	if running, queued, err = st.QuotaCounts(ctx, "", ""); err != nil || running != 0 || queued != 0 {
		t.Fatalf("empty-key QuotaCounts = %d, %d, %v", running, queued, err)
	}

	if _, ok, err := st.GetCacheManifest(ctx, "r", "t", "l"); err != nil || ok {
		t.Fatalf("missing manifest = %v, %v", ok, err)
	}
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "github.com/o/r", TrustDomain: "td", LogicalKey: "l1", BlobSHA256: memDigest, BlobSize: 7, ProducerRun: runID, ProducerJob: jobID, Envelope: []byte("env")}); err != nil {
		t.Fatalf("PutCacheManifest: %v", err)
	}
	got, ok, err := st.GetCacheManifest(ctx, "github.com/o/r", "td", "l1")
	if err != nil || !ok || got.BlobSHA256 != memDigest || got.BlobSize != 7 || string(got.Envelope) != "env" {
		t.Fatalf("GetCacheManifest = %+v, %v, %v", got, ok, err)
	}
	// A second put overwrites the record.
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "github.com/o/r", TrustDomain: "td", LogicalKey: "l1", BlobSHA256: memDigest2}); err != nil {
		t.Fatalf("PutCacheManifest overwrite: %v", err)
	}
	if got, _, _ = st.GetCacheManifest(ctx, "github.com/o/r", "td", "l1"); got.BlobSHA256 != memDigest2 {
		t.Fatalf("overwritten manifest = %+v", got)
	}
}

func TestPostgresIntegrationSidecarsAndDownstreamRuns(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	childID := pgITNewID(t)

	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("RememberPendingSidecar: %v", err)
	}
	// A re-upload replaces the digest.
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("RememberPendingSidecar replace: %v", err)
	}
	digest, ok, err := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM)
	if err != nil || !ok || digest != memDigest2 {
		t.Fatalf("PendingSidecar = %q, %v, %v", digest, ok, err)
	}
	if _, ok, err := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSigstore); err != nil || ok {
		t.Fatalf("missing pending sidecar = %v, %v", ok, err)
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("invalid digest must fail")
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", "pbom", memDigest); err == nil {
		t.Fatal("invalid kind must fail")
	}
	// A stale consumer must not delete a newer digest.
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("stale consume: %v", err)
	}
	if _, ok, _ := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM); !ok {
		t.Fatal("stale consume dropped the row")
	}
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("ConsumePendingSidecar: %v", err)
	}
	if _, ok, _ := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("consume did not delete the row")
	}
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("consume missing: %v", err)
	}
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", "pbom", memDigest); err == nil {
		t.Fatal("invalid kind must fail")
	}
	if err := st.DeletePendingSidecars(ctx, "bad"); err == nil {
		t.Fatal("invalid job id must fail")
	}

	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if err := st.DeletePendingSidecars(ctx, jobID); err != nil {
		t.Fatalf("DeletePendingSidecars: %v", err)
	}
	pruned, err := st.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour))
	if err != nil || pruned != 0 {
		t.Fatalf("prune after delete = %d, %v", pruned, err)
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("remember: %v", err)
	}
	pruned, err = st.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour))
	if err != nil || pruned != 1 {
		t.Fatalf("prune = %d, %v", pruned, err)
	}

	// Downstream run tracking.
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if err := st.AppendDownstreamRun(ctx, "ffffffffffffffffffffffffffffffff", childID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("append to missing run = %v", err)
	}
	if err := st.AppendDownstreamRun(ctx, "bad", childID); err == nil {
		t.Fatal("invalid run id must fail")
	}
	if err := st.AppendDownstreamRun(ctx, runID, childID); err != nil {
		t.Fatalf("AppendDownstreamRun: %v", err)
	}
	// The append is idempotent.
	if err := st.AppendDownstreamRun(ctx, runID, childID); err != nil {
		t.Fatalf("AppendDownstreamRun replay: %v", err)
	}
	run, _ := st.GetRun(ctx, runID)
	if len(run.DownstreamRuns) != 1 {
		t.Fatalf("downstream runs = %v", run.DownstreamRuns)
	}
	// A missing run row is a silent no-op.
	if err := st.ReopenRunForChildren(ctx, "ffffffffffffffffffffffffffffffff"); err != nil {
		t.Fatalf("reopen missing = %v", err)
	}
	if err := st.ReopenRunForChildren(ctx, "bad"); err == nil {
		t.Fatal("invalid run id must fail")
	}
	// A non-success run is left untouched.
	if err := st.ReopenRunForChildren(ctx, runID); err != nil {
		t.Fatalf("ReopenRunForChildren: %v", err)
	}
	if err := st.UpdateRunStatus(ctx, runID, model.StatusSuccess, nil, nil); err != nil {
		t.Fatalf("mark success: %v", err)
	}
	if err := st.ReopenRunForChildren(ctx, runID); err != nil {
		t.Fatalf("ReopenRunForChildren success: %v", err)
	}
	run, _ = st.GetRun(ctx, runID)
	if run.Status != model.StatusRunning || run.FinishedAt != nil {
		t.Fatalf("reopened run = %+v", run)
	}
}

func TestPostgresIntegrationTestHistory(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	version, stats, err := st.LoadTestHistory(ctx)
	if err != nil || version != 0 || stats != nil {
		t.Fatalf("empty history = %d, %s, %v", version, stats, err)
	}
	// SaveTestHistory inserts the single cache row, bumps the version on
	// every save, and the payload round-trips through LoadTestHistory.
	v1, err := st.SaveTestHistory(ctx, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("SaveTestHistory: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("first save version = %d, want 1", v1)
	}
	version, stats, err = st.LoadTestHistory(ctx)
	if err != nil || version != 1 {
		t.Fatalf("history after first save = %d, %s, %v", version, stats, err)
	}
	var saved map[string]any
	if err := json.Unmarshal(stats, &saved); err != nil || saved["a"] != float64(1) {
		t.Fatalf("saved stats = %s, %v", stats, err)
	}
	// Nil stats are stored as an empty object and read back as nil.
	v2, err := st.SaveTestHistory(ctx, nil)
	if err != nil {
		t.Fatalf("SaveTestHistory(nil): %v", err)
	}
	if v2 != 2 {
		t.Fatalf("second save version = %d, want 2", v2)
	}
	version, stats, err = st.LoadTestHistory(ctx)
	if err != nil || version != 2 || stats != nil {
		t.Fatalf("nil-stats history = %d, %s, %v", version, stats, err)
	}
	// Seeded rows drive the read paths: a JSON object round-trips and an
	// empty object normalizes to nil.
	if _, err := st.pool.Exec(ctx, `INSERT INTO test_history (id, version, stats) VALUES (1, 3, '{"a":1}'::jsonb) ON CONFLICT (id) DO UPDATE SET version=3, stats=EXCLUDED.stats`); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	version, stats, err = st.LoadTestHistory(ctx)
	if err != nil || version != 3 {
		t.Fatalf("history = %d, %s, %v", version, stats, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(stats, &decoded); err != nil || decoded["a"] != float64(1) {
		t.Fatalf("history stats = %s, %v", stats, err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE test_history SET stats='{}'::jsonb WHERE id=1`); err != nil {
		t.Fatalf("empty history stats: %v", err)
	}
	version, stats, err = st.LoadTestHistory(ctx)
	if err != nil || version != 3 || stats != nil {
		t.Fatalf("empty history = %d, %s, %v", version, stats, err)
	}
}

func TestPostgresIntegrationLeadership(t *testing.T) {
	env := pgITSetup(t)
	leader := env.open(t)
	challenger := env.open(t)
	env.migrate(t, leader)
	ctx := context.Background()
	key := "kiwi-it-leader"

	if _, err := leader.TryAcquireLeadership(ctx, "", time.Minute); err == nil {
		t.Fatal("empty key must fail")
	}
	if _, err := leader.TryAcquireLeadership(ctx, key, 0); err == nil {
		t.Fatal("non-positive ttl must fail")
	}
	got, err := leader.TryAcquireLeadership(ctx, key, time.Minute)
	if err != nil || !got {
		t.Fatalf("first TryAcquireLeadership = %v, %v", got, err)
	}
	// Re-acquiring on the same store renews the held lease.
	if got, err = leader.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("renew = %v, %v", got, err)
	}
	// A different store cannot hold the same session lock.
	if got, err = challenger.TryAcquireLeadership(ctx, key, time.Minute); err != nil || got {
		t.Fatalf("contended acquire = %v, %v", got, err)
	}
	// Switching keys releases the held lock and takes the new one.
	if got, err = leader.TryAcquireLeadership(ctx, "other-key", time.Minute); err != nil || !got {
		t.Fatalf("key switch = %v, %v", got, err)
	}
	// Releasing a key this store does not hold is a no-op.
	if err := challenger.ReleaseLeadership(ctx, "never-held"); err != nil {
		t.Fatalf("release unheld = %v", err)
	}
	if err := leader.ReleaseLeadership(ctx, "other-key"); err != nil {
		t.Fatalf("ReleaseLeadership: %v", err)
	}
	if got, err = challenger.TryAcquireLeadership(ctx, "other-key", time.Minute); err != nil || !got {
		t.Fatalf("acquire after release = %v, %v", got, err)
	}
	// Close drops the held leader connection.
	if err := challenger.Close(); err != nil {
		t.Fatalf("close with leader conn: %v", err)
	}
}

func TestPostgresIntegrationProfilesTokensRevocationsGrants(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	profileID := pgITNewID(t)
	runnerID := pgITNewID(t)

	if _, err := st.GetProfile(ctx, profileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile = %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, Labels: []string{"linux"}, Region: "eu", Repositories: []string{"github.com/o/r"}, Capabilities: []string{"container"}, MaxCapacity: 4, CostPerHour: 2, PowerWatts: 30}); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}
	got, err := st.GetProfile(ctx, profileID)
	if err != nil || got.MaxCapacity != 4 || len(got.Labels) != 1 || got.CreatedAt.IsZero() {
		t.Fatalf("GetProfile = %+v, %v", got, err)
	}
	// A zero CreatedAt preserves the stored creation time.
	created := got.CreatedAt
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 9}); err != nil {
		t.Fatalf("UpsertProfile update: %v", err)
	}
	got, _ = st.GetProfile(ctx, profileID)
	if got.MaxCapacity != 9 || !got.CreatedAt.Equal(created) {
		t.Fatalf("profile after update = %+v", got)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: ""}); err == nil {
		t.Fatal("empty profile id must fail")
	}
	profiles, err := st.ListProfiles(ctx)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("ListProfiles = %+v, %v", profiles, err)
	}

	if _, ok, err := st.ProfileForSerial(ctx, "serial-missing"); err != nil || ok {
		t.Fatalf("unlinked serial = %v, %v", ok, err)
	}
	if err := st.BindCertProfile(ctx, "serial", profileID); err != nil {
		t.Fatalf("BindCertProfile: %v", err)
	}
	// Re-binding replaces the link.
	if err := st.BindCertProfile(ctx, "serial", profileID); err != nil {
		t.Fatalf("BindCertProfile rebind: %v", err)
	}
	if p, ok, err := st.ProfileForSerial(ctx, "serial"); err != nil || !ok || p.ID != profileID {
		t.Fatalf("ProfileForSerial = %+v, %v, %v", p, ok, err)
	}
	if err := st.BindCertProfile(ctx, "dangling", pgITNewID(t)); err != nil {
		t.Fatalf("BindCertProfile dangling: %v", err)
	}
	if _, ok, err := st.ProfileForSerial(ctx, "dangling"); err != nil || ok {
		t.Fatalf("dangling serial = %v, %v", ok, err)
	}

	if has, err := st.HasRunnerTokens(ctx); err != nil || has {
		t.Fatalf("empty tokens = %v, %v", has, err)
	}
	if err := st.UpsertRunnerToken(ctx, runnerID, "digest"); err != nil {
		t.Fatalf("UpsertRunnerToken: %v", err)
	}
	if err := st.UpsertRunnerToken(ctx, runnerID, "digest"); err != nil {
		t.Fatalf("UpsertRunnerToken update: %v", err)
	}
	if id, ok, err := st.RunnerIDForToken(ctx, "digest"); err != nil || !ok || id != runnerID {
		t.Fatalf("RunnerIDForToken = %q, %v, %v", id, ok, err)
	}
	if _, ok, err := st.RunnerIDForToken(ctx, "unknown"); err != nil || ok {
		t.Fatalf("unknown token = %v, %v", ok, err)
	}
	if has, err := st.HasRunnerTokens(ctx); err != nil || !has {
		t.Fatalf("tokens present = %v, %v", has, err)
	}

	if revoked, err := st.CertRevoked(ctx, "serial"); err != nil || revoked {
		t.Fatalf("fresh cert = %v, %v", revoked, err)
	}
	if err := st.RevokeCert(ctx, "serial", runnerID, "compromised"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	// Revoking again replaces the reason without failing.
	if err := st.RevokeCert(ctx, "serial", runnerID, "renewed"); err != nil {
		t.Fatalf("RevokeCert again: %v", err)
	}
	if revoked, err := st.CertRevoked(ctx, "serial"); err != nil || !revoked {
		t.Fatalf("revoked cert = %v, %v", revoked, err)
	}

	if _, err := st.ConsumeEnrollGrant(ctx, "unknown", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown grant = %v", err)
	}
	if err := st.PutEnrollGrant(ctx, "digest", time.Now().UTC().Add(time.Hour), []string{"linux"}); err != nil {
		t.Fatalf("PutEnrollGrant: %v", err)
	}
	rec, ok, err := st.GetEnrollGrant(ctx, "digest")
	if err != nil || !ok || len(rec.BoundLabels) != 1 || rec.Consumed {
		t.Fatalf("GetEnrollGrant = %+v, %v, %v", rec, ok, err)
	}
	if _, ok, err := st.GetEnrollGrant(ctx, "missing"); err != nil || ok {
		t.Fatalf("missing grant = %v, %v", ok, err)
	}
	consumed, err := st.ConsumeEnrollGrant(ctx, "digest", "admin")
	if err != nil || !consumed.Consumed {
		t.Fatalf("ConsumeEnrollGrant = %+v, %v", consumed, err)
	}
	if _, err := st.ConsumeEnrollGrant(ctx, "digest", "admin"); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("second consume = %v, want ErrGrantConsumed", err)
	}
	if err := st.PutEnrollGrant(ctx, "expired", time.Now().UTC().Add(-time.Minute), nil); err != nil {
		t.Fatalf("PutEnrollGrant expired: %v", err)
	}
	if _, err := st.ConsumeEnrollGrant(ctx, "expired", "admin"); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired consume = %v, want ErrGrantExpired", err)
	}
}

func TestPostgresIntegrationGeneratedJobsAndFragments(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	parentID := pgITNewID(t)
	childID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, parentID, pgITRepo)

	if err := st.InsertGeneratedJobs(ctx, parentID, 1, map[string]model.Job{childID: pgITJob(runID, childID, pgITRepo)}, nil); err != nil {
		t.Fatalf("InsertGeneratedJobs: %v", err)
	}
	if _, err := st.GetJob(ctx, childID); err != nil {
		t.Fatalf("generated job missing: %v", err)
	}
	if err := st.InsertGeneratedJobs(ctx, "bad", 1, nil, nil); err == nil {
		t.Fatal("invalid parent id must fail")
	}
	if err := st.InsertGeneratedJobs(ctx, pgITNewID(t), 1, nil, nil); err != nil {
		t.Fatalf("empty generated set for unknown parent = %v", err)
	}
	if err := st.InsertGeneratedJobs(ctx, parentID, 1, nil, nil); err != nil {
		t.Fatalf("empty generated set = %v", err)
	}
	// A duplicate generated job id fails on the primary key.
	badJob := pgITJob(runID, childID, pgITRepo)
	if err := st.InsertGeneratedJobs(ctx, parentID, 1, map[string]model.Job{childID: badJob}, nil); err == nil {
		t.Fatal("duplicate generated job must fail")
	}
	if err := st.InsertGeneratedJobs(ctx, parentID, 1, map[string]model.Job{pgITNewID(t): pgITJob(runID, pgITNewID(t), pgITRepo)}, nil); err != nil {
		t.Fatalf("generated job with unknown run must fail the FK: %v", err)
	}

	if _, ok, err := st.GetGeneratedFragment(ctx, parentID, 1, "frag"); err != nil || ok {
		t.Fatalf("missing fragment = %v, %v", ok, err)
	}
	fragChild := pgITNewID(t)
	req := GeneratedFragmentRequest{
		ParentJobID:     parentID,
		Depth:           1,
		LeaseGeneration: 1,
		FragmentID:      "frag-1",
		Jobs:            map[string]model.Job{fragChild: pgITJob(runID, fragChild, pgITRepo)},
		Deps:            map[string][]string{fragChild: {}},
		Children:        []GeneratedFragmentChild{{Key: "child", ID: fragChild}},
	}
	receipt, replayed, err := st.InsertGeneratedFragmentTx(ctx, req, nil)
	if err != nil || replayed || len(receipt.Children) != 1 {
		t.Fatalf("InsertGeneratedFragmentTx = %+v, %v, %v", receipt, replayed, err)
	}
	// A replay returns the original receipt without inserting.
	again, replayed, err := st.InsertGeneratedFragmentTx(ctx, req, nil)
	if err != nil || !replayed || again.FragmentID != receipt.FragmentID {
		t.Fatalf("fragment replay = %+v, %v, %v", again, replayed, err)
	}
	got, ok, err := st.GetGeneratedFragment(ctx, parentID, 1, "frag-1")
	if err != nil || !ok || got.ParentJobID != parentID {
		t.Fatalf("GetGeneratedFragment = %+v, %v, %v", got, ok, err)
	}
	// The verifier runs inside the transaction and its error rolls back.
	verifier := func(parent model.Job, runJobCount int) error {
		if runJobCount <= 0 {
			return errors.New("no jobs")
		}
		return nil
	}
	rejChild := pgITNewID(t)
	rejReq := GeneratedFragmentRequest{ParentJobID: parentID, LeaseGeneration: 1, FragmentID: "rejected", Jobs: map[string]model.Job{rejChild: pgITJob(runID, rejChild, pgITRepo)}}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, rejReq, verifier); err != nil {
		t.Fatalf("verifier pass: %v", err)
	}
	rejectedChild := pgITNewID(t)
	rejReq.FragmentID = "rejected-2"
	rejReq.Jobs = map[string]model.Job{rejectedChild: pgITJob(runID, rejectedChild, pgITRepo)}
	failVerifier := func(parent model.Job, runJobCount int) error { return errors.New("rejected by verifier") }
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, rejReq, failVerifier); err == nil {
		t.Fatal("failing verifier must reject the fragment")
	}
	if _, err := st.GetJob(ctx, rejectedChild); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected fragment must not insert jobs")
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: "bad", Jobs: map[string]model.Job{}}, nil); err == nil {
		t.Fatal("invalid parent id must fail")
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: pgITNewID(t), FragmentID: "missing-parent", Jobs: map[string]model.Job{}}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent fragment = %v", err)
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: parentID, FragmentID: "", Jobs: map[string]model.Job{}}, nil); err == nil {
		t.Fatal("empty fragment id must fail")
	}
	if _, _, err := st.GetGeneratedFragment(ctx, parentID, 1, ""); err == nil {
		t.Fatal("empty fragment id lookup must fail")
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: parentID, Jobs: map[string]model.Job{"bad": {ID: "bad"}}}, nil); err == nil {
		t.Fatal("invalid fragment job id must fail")
	}
	// Contracts land with the fragment; an unknown contract job id simply
	// updates no row.
	contractChild := pgITNewID(t)
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{
		ParentJobID: parentID,
		FragmentID:  "with-contract",
		Jobs:        map[string]model.Job{contractChild: pgITJob(runID, contractChild, pgITRepo)},
		Contracts:   map[string]map[string]ArtifactContract{contractChild: testContracts},
	}, nil); err != nil {
		t.Fatalf("fragment with contracts: %v", err)
	}
	contracts, ok, err := st.GetJobContracts(ctx, contractChild)
	if err != nil || !ok || contracts["bundle"].Name != "bundle" {
		t.Fatalf("fragment contracts = %+v, %v, %v", contracts, ok, err)
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{
		ParentJobID: parentID,
		FragmentID:  "unknown-contract",
		Jobs:        map[string]model.Job{},
		Contracts:   map[string]map[string]ArtifactContract{pgITNewID(t): testContracts},
	}, nil); err != nil {
		t.Fatalf("unknown contract job id is a no-op update: %v", err)
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: parentID, FragmentID: "bad-contract", Jobs: map[string]model.Job{}, Contracts: map[string]map[string]ArtifactContract{"bad": {}}}, nil); err == nil {
		t.Fatal("invalid contract job id must fail")
	}
}

func TestPostgresIntegrationDownstreamLinks(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	parentID := pgITNewID(t)
	childID := pgITNewID(t)
	link := DownstreamLink{ParentJobID: parentID, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok", TargetForge: "github", TargetBaseURL: "https://github.com", TargetRepoID: "github.com/acme/child", StableChildID: memDigest, CreatedAt: time.Now().UTC()}

	if _, ok, err := st.GetDownstreamLink(ctx, parentID, "acme/child", "main"); err != nil || ok {
		t.Fatalf("missing link = %v, %v", ok, err)
	}
	if err := st.InsertDownstreamLink(ctx, link); err != nil {
		t.Fatalf("InsertDownstreamLink: %v", err)
	}
	got, ok, err := st.GetDownstreamLink(ctx, parentID, "acme/child", "main")
	if err != nil || !ok || got.LaunchToken != "tok" || got.TargetForge != "github" {
		t.Fatalf("GetDownstreamLink = %+v, %v, %v", got, ok, err)
	}
	if err := st.InsertDownstreamLink(ctx, link); err != nil {
		t.Fatalf("duplicate link insert must be a no-op: %v", err)
	}

	// Reserve is claim-if-unreserved: the second reservation reports false.
	reserved, err := st.ReserveDownstreamLaunch(ctx, parentID, "acme/child", "main", "tok-2")
	if err != nil || !reserved {
		t.Fatalf("first reserve = %v, %v", reserved, err)
	}
	if reserved, err = st.ReserveDownstreamLaunch(ctx, parentID, "acme/child", "main", "tok-3"); err != nil || reserved {
		t.Fatalf("double reserve = %v, %v", reserved, err)
	}
	if err := st.ReleaseDownstreamReservation(ctx, parentID, "acme/child", "main"); err != nil {
		t.Fatalf("ReleaseDownstreamReservation: %v", err)
	}
	if reserved, err = st.ReserveDownstreamLaunch(ctx, parentID, "acme/child", "main", "tok-4"); err != nil || !reserved {
		t.Fatalf("re-reserve = %v, %v", reserved, err)
	}
	if err := st.MarkDownstreamLaunched(ctx, parentID, "acme/child", "main", childID); err != nil {
		t.Fatalf("MarkDownstreamLaunched: %v", err)
	}
	got, _, _ = st.GetDownstreamLink(ctx, parentID, "acme/child", "main")
	if got.ChildRunID != childID || got.Reserved {
		t.Fatalf("launched link = %+v", got)
	}
	// A launched link refuses a new reservation and re-marking is a no-op.
	if reserved, err = st.ReserveDownstreamLaunch(ctx, parentID, "acme/child", "main", "tok-5"); err != nil || reserved {
		t.Fatalf("reserve launched = %v, %v", reserved, err)
	}
	if err := st.MarkDownstreamLaunched(ctx, parentID, "acme/child", "main", pgITNewID(t)); err != nil {
		t.Fatalf("re-mark launched: %v", err)
	}
	got, _, _ = st.GetDownstreamLink(ctx, parentID, "acme/child", "main")
	if got.ChildRunID != childID {
		t.Fatalf("re-mark changed the child: %+v", got)
	}
	if err := st.ReleaseDownstreamReservation(ctx, parentID, "acme/child", "main"); err != nil {
		t.Fatalf("release launched: %v", err)
	}
	// Missing links are tolerated by mark/release/reserve.
	if err := st.MarkDownstreamLaunched(ctx, pgITNewID(t), "none", "main", childID); err != nil {
		t.Fatalf("mark missing: %v", err)
	}
	if err := st.ReleaseDownstreamReservation(ctx, pgITNewID(t), "none", "main"); err != nil {
		t.Fatalf("release missing: %v", err)
	}

	// Expiry releases stale reservations but never launched links.
	staleParent := pgITNewID(t)
	if reserved, err = st.ReserveDownstreamLaunch(ctx, staleParent, "acme/child", "main", "tok"); err != nil || !reserved {
		t.Fatalf("stale reserve = %v, %v", reserved, err)
	}
	if n, err := st.ExpireDownstreamReservations(ctx, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("ExpireDownstreamReservations = %d, %v", n, err)
	}
	if n, err := st.ExpireDownstreamReservations(ctx, time.Now().UTC()); err != nil || n != 0 {
		t.Fatalf("second expiry = %d, %v", n, err)
	}
}

func TestPostgresIntegrationMigrateHelpers(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()
	// A fresh schema migrates from zero; a second run is a no-op.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	version, err := st.SchemaVersion(ctx)
	if err != nil || version == 0 {
		t.Fatalf("SchemaVersion = %d, %v", version, err)
	}
	// A migration recorded with a future version does not disturb the run.
	if _, err := st.pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (9999)`); err != nil {
		t.Fatalf("insert future migration: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate with future version: %v", err)
	}
	// A failing statement rolls the migration transaction back and surfaces
	// the error without recording the version.
	bogus := migrations.Migration{Version: 9998, Name: "9998_bogus.sql", Statements: []string{"SELECT 1 FROM table_that_does_not_exist"}}
	if err := st.applyMigration(ctx, bogus); err == nil {
		t.Fatal("failing migration must report its error")
	}
	var recorded bool
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=9998)`).Scan(&recorded); err != nil || recorded {
		t.Fatalf("failed migration must not be recorded: %v, %v", recorded, err)
	}
	// An already-applied version commits without re-running statements.
	if err := st.applyMigration(ctx, migrations.Migration{Version: version, Name: "already"}); err != nil {
		t.Fatalf("applied migration no-op: %v", err)
	}
	// SchemaVersion reads zero before the bootstrap table exists.
	fresh := pgITSetup(t)
	unst := fresh.open(t)
	if v, err := unst.SchemaVersion(ctx); err != nil || v != 0 {
		t.Fatalf("unmigrated SchemaVersion = %d, %v", v, err)
	}
}

func TestPostgresIntegrationCorruptPayloadDecodeErrors(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)

	// Corrupt payloads exercise the decode error paths of every scanner.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt job: %v", err)
	}
	if _, err := st.GetJob(ctx, jobID); err == nil {
		t.Fatal("corrupt job payload must fail to decode")
	}
	if _, err := st.ListJobsByRun(ctx, runID); err == nil {
		t.Fatal("corrupt job payload must fail the list decode")
	}

	if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='["array"]'::jsonb WHERE id=$1`, runID); err != nil {
		t.Fatalf("corrupt run: %v", err)
	}
	if _, err := st.GetRun(ctx, runID); err == nil {
		t.Fatal("corrupt run payload must fail to decode")
	}
	if _, err := st.ListRuns(ctx, 10); err == nil {
		t.Fatal("corrupt run payload must fail the list decode")
	}

	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='42'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt runner: %v", err)
	}
	if _, err := st.GetRunner(ctx, runnerID); err == nil {
		t.Fatal("corrupt runner payload must fail to decode")
	}
	if _, err := st.ListRunners(ctx); err == nil {
		t.Fatal("corrupt runner payload must fail the list decode")
	}
	// A corrupt active_jobs column is its own decode error.
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='{}'::jsonb, active_jobs='{"not":"an array"}'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt active jobs: %v", err)
	}
	if _, err := st.GetRunner(ctx, runnerID); err == nil {
		t.Fatal("corrupt active_jobs must fail to decode")
	}
}

func TestPostgresIntegrationInsertCompiledRunBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: model.Run{ID: "bad"}}); err == nil {
		t.Fatal("invalid run id must fail")
	}
	// Job ids and run ids are validated before the insert.
	runID := pgITNewID(t)
	err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{"bad": {ID: "bad", RunID: runID}},
	})
	if err == nil {
		t.Fatal("invalid job id must fail the enqueue")
	}
	// The dependency map is authoritative over the job's Needs.
	runID2 := pgITNewID(t)
	jobA := pgITNewID(t)
	jobB := pgITNewID(t)
	jobAJob := pgITJob(runID2, jobA, pgITRepo)
	jobBJob := pgITJob(runID2, jobB, pgITRepo)
	jobBJob.Needs = []string{jobA}
	req := InsertCompiledRunRequest{
		Run:  pgITRun(runID2, model.StatusQueued),
		Jobs: map[string]model.Job{jobA: jobAJob, jobB: jobBJob},
		Deps: map[string][]string{jobB: {}},
	}
	if err := st.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("enqueue with deps: %v", err)
	}
	gotB, _ := st.GetJob(ctx, jobB)
	if len(gotB.Needs) != 0 {
		t.Fatalf("explicit empty dependency entry must win: %v", gotB.Needs)
	}

	// The webhook claim dedupes the enqueue.
	runID3 := pgITNewID(t)
	jobC := pgITNewID(t)
	claim := &WebhookClaim{Forge: "github", DeliveryID: "del-1", RunID: runID3, PayloadDigest: "digest"}
	req3 := InsertCompiledRunRequest{Run: pgITRun(runID3, model.StatusQueued), Jobs: map[string]model.Job{jobC: pgITJob(runID3, jobC, pgITRepo)}, WebhookClaim: claim}
	if err := st.InsertCompiledRun(ctx, req3); err != nil {
		t.Fatalf("enqueue with claim: %v", err)
	}
	replay := InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), WebhookClaim: claim}
	if err := st.InsertCompiledRun(ctx, replay); !errors.Is(err, ErrDeliveryDuplicate) {
		t.Fatalf("duplicate delivery = %v, want ErrDeliveryDuplicate", err)
	}
	// An incomplete claim fails.
	badClaim := InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), WebhookClaim: &WebhookClaim{Forge: "", DeliveryID: "x", RunID: pgITNewID(t)}}
	if err := st.InsertCompiledRun(ctx, badClaim); err == nil {
		t.Fatal("incomplete webhook claim must fail")
	}

	// The schedule occurrence claim is part of the transaction.
	schedRun := pgITNewID(t)
	schedJob := pgITNewID(t)
	nominal := time.Now().UTC().Truncate(time.Microsecond)
	schedID := pgITNewID(t)
	if err := st.UpsertSchedule(ctx, Schedule{ID: schedID, Repository: "kiwi-it/repo", Spec: "@daily", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	schedClaim := &ScheduleClaim{ScheduleID: schedID, Nominal: nominal}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(schedRun, model.StatusQueued), Jobs: map[string]model.Job{schedJob: pgITJob(schedRun, schedJob, pgITRepo)}, ScheduleClaim: schedClaim}); err != nil {
		t.Fatalf("enqueue with schedule claim: %v", err)
	}
	lost := InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), ScheduleClaim: schedClaim}
	if err := st.InsertCompiledRun(ctx, lost); !errors.Is(err, ErrScheduleClaimLost) {
		t.Fatalf("lost schedule claim = %v, want ErrScheduleClaimLost", err)
	}
	// An empty schedule id fails the transaction.
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), ScheduleClaim: &ScheduleClaim{ScheduleID: "", Nominal: nominal}}); err == nil {
		t.Fatal("empty schedule id must fail")
	}

	// The downstream launch claim is resolved before the run insert.
	parentJob := pgITNewID(t)
	linkKey := parentJob + "\x00acme/child\x00main"
	if err := st.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: parentJob, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok"}); err != nil {
		t.Fatalf("insert link: %v", err)
	}
	childRun := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(childRun, model.StatusQueued), DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest}}); err != nil {
		t.Fatalf("enqueue downstream launch: %v", err)
	}
	// The same stable child replays as ErrDownstreamLaunched.
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(childRun, model.StatusQueued), DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest}}); !errors.Is(err, ErrDownstreamLaunched) {
		t.Fatalf("downstream replay = %v, want ErrDownstreamLaunched", err)
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: "malformed", StableChildID: memDigest}}); err == nil {
		t.Fatal("malformed launch claim must fail")
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: "short"}}); err == nil {
		t.Fatal("malformed stable child id must fail")
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: pgITNewID(t) + "\x00acme/none\x00main", StableChildID: memDigest}}); err == nil {
		t.Fatal("missing link must fail")
	}

	// Quota limits are enforced inside the transaction.
	quotaRun := pgITNewID(t)
	quotaJob := pgITNewID(t)
	key := "github.com/kiwi-it/repo"
	quota := &QuotaReservation{RepoKey: key, TeamKey: "github.com/kiwi-it", JobCount: 2}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(quotaRun, model.StatusQueued), Jobs: map[string]model.Job{quotaJob: pgITJob(quotaRun, quotaJob, pgITRepo)}, Quota: quota}); err != nil {
		t.Fatalf("quota enqueue: %v", err)
	}
	overDepth := &QuotaReservation{RepoKey: key, JobCount: 1, RepoQueueDepth: 1}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), Quota: overDepth}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("queue depth limit = %v, want ErrQuotaExceeded", err)
	}
	var qerr *QuotaExceededError
	if !errors.As(errors.New("x"), &qerr) && qerr != nil {
		t.Fatal("unreachable")
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), Quota: &QuotaReservation{RepoKey: key, RepoConcurrency: 1}}); err != nil {
		// running count is 0, so a repo concurrency of 1 admits the enqueue.
		t.Fatalf("repo concurrency admits when idle: %v", err)
	}
	// The typed limit error carries its reason and unwraps to the sentinel.
	teamRun := pgITNewID(t)
	teamJob := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:   pgITRun(teamRun, model.StatusQueued),
		Jobs:  map[string]model.Job{teamJob: pgITJob(teamRun, teamJob, pgITRepo)},
		Quota: &QuotaReservation{RepoKey: key, TeamKey: "github.com/kiwi-it", JobCount: 1, TeamQueueDepth: 1},
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("team queue depth limit = %v, want ErrQuotaExceeded", err)
	} else {
		var qe *QuotaExceededError
		if !errors.As(err, &qe) || qe.Reason != "TEAM_QUOTA" {
			t.Fatalf("quota error = %#v", err)
		}
	}
}

func TestPostgresIntegrationCompleteJobBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 1, 1)

	if err := st.CompleteJob(ctx, "bad", 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{}); err == nil {
		t.Fatal("invalid job id must fail")
	}
	if err := st.CompleteJob(ctx, jobID, -1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{}); err == nil {
		t.Fatal("negative generation must fail")
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 2, RunnerID: runnerID}); err == nil {
		t.Fatal("mismatched receipt must fail")
	}
	missingID := pgITNewID(t)
	if err := st.CompleteJob(ctx, missingID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: missingID, Generation: 1, RunnerID: runnerID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job = %v", err)
	}

	// Complete a leased job; the runner slot and run status move with it.
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	if err := st.CompleteJob(ctx, jobID, 2, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 2, RunnerID: runnerID}); !errors.Is(err, ErrGenerationMismatch) {
		t.Fatalf("stale generation = %v", err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "h"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "1"}, receipt); err != nil {
		t.Fatalf("Completion: %v", err)
	}
	// A replay of the exact completion is idempotent.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("completion replay: %v", err)
	}
	// A different runner for a terminal job is a generation mismatch.
	otherRunner := pgITNewID(t)
	if err := st.CompleteJob(ctx, jobID, 1, otherRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: otherRunner}); !errors.Is(err, ErrGenerationMismatch) {
		t.Fatalf("foreign runner completion = %v", err)
	}
	got, _ := st.GetJob(ctx, jobID)
	if got.Status != model.StatusSuccess || got.Outputs["o"] != "1" || got.LeaseRunnerID != "" {
		t.Fatalf("completed job = %+v", got)
	}
	run, _ := st.GetRun(ctx, runID)
	if run.Status != model.StatusSuccess {
		t.Fatalf("run after completion = %+v", run)
	}
	runner, _ := st.GetRunner(ctx, runnerID)
	if runner.Completed != 1 || len(runner.ActiveJobs) != 0 {
		t.Fatalf("runner after completion = %+v", runner)
	}

	// A required artifact missing rolls the completion back.
	reqRun := pgITNewID(t)
	reqJob := pgITNewID(t)
	pgITEnqueueOne(t, st, reqRun, reqJob, pgITRepo)
	if err := st.InsertJobContracts(ctx, reqJob, map[string]ArtifactContract{"bundle": {Name: "bundle", Required: true}}); err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: reqJob, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease required: %v", err)
	}
	blocked := model.CompletionReceipt{JobID: reqJob, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, reqJob, 1, runnerID, model.StatusSuccess, "", nil, blocked); !errors.Is(err, ErrRequiredArtifactMissing) {
		t.Fatalf("required artifact = %v, want ErrRequiredArtifactMissing", err)
	}
	// The failed completion left the job running.
	stillRunning, _ := st.GetJob(ctx, reqJob)
	if stillRunning.Status != model.StatusRunning {
		t.Fatalf("required-artifact failure must leave the job running: %+v", stillRunning)
	}

	// A non-terminal status is coerced to failure.
	if err := st.CompleteJob(ctx, reqJob, 1, runnerID, model.StatusQueued, "boom", nil, blocked); err != nil {
		t.Fatalf("coerced completion: %v", err)
	}
	got, _ = st.GetJob(ctx, reqJob)
	if got.Status != model.StatusFailure || got.Error != "boom" {
		t.Fatalf("coerced completion job = %+v", got)
	}
}

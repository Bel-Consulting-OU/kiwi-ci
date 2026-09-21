package storage

// Real-PostgreSQL integration coverage for the bounded recovery discovery
// queries (RecoveryDiscoveryStore): deterministic id-ordered keyset paging,
// the queue_deadline column stamped by the canonical job writes, the legacy
// compiled-payload fallback for rows whose column is NULL, and the tolerant
// skip of individually undecodable payloads.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITRecoveryJob builds a minimal job with a valid run FK target.
func pgITRecoveryJob(runID, jobID string, status model.Status) model.Job {
	return model.Job{ID: jobID, RunID: runID, Key: "build", Status: status, CreatedAt: time.Now().UTC()}
}

// pgITRecoveryPage collects one full id-ordered page walk (pages of 2) and
// asserts the cursor is strictly increasing, so the caller only checks ids.
func pgITRecoveryPage(t *testing.T, fetch func(afterID string) ([]model.Job, error)) []string {
	t.Helper()
	var got []string
	afterID := ""
	for {
		page, err := fetch(afterID)
		if err != nil {
			t.Fatalf("page after %q: %v", afterID, err)
		}
		for _, j := range page {
			if afterID != "" && j.ID <= afterID {
				t.Fatalf("cursor not strictly increasing: %q after %q", j.ID, afterID)
			}
			got = append(got, j.ID)
			afterID = j.ID
		}
		if len(page) < 2 {
			return got
		}
	}
}

func TestPostgresIntegrationRecoveryScanDiscoveryPagesDeterministically(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	ctx := context.Background()

	runID := pgITNewID(t)
	if err := st.InsertRun(ctx, model.Run{ID: runID, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("insert run: %v", err)
	}
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	live := now.Add(time.Minute)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	runningExpired := pgITNewID(t)
	runningLive := pgITNewID(t)
	runningNoExpiry := pgITNewID(t)
	terminalExpired := pgITNewID(t)
	queuedPast := pgITNewID(t)
	queuedFuture := pgITNewID(t)
	waitingPast := pgITNewID(t)
	cancelledPast := pgITNewID(t)
	legacyFallback := pgITNewID(t)

	seed := []model.Job{
		{ID: runningExpired, RunID: runID, Key: "build", Status: model.StatusRunning, CreatedAt: now, LeaseExpiresAt: &expired},
		{ID: runningLive, RunID: runID, Key: "build", Status: model.StatusRunning, CreatedAt: now, LeaseExpiresAt: &live},
		{ID: runningNoExpiry, RunID: runID, Key: "build", Status: model.StatusRunning, CreatedAt: now},
		{ID: terminalExpired, RunID: runID, Key: "build", Status: model.StatusFailure, CreatedAt: now, LeaseExpiresAt: &expired},
		{ID: queuedPast, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now, QueueDeadline: &past},
		{ID: queuedFuture, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now, QueueDeadline: &future},
		{ID: waitingPast, RunID: runID, Key: "build", Status: model.StatusWaitingApproval, CreatedAt: now, QueueDeadline: &past},
		{ID: cancelledPast, RunID: runID, Key: "build", Status: model.StatusCancelled, CreatedAt: now, QueueDeadline: &past},
		{
			// Pre-QueueDeadline persist: the deadline lives only in the
			// compiled payload, so the queue_deadline column stays NULL and
			// the query's payload fallback must find it.
			ID: legacyFallback, RunID: runID, Key: "build", Status: model.StatusQueued,
			CreatedAt: now.Add(-2 * time.Hour),
			CompiledJobPayload: &model.CompiledJobPayload{
				EffectiveJob: json.RawMessage(`{"job":{"queue_timeout":"5m"}}`),
			},
		},
	}
	for _, j := range seed {
		if err := st.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert job %s: %v", j.ID, err)
		}
	}

	// A row whose payload is undecodable but whose id may sort before valid
	// candidates must be skipped without failing the page.
	corruptID := "00000000000000000000000000000000"
	if _, err := st.pool.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, attempts, lease_runner_id, lease_generation, lease_expires_at, created_at, queue_deadline, payload) VALUES ($1, $2, 'build', 'running', 1, 'runner-x', 1, $3, $4, $3, '"scalar"'::jsonb)`,
		corruptID, runID, expired, now); err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}
	// A row with an elapsed payload deadline but a NULL column (payload
	// written outside the canonical job path) must still be discovered.
	staleColumn := pgITNewID(t)
	stale := pgITRecoveryJob(runID, staleColumn, model.StatusQueued)
	stale.QueueDeadline = &past
	if err := st.InsertJob(ctx, stale); err != nil {
		t.Fatalf("insert stale-column job: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET queue_deadline=NULL WHERE id=$1`, staleColumn); err != nil {
		t.Fatalf("null column: %v", err)
	}

	leaseIDs := pgITRecoveryPage(t, func(afterID string) ([]model.Job, error) {
		return st.ListExpiredRunningJobs(ctx, now, afterID, 2)
	})
	if len(leaseIDs) != 2 || !pgITSameSet(leaseIDs, runningExpired, runningNoExpiry) {
		t.Fatalf("expired-lease candidates = %v, want [%s %s] (corrupt %s skipped)", leaseIDs, runningExpired, runningNoExpiry, corruptID)
	}

	queueIDs := pgITRecoveryPage(t, func(afterID string) ([]model.Job, error) {
		return st.ListQueueTimedOutJobs(ctx, now, afterID, 2)
	})
	if len(queueIDs) != 4 || !pgITSameSet(queueIDs, queuedPast, waitingPast, legacyFallback, staleColumn) {
		t.Fatalf("queue candidates = %v, want [%s %s %s %s]", queueIDs, queuedPast, waitingPast, legacyFallback, staleColumn)
	}

	// The canonical job write stamped the derived column for the persisted
	// deadline rows (the legacy row stays NULL by design).
	var columnDeadline *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT queue_deadline FROM jobs WHERE id=$1`, queuedPast).Scan(&columnDeadline); err != nil {
		t.Fatalf("read column: %v", err)
	}
	if columnDeadline == nil || !columnDeadline.Equal(past) {
		t.Fatalf("queue_deadline column = %v, want %v", columnDeadline, past)
	}
	var legacyColumn *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT queue_deadline FROM jobs WHERE id=$1`, legacyFallback).Scan(&legacyColumn); err != nil {
		t.Fatalf("read legacy column: %v", err)
	}
	if legacyColumn != nil {
		t.Fatalf("legacy row column = %v, want NULL", legacyColumn)
	}

	// limit <= 0 is an explicit no-op.
	if page, err := st.ListExpiredRunningJobs(ctx, now, "", 0); err != nil || len(page) != 0 {
		t.Fatalf("limit 0 = %d/%v, want empty/nil", len(page), err)
	}
	if page, err := st.ListQueueTimedOutJobs(ctx, now, "", 0); err != nil || len(page) != 0 {
		t.Fatalf("queue limit 0 = %d/%v, want empty/nil", len(page), err)
	}
}

// pgITSameSet reports whether got is exactly the given id set (order-free).
func pgITSameSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, id := range want {
		if !seen[id] {
			return false
		}
	}
	return true
}

// TestPostgresIntegrationRecoveryQueueDeadlineMigration pins the 0021-0025
// upgrade path on a database that already holds queued jobs: the ADD COLUMN +
// backfill seeds the derived queue_deadline from persisted payload values
// (guarding malformed ones to NULL), both partial indexes are created, and
// the backfilled elapsed row is immediately discoverable.
func TestPostgresIntegrationRecoveryQueueDeadlineMigration(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()
	pgITApplyThrough(t, st, 20)

	runID := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload) VALUES ($1, 'queued', now(), '{}'::jsonb)`, runID); err != nil {
		t.Fatalf("insert run at v20: %v", err)
	}
	backfilled := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, created_at, payload) VALUES ($1, $2, 'build', 'queued', now() - interval '1 hour', $3::jsonb)`,
		backfilled, runID, `{"queue_deadline":"2000-01-01T00:00:00Z"}`); err != nil {
		t.Fatalf("insert backfill row: %v", err)
	}
	guarded := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, created_at, payload) VALUES ($1, $2, 'build', 'queued', now() - interval '1 hour', $3::jsonb)`,
		guarded, runID, `{"queue_deadline":123}`); err != nil {
		t.Fatalf("insert malformed-deadline row: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over v20 with data: %v", err)
	}
	wantVersion := pgITLatestVersion(t)
	if v, err := st.SchemaVersion(ctx); err != nil || v != wantVersion {
		t.Fatalf("SchemaVersion = %d/%v, want %d", v, err, wantVersion)
	}

	var deadline *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT queue_deadline FROM jobs WHERE id=$1`, backfilled).Scan(&deadline); err != nil {
		t.Fatalf("read backfilled column: %v", err)
	}
	want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if deadline == nil || !deadline.Equal(want) {
		t.Fatalf("backfilled queue_deadline = %v, want %v", deadline, want)
	}
	var guardedDeadline *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT queue_deadline FROM jobs WHERE id=$1`, guarded).Scan(&guardedDeadline); err != nil {
		t.Fatalf("read guarded column: %v", err)
	}
	if guardedDeadline != nil {
		t.Fatalf("malformed deadline row column = %v, want NULL", guardedDeadline)
	}

	var indexes int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN ('jobs_running_lease_recovery_idx','jobs_queue_deadline_recovery_idx')`).Scan(&indexes); err != nil {
		t.Fatalf("count indexes: %v", err)
	}
	if indexes != 2 {
		t.Fatalf("recovery indexes = %d, want 2", indexes)
	}

	// The backfilled elapsed row is a discovery candidate right away; the
	// malformed one is not (its column stayed NULL and it has no legacy
	// compiled-payload timeout either).
	page, err := st.ListQueueTimedOutJobs(ctx, time.Now().UTC(), "", 10)
	if err != nil {
		t.Fatalf("ListQueueTimedOutJobs: %v", err)
	}
	var ids []string
	for _, j := range page {
		ids = append(ids, j.ID)
	}
	if !pgITSameSet(ids, backfilled) {
		t.Fatalf("queue candidates after migration = %v, want [%s]", ids, backfilled)
	}
}

package storage

// Real-PostgreSQL integration tests for the bounded queued-candidate page
// (QueuedJobPageStore). Gated on KIWI_TEST_POSTGRES_URL like the other
// integration tests: skipped when the variable is unset and in -short mode.
//
// The tests pin the properties the scheduler's page walk relies on: a walk
// over many pages returns every eligible queued job exactly once in the aged
// order (priority + wait/10min DESC, created_at ASC, id ASC), the page count
// is bounded by the limit, HasMore/Last are exact, and the persisted
// queue_deadline pushdown excludes elapsed rows.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBulkInsertQueuedJobs seeds queued job rows with ONE statement (the same
// rows InsertJob writes: the jsonMarshal payload and the relational columns).
func pgITBulkInsertQueuedJobs(t *testing.T, st *PostgresStore, runID string, jobs []model.Job) {
	t.Helper()
	if len(jobs) == 0 {
		return
	}
	ids := make([]string, len(jobs))
	priorities := make([]int32, len(jobs))
	created := make([]string, len(jobs))
	deadlines := make([]string, len(jobs))
	payloads := make([]string, len(jobs))
	for i, j := range jobs {
		if err := ValidateJobID(j.ID); err != nil {
			t.Fatalf("bulk insert job %d: %v", i, err)
		}
		p, err := jsonMarshal(j)
		if err != nil {
			t.Fatalf("bulk insert job %d marshal: %v", i, err)
		}
		ids[i] = j.ID
		priorities[i] = int32(j.Priority)
		created[i] = j.CreatedAt.UTC().Format(time.RFC3339Nano)
		if j.QueueDeadline != nil {
			deadlines[i] = j.QueueDeadline.UTC().Format(time.RFC3339Nano)
		}
		payloads[i] = string(p)
	}
	_, err := st.pool.Exec(context.Background(), `
		INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, created_at, queue_deadline, payload)
		SELECT u.id, $1, 'build', 'queued', 'success', u.priority, 0,
		       u.created_at::timestamptz, NULLIF(u.queue_deadline,'')::timestamptz, u.payload::jsonb
		FROM unnest($2::text[], $3::int[], $4::text[], $5::text[], $6::text[])
		     AS u(id, priority, created_at, queue_deadline, payload)`,
		runID, ids, priorities, created, deadlines, payloads)
	if err != nil {
		t.Fatalf("bulk insert %d jobs: %v", len(jobs), err)
	}
}

// TestPostgresIntegrationQueuedJobsPageBoundedWalk walks a real queue in
// seven-row pages: every eligible job appears exactly once, the walk order
// equals the full aged sort, boundaries are exact, and an elapsed persisted
// queue deadline is pushed out while a future one stays.
func TestPostgresIntegrationQueuedJobsPageBoundedWalk(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

	const total = 120
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	jobs := make([]model.Job, 0, total+2)
	for i := 0; i < total; i++ {
		jobs = append(jobs, model.Job{
			ID:        fmt.Sprintf("%032x", i+1),
			RunID:     runID,
			Key:       "build",
			Status:    model.StatusQueued,
			Priority:  i % 5,
			CreatedAt: now.Add(-time.Duration(i) * time.Minute),
		})
	}
	pastID := fmt.Sprintf("%032x", total+1)
	futureID := fmt.Sprintf("%032x", total+2)
	jobs = append(jobs,
		model.Job{ID: pastID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past},
		model.Job{ID: futureID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &future},
	)
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)

	// The expected walk is the full aged sort of the eligible rows (the
	// elapsed-deadline row excluded; the future one included).
	expectedJobs := make([]model.Job, 0, total+1)
	for _, j := range jobs {
		if j.ID == pastID {
			continue
		}
		expectedJobs = append(expectedJobs, j)
	}
	sortQueuedJobsAged(expectedJobs, now)
	expected := make([]string, 0, len(expectedJobs))
	for _, j := range expectedJobs {
		expected = append(expected, j.ID)
	}

	const pageSize = 7
	var seen []string
	var after *QueuedJobCursor
	pages := 0
	for {
		page, err := st.ListQueuedJobsPage(ctx, after, pageSize, now)
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		pages++
		wantLen := pageSize
		if remaining := len(expected) - len(seen); remaining < wantLen {
			wantLen = remaining
		}
		if len(page.Jobs) != wantLen {
			t.Fatalf("page %d returned %d jobs, want %d", pages, len(page.Jobs), wantLen)
		}
		for _, j := range page.Jobs {
			seen = append(seen, j.ID)
		}
		if page.HasMore != (len(seen) < len(expected)) {
			t.Fatalf("page %d HasMore = %v with %d/%d seen", pages, page.HasMore, len(seen), len(expected))
		}
		if len(page.Jobs) > 0 {
			last := page.Jobs[len(page.Jobs)-1]
			if page.Last.ID != last.ID || page.Last.AgedPriority != queuedJobAgedPriority(last, now) || !page.Last.CreatedAt.Equal(last.CreatedAt) {
				t.Fatalf("page %d Last = %+v, want cursor of %s", pages, page.Last, last.ID)
			}
		}
		if !page.HasMore {
			break
		}
		cursor := page.Last
		after = &cursor
	}
	if pages != len(expected)/pageSize+1 {
		t.Fatalf("pages = %d, want %d", pages, len(expected)/pageSize+1)
	}
	for i, id := range seen {
		if id != expected[i] {
			t.Fatalf("walk[%d] = %s, want %s", i, id, expected[i])
		}
	}
	seenIDs := map[string]bool{}
	for _, id := range seen {
		if seenIDs[id] {
			t.Fatalf("duplicate job %s in the walk", id)
		}
		seenIDs[id] = true
	}
	if seenIDs[pastID] {
		t.Fatal("elapsed persisted deadline was returned as a candidate")
	}
	if !seenIDs[futureID] {
		t.Fatal("future deadline candidate missing from the walk")
	}

	// A page strictly after the final cursor is empty and terminal.
	page, err := st.ListQueuedJobsPage(ctx, &QueuedJobCursor{
		AgedPriority: queuedJobAgedPriority(expectedJobs[len(expectedJobs)-1], now),
		CreatedAt:    expectedJobs[len(expectedJobs)-1].CreatedAt,
		ID:           expectedJobs[len(expectedJobs)-1].ID,
	}, pageSize, now)
	if err != nil {
		t.Fatalf("terminal page: %v", err)
	}
	if len(page.Jobs) != 0 || page.HasMore {
		t.Fatalf("terminal page = %d jobs (hasMore=%v), want empty terminal", len(page.Jobs), page.HasMore)
	}
}

// TestPostgresIntegrationQueuedJobsPageMemoryParity runs the same seed and
// cursor walk against memStore and PostgresStore and requires identical
// page contents and boundaries.
func TestPostgresIntegrationQueuedJobsPageMemoryParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	pgITBulkInsertRuns(t, st, []model.Run{{ID: runID, Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Hour)}})

	const total = 25
	jobs := make([]model.Job, 0, total)
	for i := 0; i < total; i++ {
		jobs = append(jobs, model.Job{
			ID:        fmt.Sprintf("%032x", i+1),
			RunID:     runID,
			Key:       "build",
			Status:    model.StatusQueued,
			Priority:  i % 3,
			CreatedAt: now.Add(-time.Duration(i) * 30 * time.Second),
		})
	}
	pgITBulkInsertQueuedJobs(t, st, runID, jobs)
	mem := newMemStore()
	for _, j := range jobs {
		if err := mem.InsertJob(ctx, j); err != nil {
			t.Fatalf("mem seed: %v", err)
		}
	}
	var after *QueuedJobCursor
	for page := 1; ; page++ {
		pgPage, err := st.ListQueuedJobsPage(ctx, after, 4, now)
		if err != nil {
			t.Fatalf("pg page %d: %v", page, err)
		}
		memPage, err := mem.ListQueuedJobsPage(ctx, after, 4, now)
		if err != nil {
			t.Fatalf("mem page %d: %v", page, err)
		}
		// The cursor's CreatedAt must be compared with time.Equal: pgx
		// returns a fixed +00 zone while the memory store keeps UTC, and a
		// struct/slice comparison would reject two identical instants.
		lastEqual := pgPage.Last.AgedPriority == memPage.Last.AgedPriority &&
			pgPage.Last.ID == memPage.Last.ID &&
			pgPage.Last.CreatedAt.Equal(memPage.Last.CreatedAt)
		if len(pgPage.Jobs) != len(memPage.Jobs) || pgPage.HasMore != memPage.HasMore || !lastEqual {
			t.Fatalf("page %d differs: pg %d/%v/%+v mem %d/%v/%+v",
				page, len(pgPage.Jobs), pgPage.HasMore, pgPage.Last, len(memPage.Jobs), memPage.HasMore, memPage.Last)
		}
		for i := range pgPage.Jobs {
			if pgPage.Jobs[i].ID != memPage.Jobs[i].ID {
				t.Fatalf("page %d row %d: pg %s mem %s", page, i, pgPage.Jobs[i].ID, memPage.Jobs[i].ID)
			}
		}
		if !pgPage.HasMore {
			break
		}
		cursor := pgPage.Last
		after = &cursor
	}
}

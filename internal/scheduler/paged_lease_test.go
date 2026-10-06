package scheduler

// Bounded paged lease-scan tests: a store implementing
// storage.QueuedJobPageStore must be scanned in keyset pages (never through
// the whole-queue ListQueuedJobs path), the page budget must be enforced, and
// the reservation rule must still apply on the legacy fallback.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pagedFakeStore wraps resourceFakeStore with a recording implementation of
// storage.QueuedJobPageStore. Its ListQueuedJobs PANICS: a scheduler that
// claims the page contract must never materialize the whole queue.
type pagedFakeStore struct {
	*resourceFakeStore

	mu              sync.Mutex
	pagesRequested  int
	jobsReturned    int
	wholeQueueCalls int
}

var _ storage.QueuedJobPageStore = (*pagedFakeStore)(nil)

func newPagedFakeStore() *pagedFakeStore {
	return &pagedFakeStore{resourceFakeStore: newResourceFakeStore()}
}

// ListQueuedJobs proves the whole-queue path is never taken: the paged
// scheduler path must use ListQueuedJobsPage alone.
func (p *pagedFakeStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	p.mu.Lock()
	p.wholeQueueCalls++
	p.mu.Unlock()
	panic("paged store: scheduler used the whole-queue ListQueuedJobs path")
}

// ListQueuedJobsPage mirrors the store contract: aged order (priority +
// wait/10min DESC, created_at ASC, id ASC), strict keyset cursor, limit+1
// fetched for an exact HasMore, and a Last cursor naming the last returned
// job.
func (p *pagedFakeStore) ListQueuedJobsPage(ctx context.Context, after *storage.QueuedJobCursor, limit int, now time.Time) (storage.QueuedJobPage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pagesRequested++
	eligible := make([]model.Job, 0, len(p.fakeStore.jobs))
	for _, j := range p.fakeStore.jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		if j.QueueDeadline != nil && !j.QueueDeadline.After(now) {
			continue
		}
		if after != nil && !pagedJobAfterCursor(j, *after, now) {
			continue
		}
		eligible = append(eligible, j)
	}
	orderQueuedJobs(eligible, now)
	page := storage.QueuedJobPage{Jobs: eligible}
	if len(eligible) > limit {
		page.Jobs = eligible[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = storage.QueuedJobCursor{
			AgedPriority: agedPriority(last, now),
			CreatedAt:    last.CreatedAt,
			ID:           last.ID,
		}
	}
	p.jobsReturned += len(page.Jobs)
	return page, nil
}

func pagedJobAfterCursor(j model.Job, c storage.QueuedJobCursor, now time.Time) bool {
	ap := agedPriority(j, now)
	if ap != c.AgedPriority {
		return ap < c.AgedPriority
	}
	if !j.CreatedAt.Equal(c.CreatedAt) {
		return j.CreatedAt.After(c.CreatedAt)
	}
	return j.ID > c.ID
}

// pagedLeaseStore builds the scheduler over the paged wrapper after seeding
// through the same fixture the resource tests use.
func pagedLeaseStore(t *testing.T, p *pagedFakeStore, runnerID string, now time.Time, jobs ...model.Job) *DBScheduler {
	t.Helper()
	seedResourceScheduler(t, p.resourceFakeStore, runnerID, 8, model.ResourceCapacity{}, jobs...)
	s := NewDB(p, time.Minute, nil, nil)
	if !s.IsLeader(context.Background()) {
		t.Fatal("not leader")
	}
	return s
}

// TestSchedulerLeaseUsesBoundedPages seeds 1000 label-ineligible jobs and a
// 25-row budget: Lease must materialize at most 25 jobs (3 pages of 10/10/5)
// and never touch the whole-queue path.
func TestSchedulerLeaseUsesBoundedPages(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 1000)
	for i := 0; i < 1000; i++ {
		jobs = append(jobs, model.Job{
			ID:             fmt.Sprintf("job-%04d", i),
			Priority:       i % 4,
			RequiredLabels: []string{"never"},
			CreatedAt:      base.Add(time.Duration(i) * time.Millisecond),
		})
	}
	runnerID := "runner-paged-bound"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(10, 25, 0)

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease = %v, want ErrNoJobs (no job matches the runner)", err)
	}
	p.mu.Lock()
	pages, returned := p.pagesRequested, p.jobsReturned
	p.mu.Unlock()
	if returned != 25 {
		t.Fatalf("jobs materialized = %d, want exactly the 25-row budget", returned)
	}
	if pages != 3 {
		t.Fatalf("pages requested = %d, want 3", pages)
	}
}

// TestSchedulerLeaseFindsCandidateAcrossPages places the only eligible job
// after the first page: the walk must follow the keyset cursor to find and
// claim it.
func TestSchedulerLeaseFindsCandidateAcrossPages(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 13)
	for i := 0; i < 12; i++ {
		jobs = append(jobs, model.Job{
			ID:             fmt.Sprintf("job-old-%02d", i),
			Priority:       10,
			RequiredLabels: []string{"never"},
			CreatedAt:      base.Add(time.Duration(i) * time.Millisecond),
		})
	}
	jobs = append(jobs, model.Job{ID: "job-target", CreatedAt: now.Add(-time.Minute)})
	runnerID := "runner-paged-across"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(5, 50, 0)

	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("lease across pages: %v", err)
	}
	if j.ID != "job-target" {
		t.Fatalf("leased %s, want job-target (third page)", j.ID)
	}
	p.mu.Lock()
	pages := p.pagesRequested
	p.mu.Unlock()
	if pages != 3 {
		t.Fatalf("pages requested = %d, want 3 (5+5+3)", pages)
	}
}

// TestSchedulerLeaseFallsBackWithoutPageStore proves a store without the page
// contract still leases through the whole-queue fallback, and that the
// reservation rule applies there too.
func TestSchedulerLeaseFallsBackWithoutPageStore(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	if _, ok := storage.Store(st).(storage.QueuedJobPageStore); ok {
		t.Fatal("fixture bug: resourceFakeStore unexpectedly implements QueuedJobPageStore")
	}
	runnerID := "runner-fallback"
	now := time.Now().UTC()
	jobs := append([]model.Job{{
		ID: "job-big", CPURequest: 8, CreatedAt: now.Add(-2 * time.Hour),
	}}, seedFragmentationBackfill(now, 3, 1, 0)...)
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8}, jobs...)
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{CPU: 7}
	st.mu.Unlock()

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("fallback lease = %v, want ErrNoJobs (reservation rule applies without pages)", err)
	}
	if st.claimCount() != 0 {
		t.Fatalf("fallback attempted %d claims, want 0", st.claimCount())
	}
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{}
	st.mu.Unlock()
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("fallback lease after release: %v", err)
	}
	if j.ID != "job-big" {
		t.Fatalf("leased %s, want job-big", j.ID)
	}
}

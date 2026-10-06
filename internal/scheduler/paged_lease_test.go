package scheduler

// Bounded paged lease-scan tests: a store implementing
// storage.QueuedJobPageStore must be scanned in keyset pages (never through
// the whole-queue ListQueuedJobs path), the page budget must be enforced, the
// runner-coarse filter must be honored by the page read, and the per-runner
// continuation cursor must let a long prefix of rows that pass the filter but
// fail the Go gates (deadlines, dependencies, environment/policy
// concurrency) make progress instead of being re-scanned on every poll.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
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

// ListQueuedJobsPage mirrors the store contract: the SAME runner-coarse
// filter predicate the SQL path and the in-memory store apply
// (storage.QueuedJobMatchesFilter), aged order (priority + wait/10min DESC,
// created_at ASC, id ASC), strict keyset cursor, limit+1 fetched for an exact
// HasMore, and a Last cursor naming the last returned job.
func (p *pagedFakeStore) ListQueuedJobsPage(ctx context.Context, filter storage.QueuedJobFilter, after *storage.QueuedJobCursor, limit int, now time.Time) (storage.QueuedJobPage, error) {
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
		if !storage.QueuedJobMatchesFilter(j, filter) {
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

// TestRunnerQueuedJobFilterMapping pins the filter construction: the
// legacy-unrestricted runner passes nil Runtimes (every runtime), an enforced
// runner passes a non-nil copy of its capabilities (an enforced empty set
// matches nothing), RunnerLabels is always non-nil (empty for a label-less
// runner) and sorted, and region/capacity/cgroup ride along verbatim.
func TestRunnerQueuedJobFilterMapping(t *testing.T) {
	legacy := runnerQueuedJobFilter(model.Runner{})
	if legacy.Runtimes != nil {
		t.Fatalf("legacy filter Runtimes = %v, want nil (unrestricted)", legacy.Runtimes)
	}
	if legacy.RunnerLabels == nil || len(legacy.RunnerLabels) != 0 {
		t.Fatalf("legacy filter labels = %#v, want a non-nil empty slice", legacy.RunnerLabels)
	}

	enforcedEmpty := runnerQueuedJobFilter(model.Runner{CapabilitiesEnforced: true})
	if enforcedEmpty.Runtimes == nil || len(enforcedEmpty.Runtimes) != 0 {
		t.Fatalf("enforced empty caps = %#v, want a non-nil empty slice (deny all)", enforcedEmpty.Runtimes)
	}

	full := runnerQueuedJobFilter(model.Runner{
		Capabilities:         []string{"tart", "native"},
		CapabilitiesEnforced: true,
		Labels:               []string{"os:linux", "container"},
		Region:               "east",
		ResourceCapacity:     model.ResourceCapacity{CPU: 4, Memory: 8 << 30},
		JobCgroup:            true,
	})
	if len(full.Runtimes) != 2 || full.Runtimes[0] != "tart" || full.Runtimes[1] != "native" {
		t.Fatalf("runtimes = %v, want the capability copy", full.Runtimes)
	}
	if len(full.RunnerLabels) != 2 || full.RunnerLabels[0] != "container" || full.RunnerLabels[1] != "os:linux" {
		t.Fatalf("labels = %v, want the sorted copy", full.RunnerLabels)
	}
	if full.RunnerRegion != "east" || full.MaxRequested.CPU != 4 || full.MaxRequested.Memory != 8<<30 || !full.IgnoreServiceEnvelope {
		t.Fatalf("filter = %+v, want region/capacity/cgroup carried", full)
	}
}

// TestSetLeaseScanLimitsClampsHardCap proves a library caller cannot install
// an unbounded candidate row budget: values above MaxCandidateRowsCap are
// clamped, and the built-in defaults still apply to non-positive inputs.
func TestSetLeaseScanLimitsClampsHardCap(t *testing.T) {
	s := &DBScheduler{}
	s.SetLeaseScanLimits(0, MaxCandidateRowsCap+1000, 0)
	pageSize, maxRows, wait := s.leaseScanLimits()
	if pageSize != DefaultCandidatePageSize {
		t.Fatalf("page size = %d, want default %d", pageSize, DefaultCandidatePageSize)
	}
	if maxRows != MaxCandidateRowsCap {
		t.Fatalf("max rows = %d, want the hard cap %d", maxRows, MaxCandidateRowsCap)
	}
	if wait != 0 {
		t.Fatalf("reservation wait = %v, want 0", wait)
	}
	s.SetLeaseScanLimits(0, 0, 0)
	if _, maxRows, _ = s.leaseScanLimits(); maxRows != DefaultMaxCandidateRows {
		t.Fatalf("non-positive max rows = %d, want default %d", maxRows, DefaultMaxCandidateRows)
	}
}

// scanCursorFor reads one runner's continuation state for assertions.
func scanCursorFor(s *DBScheduler, runnerID string) (storage.QueuedJobCursor, bool) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	st, ok := s.scan[runnerID]
	return st.after, ok
}

// pagedReturned snapshots the fake's cumulative returned-row counter.
func pagedReturned(p *pagedFakeStore) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jobsReturned
}

// dependencyBlockedJob builds a queued job that PASSES the runner-coarse
// filter (no runtime/label/region/capacity incompatibility) but can never be
// leased by the Go walk: its dependency does not exist, so the dependency
// gate resolves it to a failed outcome. These rows are exactly the ones the
// per-runner continuation cursor exists for — the SQL pushdown cannot skip
// them, and without a cursor they would be re-scanned from the head forever.
func dependencyBlockedJob(id string, createdAt time.Time) model.Job {
	return model.Job{ID: id, Key: id, Needs: []string{"missing-dep"}, CreatedAt: createdAt}
}

// runtimeJob builds a job whose compiled payload declares the given runtime.
// The payload carries the non-enforced effective policy a real compiled
// payload always has, so the fail-closed missing-policy contract does not
// decide the fixture.
func runtimeJob(id, runtime string, createdAt time.Time) model.Job {
	eff, _ := json.Marshal(map[string]any{"job": map[string]any{"runtime": runtime}})
	return model.Job{ID: id, Key: id, CreatedAt: createdAt,
		CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1, EffectiveJob: json.RawMessage(eff), EffectivePolicy: policy.Capabilities{Enforced: false}}}
}

// TestSchedulerLeaseUsesBoundedPages seeds 1000 rows that pass the coarse
// filter but fail the Go dependency gate and a 25-row budget: Lease must
// materialize at most 25 jobs (3 pages of 10/10/5) and never touch the
// whole-queue path.
func TestSchedulerLeaseUsesBoundedPages(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 1000)
	for i := 0; i < 1000; i++ {
		j := dependencyBlockedJob(fmt.Sprintf("job-%04d", i), base.Add(time.Duration(i)*time.Millisecond))
		j.Priority = i % 4
		jobs = append(jobs, j)
	}
	runnerID := "runner-paged-bound"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(10, 25, 0)

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease = %v, want ErrNoJobs (no job passes the dependency gate)", err)
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
		j := dependencyBlockedJob(fmt.Sprintf("job-old-%02d", i), base.Add(time.Duration(i)*time.Millisecond))
		j.Priority = 10
		jobs = append(jobs, j)
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

// TestSchedulerFallbackFilterApplied proves the whole-queue fallback applies
// the ONE shared coarse matcher before ordering: a runner with no labels must
// never lease a label-requiring job (and, with the compatible job behind it,
// must lease the compatible one).
func TestSchedulerFallbackFilterApplied(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	if _, ok := storage.Store(st).(storage.QueuedJobPageStore); ok {
		t.Fatal("fixture bug: resourceFakeStore unexpectedly implements QueuedJobPageStore")
	}
	runnerID := "runner-fallback-filter"
	now := time.Now().UTC()
	jobs := []model.Job{
		{ID: "job-incompatible", Priority: 10, RequiredLabels: []string{"never"}, CreatedAt: now.Add(-2 * time.Hour)},
		{ID: "job-compatible", CreatedAt: now.Add(-time.Minute)},
	}
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{}, jobs...)

	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("fallback filtered lease: %v", err)
	}
	if j.ID != "job-compatible" {
		t.Fatalf("leased %s, want job-compatible", j.ID)
	}
	claim := st.lastClaim(t)
	if claim.JobID != "job-compatible" {
		t.Fatalf("claim = %s, want only the compatible candidate", claim.JobID)
	}
}

// TestSchedulerLeaseDoesNotStarveBehindIncompatiblePrefix: 4096 rows that the
// coarse filter cannot exclude (they are dependency-blocked, not
// label/runtime/region/capacity-incompatible — those are skipped by the page
// filter now) sit ahead of one compatible job with a 4096-row budget. The
// first poll exhausts the budget without a claim and records a continuation
// cursor; the second poll starts with the head window and then resumes BEHIND
// the scanned prefix, so it examines far fewer than 4096 rows before claiming
// the compatible job.
func TestSchedulerLeaseDoesNotStarveBehindIncompatiblePrefix(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 4097)
	for i := 0; i < 4096; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("job-blocked-%04d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	jobs = append(jobs, model.Job{ID: "job-target", CreatedAt: base.Add(4096 * time.Millisecond)})
	runnerID := "runner-paged-cursor"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(256, 4096, 0)

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("first lease = %v, want ErrNoJobs (budget exhausted before the target)", err)
	}
	if returned := pagedReturned(p); returned != 4096 {
		t.Fatalf("first scan materialized %d rows, want exactly the 4096-row budget", returned)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("first scan did not record a continuation cursor")
	}

	before := pagedReturned(p)
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("second lease: %v", err)
	}
	if j.ID != "job-target" {
		t.Fatalf("second lease took %s, want job-target", j.ID)
	}
	second := pagedReturned(p) - before
	if second >= 4096 {
		t.Fatalf("second scan materialized %d rows, want far fewer than 4096 (cursor must resume)", second)
	}
	// One head window plus the page holding the target.
	if second > 2*256+1 {
		t.Fatalf("second scan materialized %d rows, want the head window plus one page", second)
	}
	if _, ok := scanCursorFor(s, runnerID); ok {
		t.Fatal("a successful claim must clear the continuation cursor")
	}
}

// seedPagedRunner seeds one profile-linked runner into the shared paged fake.
func seedPagedRunner(t *testing.T, st *pagedFakeStore, runnerID string, profile model.RunnerProfile, reported []string) {
	t.Helper()
	ctx := context.Background()
	if profile.ID == "" {
		profile.ID = "prof-" + runnerID
	}
	if profile.MaxCapacity == 0 {
		profile.MaxCapacity = 8
	}
	if err := st.UpsertProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	if err := st.BindCertProfile(ctx, "serial-"+runnerID, profile.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: profile.MaxCapacity,
		CertSerial: "serial-" + runnerID, ReportedCapabilities: reported}); err != nil {
		t.Fatal(err)
	}
}

// TestSchedulerLeaseMixedRunnerClassesMakeProgress interleaves high-priority
// runtime-incompatible (container), label-incompatible and
// region-incompatible jobs with exactly one eligible job per runner class.
// Each runner (native, tart-capable, label-holding, region-matching) must
// lease its own job within a handful of polls with a small budget: the coarse
// filter excludes each blocker class at the store, so no runner's scan is
// pinned by another class's queue.
func TestSchedulerLeaseMixedRunnerClassesMakeProgress(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)

	nativeRunner, tartRunner, labelRunner, regionRunner := "runner-mixed-native", "runner-mixed-tart", "runner-mixed-label", "runner-mixed-region"
	seedPagedRunner(t, p, nativeRunner, model.RunnerProfile{Capabilities: []string{"native"}}, []string{"native"})
	seedPagedRunner(t, p, tartRunner, model.RunnerProfile{Capabilities: []string{"tart"}}, []string{"tart"})
	seedPagedRunner(t, p, labelRunner, model.RunnerProfile{Capabilities: []string{"native"}, Labels: []string{"gpu"}}, []string{"native"})
	seedPagedRunner(t, p, regionRunner, model.RunnerProfile{Capabilities: []string{"native"}, Region: "east"}, []string{"native"})

	// High-priority blockers: every class is incompatible with every OTHER
	// runner class (but not with its own matching runner).
	jobs := []model.Job{
		{ID: "block-label-0", Priority: 50, RequiredLabels: []string{"never"}, CreatedAt: base},
		runtimeJob("block-runtime-0", "container", base.Add(1*time.Millisecond)),
		{ID: "block-region-0", Priority: 49, PlacementRegions: []string{"west"}, CreatedAt: base.Add(2 * time.Millisecond)},
		{ID: "block-label-1", Priority: 48, RequiredLabels: []string{"never"}, CreatedAt: base.Add(3 * time.Millisecond)},
		{ID: "block-region-1", Priority: 47, PlacementRegions: []string{"west"}, CreatedAt: base.Add(4 * time.Millisecond)},
	}
	jobs[1].Priority = 50
	// One eligible job per runner class.
	jobs = append(jobs,
		model.Job{ID: "job-native", Priority: 1, CreatedAt: base.Add(10 * time.Millisecond)},
		runtimeJob("job-tart", "tart", base.Add(11*time.Millisecond)),
		model.Job{ID: "job-label", Priority: 1, RequiredLabels: []string{"gpu"}, CreatedAt: base.Add(12 * time.Millisecond)},
		model.Job{ID: "job-region", Priority: 1, PlacementRegions: []string{"east"}, CreatedAt: base.Add(13 * time.Millisecond)},
	)
	if err := p.InsertRun(ctx, model.Run{ID: "run-mixed", Status: model.StatusQueued, CreatedAt: base}); err != nil {
		t.Fatal(err)
	}
	for i, j := range jobs {
		j.RunID = "run-mixed"
		j.Status = model.StatusQueued
		if j.Key == "" {
			j.Key = fmt.Sprintf("mixed-%d", i)
		}
		if err := p.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert %s: %v", j.ID, err)
		}
	}
	s := NewDB(p, time.Minute, nil, nil)
	if !s.IsLeader(ctx) {
		t.Fatal("not leader")
	}
	s.SetLeaseScanLimits(16, 64, 0)

	want := map[string]string{
		nativeRunner: "job-native",
		tartRunner:   "job-tart",
		labelRunner:  "job-label",
		regionRunner: "job-region",
	}
	for _, runnerID := range []string{nativeRunner, tartRunner, labelRunner, regionRunner} {
		var leased *model.Job
		for poll := 0; poll < 3; poll++ {
			j, _, _, err := s.Lease(ctx, runnerID, now)
			if err != nil {
				if errors.Is(err, ErrNoJobs) {
					continue
				}
				t.Fatalf("%s poll %d: %v", runnerID, poll, err)
			}
			leased = j
			break
		}
		if leased == nil {
			t.Fatalf("%s never leased its eligible job within 3 polls", runnerID)
		}
		if leased.ID != want[runnerID] {
			t.Fatalf("%s leased %s, want %s", runnerID, leased.ID, want[runnerID])
		}
	}
}

// TestSchedulerLeaseHeadWindowSeesNewJobWhileResuming forces a continuation
// cursor behind a large dependency-blocked queue, then enqueues a new
// highest-priority compatible job: the next poll's HEAD WINDOW (fetched with
// after=nil) must find and claim it instead of only resuming the old scan.
func TestSchedulerLeaseHeadWindowSeesNewJobWhileResuming(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 512)
	for i := 0; i < 512; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("job-old-%04d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	runnerID := "runner-paged-head"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(64, 128, 0)

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("priming lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("priming lease did not record a continuation cursor")
	}

	if err := p.InsertJob(ctx, model.Job{ID: "job-new", RunID: "run-" + runnerID, Key: "new",
		Status: model.StatusQueued, Priority: 100, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("head-window lease: %v", err)
	}
	if j.ID != "job-new" {
		t.Fatalf("leased %s, want job-new from the head window", j.ID)
	}
}

// TestSchedulerLeaseCursorClearedOnClaimAndExhaustion pins the cursor
// lifecycle: a claim clears it (covered end-to-end in the prefix test), and
// reaching the end of the queue clears it so the next poll restarts from the
// head instead of resuming at a position that no longer exists.
func TestSchedulerLeaseCursorClearedOnClaimAndExhaustion(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := []model.Job{
		dependencyBlockedJob("job-blocked-0", base),
		dependencyBlockedJob("job-blocked-1", base.Add(time.Millisecond)),
		model.Job{ID: "job-target", CreatedAt: base.Add(2 * time.Millisecond)},
	}
	runnerID := "runner-paged-clear"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)

	// Budget 2 over a 3-row queue: row 3 is never reached, so a cursor is
	// stored for the resume.
	s.SetLeaseScanLimits(1, 2, 0)
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("budget lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("budget exhaustion with HasMore must store a cursor")
	}

	// A bigger budget reaches the target: the claim clears the cursor.
	s.SetLeaseScanLimits(64, 64, 0)
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("cursor vanished before the resuming poll")
	}
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("resuming lease: %v", err)
	}
	if j.ID != "job-target" {
		t.Fatalf("resuming lease took %s, want job-target", j.ID)
	}
	if _, ok := scanCursorFor(s, runnerID); ok {
		t.Fatal("a claim must clear the continuation cursor")
	}

	// Exhaustion: a scan with budget left that reaches the end of the queue
	// with no claim clears the cursor too.
	p2 := newPagedFakeStore()
	now2 := time.Now().UTC()
	base2 := now2.Add(-time.Hour)
	blocked := []model.Job{
		dependencyBlockedJob("job-b0", base2),
		dependencyBlockedJob("job-b1", base2.Add(time.Millisecond)),
		dependencyBlockedJob("job-b2", base2.Add(2*time.Millisecond)),
	}
	runner2 := "runner-paged-exhaust"
	s2 := pagedLeaseStore(t, p2, runner2, now2, blocked...)
	s2.SetLeaseScanLimits(1, 2, 0)
	if _, _, _, err := s2.Lease(ctx, runner2, now2); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("priming lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s2, runner2); !ok {
		t.Fatal("budget exhaustion with HasMore must store a cursor")
	}
	s2.SetLeaseScanLimits(64, 64, 0)
	if _, _, _, err := s2.Lease(ctx, runner2, now2); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("exhausting lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s2, runner2); ok {
		t.Fatal("queue exhaustion must clear the continuation cursor")
	}
}

// TestSchedulerLeasePushdownSkipsIncompatiblePrefix is the audit's liveness
// regression in its strongest form: 4096 label-incompatible jobs sort AHEAD
// of one runnable job, but the runner-coarse SQL filter removes them from the
// candidate set entirely, so the FIRST lease request finishes the runnable
// job without materializing the incompatible prefix. Without the pushdown,
// the scan budget would be exhausted on rows this runner can never run and
// the runnable job would starve.
func TestSchedulerLeasePushdownSkipsIncompatiblePrefix(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	jobs := make([]model.Job, 0, 4097)
	for i := 0; i < 4096; i++ {
		jobs = append(jobs, model.Job{
			ID:             fmt.Sprintf("job-macos-%04d", i),
			RunID:          "run-1",
			Key:            fmt.Sprintf("macos-%04d", i),
			Status:         model.StatusQueued,
			CreatedAt:      now.Add(-time.Duration(i+1) * time.Minute),
			RequiredLabels: []string{"macos"},
		})
	}
	target := model.Job{ID: "job-linux", RunID: "run-1", Key: "linux", Status: model.StatusQueued, CreatedAt: now}
	jobs = append(jobs, target)
	s := pagedLeaseStore(t, p, "runner-linux", now, jobs...)
	s.SetLeaseScanLimits(256, 4096, 0)

	j, _, _, err := s.Lease(ctx, "runner-linux", now)
	if err != nil {
		t.Fatalf("lease with an incompatible prefix: %v", err)
	}
	if j.ID != target.ID {
		t.Fatalf("leased %s, want the runnable %s", j.ID, target.ID)
	}
	p.mu.Lock()
	returned, pages := p.jobsReturned, p.pagesRequested
	p.mu.Unlock()
	if returned > 256 {
		t.Fatalf("pushdown materialized %d rows across %d pages, want at most one bounded page", returned, pages)
	}
}

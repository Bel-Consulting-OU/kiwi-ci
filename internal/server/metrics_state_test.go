package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// metricsStateDataset returns the state-gauge parity dataset: 133 runs whose
// 30 failures are all OLDER than the newest 100 runs (so the previous
// ListRuns(100) sampling counted zero failures), 137 jobs spread across
// statuses including jobs inside terminal runs, three queued jobs with queue
// reasons (plus two jobs whose reasons must NOT be counted), and three
// runners whose capacities exercise the clamp-at-one rule.
func metricsStateDataset() ([]model.Run, []model.Job, []model.Runner) {
	runID := func(i int) string { return fmt.Sprintf("%032x", i) }
	jobID := func(i int) string { return fmt.Sprintf("%032x", 0x1000+i) }
	var runs []model.Run
	for i := 0; i < 133; i++ {
		status := model.StatusSuccess
		switch {
		case i < 30:
			status = model.StatusFailure
		case i >= 130 && i < 132:
			status = model.StatusRunning
		case i == 132:
			status = model.StatusQueued
		}
		runs = append(runs, model.Run{ID: runID(i), Status: status, CreatedAt: time.Unix(int64(1000+i), 0).UTC()})
	}
	var jobs []model.Job
	for i := 0; i < 133; i++ {
		status := model.StatusFailure
		if i < 30 {
			status = model.StatusSuccess
		}
		switch {
		case i >= 130 && i < 132:
			status = model.StatusRunning
		case i == 132:
			status = model.StatusQueued
		}
		j := model.Job{ID: jobID(i), RunID: runID(i), Key: "build", Status: status, CreatedAt: time.Unix(int64(2000+i), 0).UTC()}
		if i == 132 {
			j.QueueReason = "NO_COMPATIBLE_RUNNER"
		}
		jobs = append(jobs, j)
	}
	jobs = append(jobs,
		model.Job{ID: jobID(0x2000), RunID: runID(30), Key: "deploy", Status: model.StatusWaitingApproval, QueueReason: "WAITING_APPROVAL"},
		model.Job{ID: jobID(0x2001), RunID: runID(30), Key: "test", Status: model.StatusQueued, QueueReason: "WAITING_DEPENDENCY"},
		model.Job{ID: jobID(0x2002), RunID: runID(30), Key: "lint", Status: model.StatusQueued},
		model.Job{ID: jobID(0x2003), RunID: runID(30), Key: "docs", Status: model.StatusSuccess, QueueReason: "STALE_REASON"},
	)
	runners := []model.Runner{
		{ID: jobID(0x3000), Name: "zero", Capacity: 0, ActiveJobs: []string{jobID(0)}},
		{ID: jobID(0x3001), Name: "four", Capacity: 4, ActiveJobs: []string{jobID(1), jobID(2)}},
		{ID: jobID(0x3002), Name: "two", Capacity: 2},
	}
	return runs, jobs, runners
}

// metricsStateExpectedLines is the reference exposition of
// metricsStateDataset: DB aggregates and memory mode must BOTH render exactly
// these samples.
func metricsStateExpectedLines() []string {
	lines := []string{
		`kiwi_jobs{status="failure"} 100`,
		`kiwi_jobs{status="queued"} 3`,
		`kiwi_jobs{status="running"} 2`,
		`kiwi_jobs{status="success"} 31`,
		`kiwi_jobs{status="waiting_approval"} 1`,
		`kiwi_jobs_queue_reason{reason="NO_COMPATIBLE_RUNNER"} 1`,
		`kiwi_jobs_queue_reason{reason="WAITING_APPROVAL"} 1`,
		`kiwi_jobs_queue_reason{reason="WAITING_DEPENDENCY"} 1`,
		`kiwi_runs{status="failure"} 30`,
		`kiwi_runs{status="queued"} 1`,
		`kiwi_runs{status="running"} 2`,
		`kiwi_runs{status="success"} 100`,
		"kiwi_runner_saturation 0.42857142857142855",
		"kiwi_runner_slots 7",
		"kiwi_runner_slots_busy 3",
		"kiwi_runners 3",
	}
	sort.Strings(lines)
	return lines
}

// stateGaugeLines extracts and sorts the state-gauge sample lines from a
// scrape body, ignoring HELP/TYPE lines and every process-registry metric.
func stateGaugeLines(body string) []string {
	out := []string{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		switch name {
		case "kiwi_runs", "kiwi_jobs", "kiwi_jobs_queue_reason",
			"kiwi_runners", "kiwi_runner_slots", "kiwi_runner_slots_busy",
			"kiwi_runner_saturation":
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

// metricsScrapeBody serves /metrics through the dedicated metrics handler.
func metricsScrapeBody(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics = %d: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

// metricsAggregateOnlyStore proves the DB metrics path never enumerates
// runs, jobs or runners: the enumeration methods fail hard and are counted,
// so any use would be visible (and would change the rendered output).
type metricsAggregateOnlyStore struct {
	*dbFakeStore
	mu             sync.Mutex
	enumerations   int
	aggregateCalls int
}

func (s *metricsAggregateOnlyStore) noteEnumeration() {
	s.mu.Lock()
	s.enumerations++
	s.mu.Unlock()
}

func (s *metricsAggregateOnlyStore) noteAggregate() {
	s.mu.Lock()
	s.aggregateCalls++
	s.mu.Unlock()
}

func (s *metricsAggregateOnlyStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	s.noteEnumeration()
	return nil, errors.New("metrics must not enumerate runs")
}

func (s *metricsAggregateOnlyStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	s.noteEnumeration()
	return nil, errors.New("metrics must not enumerate jobs")
}

func (s *metricsAggregateOnlyStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	s.noteEnumeration()
	return nil, errors.New("metrics must not enumerate runners")
}

func (s *metricsAggregateOnlyStore) RunStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	s.noteAggregate()
	return s.dbFakeStore.RunStatusCounts(ctx)
}

func (s *metricsAggregateOnlyStore) JobStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	s.noteAggregate()
	return s.dbFakeStore.JobStatusCounts(ctx)
}

func (s *metricsAggregateOnlyStore) QueuedJobQueueReasonCounts(ctx context.Context) (map[string]int, error) {
	s.noteAggregate()
	return s.dbFakeStore.QueuedJobQueueReasonCounts(ctx)
}

func (s *metricsAggregateOnlyStore) RunnerSlotTotals(ctx context.Context) (storage.RunnerSlotTotals, error) {
	s.noteAggregate()
	return s.dbFakeStore.RunnerSlotTotals(ctx)
}

// metricsStoreOnly hides the aggregate contract behind a plain Store, so the
// handler's missing-capability path is testable.
type metricsStoreOnly struct{ storage.Store }

// seedMetricsStateFake loads the dataset into a dbFakeStore.
func seedMetricsStateFake(f *dbFakeStore) {
	runs, jobs, runners := metricsStateDataset()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range runs {
		f.runs[r.ID] = r
	}
	for _, j := range jobs {
		f.jobs[j.ID] = j
	}
	for _, r := range runners {
		f.runners[r.ID] = r
	}
}

// TestMetricsDBStateGaugesUseAggregatesOnly is the core regression test: the
// DB-mode state gauges must come from the store aggregates (no ListRuns
// sampling, no terminal-run exclusion) and must equal the memory-mode values
// for the same data.
func TestMetricsDBStateGaugesUseAggregatesOnly(t *testing.T) {
	fake := &metricsAggregateOnlyStore{dbFakeStore: newDBFakeStore()}
	seedMetricsStateFake(fake.dbFakeStore)
	dbSrv := New("token")
	dbSrv.DB = fake

	body := metricsScrapeBody(t, dbSrv)
	fake.mu.Lock()
	enumerations, aggregates := fake.enumerations, fake.aggregateCalls
	fake.mu.Unlock()
	if enumerations != 0 {
		t.Fatalf("metrics path enumerated store state %d times; it must use aggregates only", enumerations)
	}
	if aggregates != 4 {
		t.Fatalf("aggregate calls = %d, want 4 (runs, jobs, queue reasons, runner slots)", aggregates)
	}

	got := stateGaugeLines(body)
	if want := metricsStateExpectedLines(); !slices.Equal(got, want) {
		t.Fatalf("db state gauges mismatch\ngot:  %v\nwant: %v", got, want)
	}

	// Memory mode renders the same exposition for the same data.
	runs, jobs, runners := metricsStateDataset()
	memSrv := New("token")
	memSrv.mu.Lock()
	for _, r := range runs {
		memSrv.runs[r.ID] = r
	}
	for _, j := range jobs {
		memSrv.jobs[j.ID] = j
	}
	for _, r := range runners {
		memSrv.runners[r.ID] = r
	}
	memSrv.mu.Unlock()
	memLines := stateGaugeLines(metricsScrapeBody(t, memSrv))
	if !slices.Equal(got, memLines) {
		t.Fatalf("db/memory parity broken\ndb:  %v\nmem: %v", got, memLines)
	}

	// The old newest-100 sample would have reported zero failure runs while
	// the aggregate reports 30: the dataset is exactly the regression case.
	newest := append([]model.Run(nil), runs...)
	sort.Slice(newest, func(i, j int) bool { return newest[i].CreatedAt.After(newest[j].CreatedAt) })
	sampled := map[model.Status]int{}
	for _, r := range newest[:100] {
		sampled[r.Status]++
	}
	if sampled[model.StatusFailure] != 0 {
		t.Fatalf("sampled failures = %d, want 0 (regression dataset)", sampled[model.StatusFailure])
	}
	if !slices.Contains(got, `kiwi_runs{status="failure"} 30`) {
		t.Fatalf("aggregate failure runs missing from %v", got)
	}
}

// TestMetricsDBStateFamilyFailureSkipsFamily pins the fail behavior: a failed
// aggregate logs and skips ONLY its family — HELP/TYPE and samples are
// omitted (never rendered as wrong zeros) while the other families render.
func TestMetricsDBStateFamilyFailureSkipsFamily(t *testing.T) {
	cases := []struct {
		name string
		arm  func(*dbFakeStore)
		// absent lists exact substrings (HELP/TYPE headers or sample lines)
		// that must not appear.
		absent []string
		// absentPrefixes lists state sample-line prefixes that must not
		// appear (used for the runner gauges, which share a prefix with the
		// registry's HELP text).
		absentPrefixes []string
		present        []string
	}{
		{
			name:   "runs aggregate",
			arm:    func(f *dbFakeStore) { f.metricRunStatusErr = errors.New("runs down") },
			absent: []string{"# HELP kiwi_runs Number", `kiwi_runs{status=`},
			present: []string{"# HELP kiwi_jobs Number", `kiwi_jobs{status="failure"} 100`,
				"# HELP kiwi_jobs_queue_reason Number", "kiwi_runners 3"},
		},
		{
			name:   "jobs aggregate",
			arm:    func(f *dbFakeStore) { f.metricJobStatusErr = errors.New("jobs down") },
			absent: []string{"# HELP kiwi_jobs Number", `kiwi_jobs{status=`},
			present: []string{"# HELP kiwi_runs Number", `kiwi_runs{status="failure"} 30`,
				"# HELP kiwi_jobs_queue_reason Number", "kiwi_runner_slots_busy 3"},
		},
		{
			name:   "queue reason aggregate",
			arm:    func(f *dbFakeStore) { f.metricQueueReasonErr = errors.New("reasons down") },
			absent: []string{"# HELP kiwi_jobs_queue_reason Number", `kiwi_jobs_queue_reason{reason=`},
			present: []string{"# HELP kiwi_jobs Number", `kiwi_jobs{status="queued"} 3`,
				`kiwi_runs{status="success"} 100`},
		},
		{
			name:           "runner slot aggregate",
			arm:            func(f *dbFakeStore) { f.metricRunnerSlotsErr = errors.New("runners down") },
			absentPrefixes: []string{"kiwi_runners ", "kiwi_runner_slots ", "kiwi_runner_slots_busy ", "kiwi_runner_saturation "},
			present: []string{"# HELP kiwi_runs Number", `kiwi_runs{status="failure"} 30`,
				"# HELP kiwi_jobs Number", `kiwi_jobs{status="failure"} 100`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDBFakeStore()
			seedMetricsStateFake(f)
			tc.arm(f)
			srv := New("token")
			srv.DB = f
			body := metricsScrapeBody(t, srv)
			for _, gone := range tc.absent {
				if strings.Contains(body, gone) {
					t.Fatalf("failed family rendered %q:\n%s", gone, body)
				}
			}
			lines := stateGaugeLines(body)
			for _, prefix := range tc.absentPrefixes {
				for _, line := range lines {
					if strings.HasPrefix(line, prefix) {
						t.Fatalf("failed family rendered %q:\n%s", line, body)
					}
				}
			}
			for _, keep := range tc.present {
				if !strings.Contains(body, keep) {
					t.Fatalf("healthy family missing %q:\n%s", keep, body)
				}
			}
		})
	}

	t.Run("missing aggregate contract", func(t *testing.T) {
		srv := New("token")
		srv.DB = metricsStoreOnly{Store: newDBFakeStore()}
		body := metricsScrapeBody(t, srv)
		if lines := stateGaugeLines(body); len(lines) != 0 {
			t.Fatalf("state gauges rendered without the aggregate contract: %v", lines)
		}
	})
}

// TestMetricsRunnerSaturationZeroCapacityIsNotStale pins C4-B: the exported
// saturation always reflects the latest scrape — capacity > 0 exports the
// busy/capacity fraction, capacity dropping to zero exports an explicit 0
// (never the previous fraction), and restored capacity resumes updating.
func TestMetricsRunnerSaturationZeroCapacityIsNotStale(t *testing.T) {
	s := New("token")
	setRunners := func(runners ...model.Runner) {
		s.mu.Lock()
		s.runners = map[string]model.Runner{}
		for _, r := range runners {
			s.runners[r.ID] = r
		}
		s.mu.Unlock()
	}
	saturation := func() float64 {
		t.Helper()
		for _, line := range strings.Split(metricsScrapeBody(t, s), "\n") {
			if v, ok := strings.CutPrefix(line, "kiwi_runner_saturation "); ok {
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					t.Fatalf("parse saturation %q: %v", line, err)
				}
				return f
			}
		}
		t.Fatal("kiwi_runner_saturation absent from the scrape")
		return 0
	}

	setRunners(model.Runner{ID: "r1", Name: "r1", Capacity: 4, ActiveJobs: []string{"j1", "j2"}})
	if got := saturation(); got != 0.5 {
		t.Fatalf("saturation with capacity = %v, want 0.5", got)
	}
	// A capacity change updates the exported value.
	setRunners(model.Runner{ID: "r1", Name: "r1", Capacity: 10, ActiveJobs: []string{"j1", "j2", "j3"}})
	if got := saturation(); got != 0.3 {
		t.Fatalf("saturation after capacity change = %v, want 0.3", got)
	}
	// Capacity drops to zero: the exported value must be 0, not the stale
	// fraction from the previous scrape.
	setRunners()
	if got := saturation(); got != 0 {
		t.Fatalf("saturation with zero capacity = %v, want 0 (stale value exported)", got)
	}
	// Capacity returns: the gauge resumes updating.
	setRunners(model.Runner{ID: "r2", Name: "r2", Capacity: 2, ActiveJobs: []string{"j1"}})
	if got := saturation(); got != 0.5 {
		t.Fatalf("saturation after capacity returns = %v, want 0.5", got)
	}
}

// TestMetricsDBStateCanceledContextSkipsReads proves a canceled request
// context short-circuits before any store read: no aggregate is called and no
// state sample is rendered (in particular, no wrong zeros).
func TestMetricsDBStateCanceledContextSkipsReads(t *testing.T) {
	fake := &metricsAggregateOnlyStore{dbFakeStore: newDBFakeStore()}
	seedMetricsStateFake(fake.dbFakeStore)
	srv := New("token")
	srv.DB = fake

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics on canceled ctx = %d: %s", w.Code, w.Body.String())
	}
	if lines := stateGaugeLines(w.Body.String()); len(lines) != 0 {
		t.Fatalf("canceled request rendered state gauges: %v", lines)
	}
	fake.mu.Lock()
	aggregates := fake.aggregateCalls
	fake.mu.Unlock()
	if aggregates != 0 {
		t.Fatalf("canceled request read %d aggregates; it must skip store reads", aggregates)
	}
}

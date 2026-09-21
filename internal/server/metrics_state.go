package server

import (
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// stateMetricFamilies is the rendering input shared by the memory and DB
// state-gauge paths. A nil map (or haveRunners=false) means the family was
// NOT readable: it is skipped entirely — no HELP/TYPE, no samples — instead
// of being rendered from stale or zero data. A present-but-empty family
// still renders its headers, exactly like a memory scrape with zero rows.
type stateMetricFamilies struct {
	runs         map[model.Status]int
	jobs         map[model.Status]int
	queueReasons map[string]int
	runners      storage.RunnerSlotTotals
	haveRunners  bool
}

// writeStateMetrics renders the state gauges in the stable Prometheus text
// form. Sample lines are sorted so a scrape is deterministic (map iteration
// order is not).
func (s *Server) writeStateMetrics(w io.Writer, fam stateMetricFamilies) {
	if fam.runs != nil {
		fmt.Fprintln(w, "# HELP kiwi_runs Number of CI runs by status")
		fmt.Fprintln(w, "# TYPE kiwi_runs gauge")
		for _, st := range sortedStatuses(fam.runs) {
			fmt.Fprintf(w, "kiwi_runs{status=%q} %d\n", st, fam.runs[st])
		}
	}
	if fam.jobs != nil {
		fmt.Fprintln(w, "# HELP kiwi_jobs Number of CI jobs by status")
		fmt.Fprintln(w, "# TYPE kiwi_jobs gauge")
		for _, st := range sortedStatuses(fam.jobs) {
			fmt.Fprintf(w, "kiwi_jobs{status=%q} %d\n", st, fam.jobs[st])
		}
	}
	if fam.queueReasons != nil {
		fmt.Fprintln(w, "# HELP kiwi_jobs_queue_reason Number of queued jobs by queue reason")
		fmt.Fprintln(w, "# TYPE kiwi_jobs_queue_reason gauge")
		for _, reason := range sortedKeys(fam.queueReasons) {
			fmt.Fprintf(w, "kiwi_jobs_queue_reason{reason=%q} %d\n", reason, fam.queueReasons[reason])
		}
	}
	if fam.haveRunners {
		fmt.Fprintf(w, "kiwi_runners %d\nkiwi_runner_slots %d\nkiwi_runner_slots_busy %d\n", fam.runners.Runners, fam.runners.Capacity, fam.runners.Busy)
		// Zero total capacity means there are no runner slots at all, so
		// saturation is explicitly ZERO: setting it unconditionally keeps a
		// capacity drop to zero from exporting the previous scrape's ratio
		// (a stale gauge). With capacity present the value is the usual
		// busy/capacity fraction.
		if fam.runners.Capacity > 0 {
			s.metricSet("kiwi_runner_saturation", float64(fam.runners.Busy)/float64(fam.runners.Capacity), nil)
		} else {
			s.metricSet("kiwi_runner_saturation", 0, nil)
		}
	}
}

// sortedStatuses returns the status keys of a count map in canonical order.
func sortedStatuses(counts map[model.Status]int) []model.Status {
	out := make([]model.Status, 0, len(counts))
	for st := range counts {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// metricsMemory renders the state gauges from the in-memory maps. Memory mode
// always has every family (a map read cannot fail), so these values are the
// reference the DB aggregates must agree with.
func (s *Server) metricsMemory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	fam := stateMetricFamilies{
		runs:         make(map[model.Status]int, len(s.runs)),
		jobs:         make(map[model.Status]int, len(s.jobs)),
		queueReasons: map[string]int{},
		haveRunners:  true,
	}
	for _, run := range s.runs {
		fam.runs[run.Status]++
	}
	for _, j := range s.jobs {
		fam.jobs[j.Status]++
		if j.QueueReason != "" && (j.Status == model.StatusQueued || j.Status == model.StatusWaitingApproval) {
			fam.queueReasons[j.QueueReason]++
		}
	}
	for _, ri := range s.runners {
		fam.runners.Runners++
		c := ri.Capacity
		if c < 1 {
			c = 1
		}
		fam.runners.Capacity += c
		fam.runners.Busy += len(ri.ActiveJobs)
	}
	s.mu.Unlock()
	s.writeStateMetrics(w, fam)
}

// metricsDB renders the state gauges from the store's aggregate contract
// (storage.MetricsAggregateStore), never from run sampling: the previous
// implementation called ListRuns(ctx, 100), so kiwi_runs counted at most the
// newest 100 runs and every job of a terminal run was skipped — the same
// metric changed meaning with the backend. The aggregates count every row of
// their table, so DB-mode values equal the memory-mode values for the same
// data.
//
// Fail behavior: a family whose aggregate fails is logged and SKIPPED (its
// HELP/TYPE and samples are omitted) while the families that succeeded still
// render; an unreadable family must never surface as a wrong zero. A
// cancelled request context short-circuits before any store read.
func (s *Server) metricsDB(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := ctx.Err(); err != nil {
		// The scraper is gone: do not read state for a dead request.
		s.logInfo("metrics: skipped db state gauges on canceled request", "error", err.Error())
		return
	}
	agg, ok := s.DB.(storage.MetricsAggregateStore)
	if !ok {
		// Wiring error: without the aggregate contract the state gauges
		// cannot be rendered honestly. Skipping them is the fail-closed
		// choice (the alternative — run sampling — is the defect being
		// fixed).
		s.logError("metrics: db store lacks the aggregate contract; state gauges skipped", "error", "missing storage.MetricsAggregateStore")
		return
	}
	var fam stateMetricFamilies
	if counts, err := agg.RunStatusCounts(ctx); err != nil {
		s.logError("metrics: run status aggregate failed; family skipped", "error", err.Error())
	} else {
		fam.runs = counts
	}
	if counts, err := agg.JobStatusCounts(ctx); err != nil {
		s.logError("metrics: job status aggregate failed; family skipped", "error", err.Error())
	} else {
		fam.jobs = counts
	}
	if counts, err := agg.QueuedJobQueueReasonCounts(ctx); err != nil {
		s.logError("metrics: queue reason aggregate failed; family skipped", "error", err.Error())
	} else {
		fam.queueReasons = counts
	}
	if totals, err := agg.RunnerSlotTotals(ctx); err != nil {
		s.logError("metrics: runner slot aggregate failed; family skipped", "error", err.Error())
	} else {
		fam.runners = totals
		fam.haveRunners = true
	}
	s.writeStateMetrics(w, fam)
}

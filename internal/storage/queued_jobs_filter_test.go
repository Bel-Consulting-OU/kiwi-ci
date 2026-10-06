package storage

// Unit tests for the runner-coarse QueuedJobFilter pushdown and the
// materialized scheduling key on the in-memory store. They pin the exact
// filter semantics the SQL predicates mirror: runtime with "" -> native,
// labels as a containment test where a legacy NULL payload passes, the
// region/empty-region rule, capacity over the EFFECTIVE request and the
// IgnoreServiceEnvelope relaxation, plus the zero-value unconstrained filter.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func queuedFilterCompiledRuntime(runtime string) *model.CompiledJobPayload {
	return &model.CompiledJobPayload{
		SchemaVersion: 1,
		EffectiveJob:  json.RawMessage(`{"job":{"runtime":"` + runtime + `"}}`),
	}
}

func queuedFilterSeed(t *testing.T, now time.Time) *memStore {
	t.Helper()
	mk := func(id, runtime string, labels, regions []string, cpu float64, envCPU float64) model.Job {
		j := model.Job{
			ID: id, RunID: "run-1", Key: id, Status: model.StatusQueued,
			CreatedAt: now.Add(-time.Minute), Priority: 0,
			RequiredLabels: labels, PlacementRegions: regions,
			CPURequest:             cpu,
			ServiceEnvelopeRequest: model.ResourceCapacity{CPU: envCPU},
		}
		if runtime != "" {
			j.CompiledJobPayload = queuedFilterCompiledRuntime(runtime)
		}
		return j
	}
	return queuedJobsPageMemoryStore(t,
		// Legacy payload: no compiled runtime, no labels, no regions.
		mk("legacy", "", nil, nil, 0, 0),
		mk("native", "native", []string{"linux"}, nil, 1, 2),
		mk("container", "container", []string{"linux"}, nil, 1, 0),
		mk("gpu", "native", []string{"linux", "gpu"}, nil, 1, 0),
		mk("region-us", "native", []string{"linux"}, []string{"us"}, 1, 0),
		mk("region-eu", "native", []string{"linux"}, []string{"eu"}, 1, 0),
		// effective CPU = 8 + 4 = 12 (over the 8 cap), own request only = 8.
		mk("big", "native", []string{"linux"}, nil, 8, 4),
		mk("big-job-only", "native", []string{"linux"}, nil, 8, 0),
	)
}

func queuedFilterPageIDs(t *testing.T, m *memStore, filter QueuedJobFilter, now time.Time) []string {
	t.Helper()
	page, err := m.ListQueuedJobsPage(context.Background(), filter, nil, 0, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage(%+v): %v", filter, err)
	}
	ids := make([]string, 0, len(page.Jobs))
	for _, j := range page.Jobs {
		ids = append(ids, j.ID)
	}
	sort.Strings(ids)
	return ids
}

func queuedFilterWant(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

func TestQueuedJobsPageMemoryFilterSemantics(t *testing.T) {
	now := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	m := queuedFilterSeed(t, now)
	for _, tc := range []struct {
		name   string
		filter QueuedJobFilter
		want   []string
	}{
		{
			// The zero-value filter is the documented UNCONSTRAINED read:
			// every queued job passes, including placement-region jobs.
			name:   "zero filter matches everything",
			filter: QueuedJobFilter{},
			want:   queuedFilterWant("legacy", "native", "container", "gpu", "region-us", "region-eu", "big", "big-job-only"),
		},
		{
			// Runtime: "" is native (legacy payload), non-matching runtimes
			// are excluded; the non-zero filter also applies the empty-region
			// rule, so placement-region jobs drop out.
			name:   "runtime filter with native default",
			filter: QueuedJobFilter{Runtimes: []string{"native"}},
			want:   queuedFilterWant("legacy", "native", "gpu", "big", "big-job-only"),
		},
		{
			// Labels: a job passes when every RequiredLabel is present; a
			// legacy payload without required labels passes; an empty runner
			// label set admits only label-free/legacy jobs.
			name:   "label containment",
			filter: QueuedJobFilter{RunnerLabels: []string{"linux"}},
			want:   queuedFilterWant("legacy", "native", "container", "big", "big-job-only"),
		},
		{
			// An explicitly empty (non-nil) runner label set admits only
			// jobs without required labels: the legacy NULL payload.
			name:   "empty runner labels exclude required labels",
			filter: QueuedJobFilter{RunnerLabels: []string{}},
			want:   queuedFilterWant("legacy"),
		},
		{
			// Region: only region-less jobs pass when the runner has no
			// region; a region admits matching placement lists.
			name:   "region empty means region-less only",
			filter: QueuedJobFilter{RunnerLabels: []string{"linux"}, RunnerRegion: ""},
			want:   queuedFilterWant("legacy", "native", "container", "big", "big-job-only"),
		},
		{
			name:   "region match",
			filter: QueuedJobFilter{RunnerRegion: "eu"},
			want:   queuedFilterWant("legacy", "native", "container", "gpu", "region-eu", "big", "big-job-only"),
		},
		{
			// Capacity: the effective request (job + envelope) must fit
			// every constrained dimension. "big" is 12 > 8 and is excluded;
			// its own 8 fits.
			name:   "effective request excludes envelope overflow",
			filter: QueuedJobFilter{MaxRequested: model.ResourceCapacity{CPU: 8}},
			want:   queuedFilterWant("legacy", "native", "container", "gpu", "big-job-only"),
		},
		{
			// IgnoreServiceEnvelope drops the envelope from the effective
			// request: "big" now fits exactly at the cap.
			name:   "ignore service envelope",
			filter: QueuedJobFilter{MaxRequested: model.ResourceCapacity{CPU: 8}, IgnoreServiceEnvelope: true},
			want:   queuedFilterWant("legacy", "native", "container", "gpu", "big", "big-job-only"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := queuedFilterPageIDs(t, m, tc.filter, now)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("filter %+v = %v, want %v", tc.filter, got, tc.want)
			}
		})
	}
}

// TestQueuedJobsPageMemoryBoostOrder pins the materialized scheduling key on
// the memory path: every returned copy carries the computed boost with
// BoostKnown set, the page order equals sortQueuedJobsAged over the same
// copies, and Last.AgedPriority is priority+queue_boost.
func TestQueuedJobsPageMemoryBoostOrder(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	mk := func(id string, priority int, age time.Duration) model.Job {
		return model.Job{ID: id, RunID: "run-1", Key: id, Status: model.StatusQueued, Priority: priority, CreatedAt: now.Add(-age)}
	}
	jobs := []model.Job{
		mk("fresh", 0, 0),             // boost 0
		mk("10m", 0, 10*time.Minute),  // boost 1
		mk("11m", 0, 11*time.Minute),  // boost 1, created after 10m
		mk("25m", 0, 25*time.Minute),  // boost 2
		mk("priority", 9, 0),          // boost 0, aged 9
		mk("skew", 0, -time.Hour),     // clock skew: boost 0
		mk("long", 3, 65*time.Minute), // boost 6 -> aged 9, oldest first
	}
	m := queuedJobsPageMemoryStore(t, jobs...)

	wantOrder := append([]model.Job(nil), jobs...)
	for i := range wantOrder {
		wantOrder[i].QueueBoost = queuedJobComputedBoost(wantOrder[i], now)
		wantOrder[i].BoostKnown = true
	}
	sortQueuedJobsAged(wantOrder, now)
	wantIDs := make([]string, 0, len(wantOrder))
	for _, j := range wantOrder {
		wantIDs = append(wantIDs, j.ID)
	}

	page, err := m.ListQueuedJobsPage(ctx, QueuedJobFilter{}, nil, 0, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage: %v", err)
	}
	gotIDs := make([]string, 0, len(page.Jobs))
	for _, j := range page.Jobs {
		if !j.BoostKnown {
			t.Fatalf("returned job %s: BoostKnown = false, want true", j.ID)
		}
		if j.QueueBoost != queuedJobComputedBoost(j, now) {
			t.Fatalf("returned job %s: QueueBoost = %d, want %d", j.ID, j.QueueBoost, queuedJobComputedBoost(j, now))
		}
		gotIDs = append(gotIDs, j.ID)
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("page order = %v, want aged sort %v", gotIDs, wantIDs)
	}
	last := page.Jobs[len(page.Jobs)-1]
	if page.Last.AgedPriority != last.Priority+last.QueueBoost {
		t.Fatalf("Last.AgedPriority = %d, want priority+queue_boost = %d", page.Last.AgedPriority, last.Priority+last.QueueBoost)
	}

	// The keyset walk over the boosted order returns every job exactly once.
	var seen []string
	var after *QueuedJobCursor
	for {
		page, err := m.ListQueuedJobsPage(ctx, QueuedJobFilter{}, after, 3, now)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		for _, j := range page.Jobs {
			seen = append(seen, j.ID)
		}
		if !page.HasMore {
			break
		}
		cursor := page.Last
		after = &cursor
	}
	if strings.Join(seen, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("boosted walk = %v, want %v", seen, wantIDs)
	}
}

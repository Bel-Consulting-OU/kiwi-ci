package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestExecutionEventTypeMapping pins the shared status -> event type mapping:
// terminal statuses spell succeeded/failed and a running->queued move is the
// recovery requeue, matching the PostgreSQL trigger's CASE expression.
func TestExecutionEventTypeMapping(t *testing.T) {
	cases := []struct {
		from, to model.Status
		scope    string
		want     string
	}{
		{"", model.StatusQueued, "job", "job.queued"},
		{model.StatusQueued, model.StatusRunning, "job", "job.running"},
		{model.StatusRunning, model.StatusSuccess, "job", "job.succeeded"},
		{model.StatusRunning, model.StatusFailure, "job", "job.failed"},
		{model.StatusRunning, model.StatusCancelled, "job", "job.cancelled"},
		{model.StatusRunning, model.StatusQueued, "job", "job.requeued"},
		{model.StatusQueued, model.StatusWaitingApproval, "job", "job.waiting_approval"},
		{model.StatusQueued, model.StatusBlocked, "job", "job.blocked"},
		{model.StatusRunning, model.StatusSkipped, "job", "job.skipped"},
		{"", model.StatusQueued, "run", "run.queued"},
		{model.StatusQueued, model.StatusRunning, "run", "run.running"},
		{model.StatusRunning, model.StatusSuccess, "run", "run.succeeded"},
		{model.StatusRunning, model.StatusFailure, "run", "run.failed"},
	}
	for _, tc := range cases {
		if got := ExecutionEventType(tc.scope, tc.from, tc.to); got != tc.want {
			t.Errorf("ExecutionEventType(%s, %s->%s) = %q, want %q", tc.scope, tc.from, tc.to, got, tc.want)
		}
	}
}

func TestClampExecutionEventLimit(t *testing.T) {
	if got := ClampExecutionEventLimit(0); got != DefaultExecutionEventLimit {
		t.Fatalf("limit 0 = %d, want %d", got, DefaultExecutionEventLimit)
	}
	if got := ClampExecutionEventLimit(-5); got != DefaultExecutionEventLimit {
		t.Fatalf("negative limit = %d, want %d", got, DefaultExecutionEventLimit)
	}
	if got := ClampExecutionEventLimit(MaxExecutionEventLimit + 1); got != DefaultExecutionEventLimit {
		t.Fatalf("over-max limit = %d, want %d", got, DefaultExecutionEventLimit)
	}
	if got := ClampExecutionEventLimit(7); got != 7 {
		t.Fatalf("in-range limit = %d, want 7", got)
	}
}

// TestMemStoreExecutionEvents proves the in-memory mirror allocates its own
// monotonic seq, filters by run, pages by cursor and clamps limits exactly
// like the SQL and fs stores.
func TestMemStoreExecutionEvents(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	for i := 0; i < 5; i++ {
		run := "run-a"
		if i%2 == 1 {
			run = "run-b"
		}
		if err := m.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: run, JobID: "j", Type: "job.queued", ToStatus: "queued",
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, cursor, err := m.ListExecutionEvents(ctx, 0, 100, "")
	if err != nil || len(events) != 5 || cursor != 5 {
		t.Fatalf("list all = %d events cursor %d err %v, want 5/5", len(events), cursor, err)
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Fatalf("event %d seq = %d, want %d", i, e.Seq, i+1)
		}
		if e.SchemaVersion != 1 {
			t.Fatalf("event %d schema = %d, want 1", i, e.SchemaVersion)
		}
	}
	// Limit clamps out-of-range values to one default page.
	if got, _, _ := m.ListExecutionEvents(ctx, 0, -1, ""); len(got) != 5 {
		t.Fatalf("negative limit returned %d events", len(got))
	}
	// Cursor paging has no gaps or duplicates.
	page1, cur, err := m.ListExecutionEvents(ctx, 0, 2, "")
	if err != nil || len(page1) != 2 || cur != 2 {
		t.Fatalf("page1 = %d cursor %d err %v", len(page1), cur, err)
	}
	page2, cur, err := m.ListExecutionEvents(ctx, cur, 2, "")
	if err != nil || len(page2) != 2 || cur != 4 {
		t.Fatalf("page2 = %d cursor %d err %v", len(page2), cur, err)
	}
	page3, cur, err := m.ListExecutionEvents(ctx, cur, 2, "")
	if err != nil || len(page3) != 1 || cur != 5 {
		t.Fatalf("page3 = %d cursor %d err %v", len(page3), cur, err)
	}
	if page2[0].Seq != 3 || page3[0].Seq != 5 {
		t.Fatalf("cursor paging skipped/duplicated: %d, %d", page2[0].Seq, page3[0].Seq)
	}
	// Run filter.
	filtered, _, err := m.ListExecutionEvents(ctx, 0, 100, "run-b")
	if err != nil || len(filtered) != 2 {
		t.Fatalf("run filter = %d events err %v, want 2", len(filtered), err)
	}
	for _, e := range filtered {
		if e.RunID != "run-b" {
			t.Fatalf("run filter leaked %q", e.RunID)
		}
	}
	// Empty page keeps the caller's cursor.
	if got, cur, err := m.ListExecutionEvents(ctx, 5, 100, ""); err != nil || len(got) != 0 || cur != 5 {
		t.Fatalf("empty page = %d cursor %d err %v", len(got), cur, err)
	}
}

// TestFaultyStoreExecutionEvents proves the wrapper injects the configured
// mutation fault on AppendExecutionEvent and leaves reads untouched.
func TestFaultyStoreExecutionEvents(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	if err := inner.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "run.queued", ToStatus: "queued"}); err != nil {
		t.Fatal(err)
	}
	fault := &FaultyStore{Inner: inner, FailAfter: 1, Err: errors.New("injected event failure")}
	err := fault.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "job.queued", ToStatus: "queued"})
	if err == nil || err.Error() != "injected event failure" {
		t.Fatalf("append fault = %v, want injected failure", err)
	}
	events, cursor, err := fault.ListExecutionEvents(ctx, 0, 100, "")
	if err != nil || len(events) != 1 || cursor != 1 {
		t.Fatalf("read through faulty store = %d cursor %d err %v, want the committed event", len(events), cursor, err)
	}
	// A minimal Store without the contract fails closed and does not consume
	// the mutation fault.
	if _, _, err := (&FaultyStore{Inner: storeOnlyInner{}}).ListExecutionEvents(ctx, 0, 10, ""); err == nil {
		t.Fatal("missing inner contract must fail closed")
	}
}

// TestExecutionEventTimingPayload pins the terminal payload helper so the fs
// appender and the PostgreSQL trigger agree on keys.
func TestExecutionEventTimingPayload(t *testing.T) {
	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finished := started.Add(1500 * time.Millisecond)
	got := ExecutionEventTimingPayload(&started, &finished)
	if got["started_at"] != "2026-01-02T03:04:05Z" || got["finished_at"] != "2026-01-02T03:04:06.5Z" {
		t.Fatalf("timing payload = %v", got)
	}
	if got["duration_ms"] != "1500" {
		t.Fatalf("duration_ms = %q, want 1500", got["duration_ms"])
	}
	if len(ExecutionEventTimingPayload(nil, nil)) != 0 {
		t.Fatal("nil timings must produce no payload keys")
	}
}

// TestExecutionEventTerminalStatusesIncludeBlocked pins the terminal-timing
// enumeration: blocked is terminal in the model and must be treated exactly
// like success/failure/cancelled/skipped, so the list stays in exact parity
// with model.Status.Terminal(). The PostgreSQL trigger function embeds the
// same set (migration 0046), so the two can never drift.
func TestExecutionEventTerminalStatusesIncludeBlocked(t *testing.T) {
	listed := map[model.Status]bool{}
	for _, s := range ExecutionEventTerminalStatuses {
		listed[s] = true
	}
	if !listed[model.StatusBlocked] {
		t.Fatal("ExecutionEventTerminalStatuses omits blocked")
	}
	all := []model.Status{
		model.StatusQueued,
		model.StatusRunning,
		model.StatusWaitingApproval,
		model.StatusBlocked,
		model.StatusSuccess,
		model.StatusFailure,
		model.StatusCancelled,
		model.StatusSkipped,
	}
	for _, s := range all {
		if got := listed[s]; got != s.Terminal() {
			t.Errorf("terminal parity for %s: listed=%v Terminal()=%v", s, got, s.Terminal())
		}
	}
}

// TestExecutionEventCursorExpiredBoundary pins the retained_from expiry rule:
// retainedFrom is the HIGHEST removed seq, so after == retainedFrom is the
// consumed boundary and stays valid while after == retainedFrom-1 is expired
// (seq retainedFrom was removed unobserved).
func TestExecutionEventCursorExpiredBoundary(t *testing.T) {
	for _, tc := range []struct {
		after, retained int64
		expired         bool
	}{
		{0, 0, false},
		{5, 0, false},
		{0, 5, true},
		{4, 5, true},
		{5, 5, false},
		{6, 5, false},
		{9, 5, false},
	} {
		if got := ExecutionEventCursorExpired(tc.after, tc.retained); got != tc.expired {
			t.Errorf("ExecutionEventCursorExpired(%d, %d) = %v, want %v", tc.after, tc.retained, got, tc.expired)
		}
	}
}

// TestExecutionEventDeploymentAttempt pins the semantic deployment events'
// attempt identity: both deployment.started and deployment.completed carry
// the deployment record's lease generation as ExecutionEvent.Attempt, so a
// consumer can attribute a deployment to the exact job attempt.
func TestExecutionEventDeploymentAttempt(t *testing.T) {
	d := testDeployment
	d.LeaseGeneration = 4
	started := ExecutionEventDeploymentStarted(d)
	if started.Attempt != 4 {
		t.Fatalf("deployment.started attempt = %d, want 4: %+v", started.Attempt, started)
	}
	d.Status = model.StatusSuccess
	done := ExecutionEventDeploymentCompleted(d)
	if done.Attempt != 4 {
		t.Fatalf("deployment.completed attempt = %d, want 4: %+v", done.Attempt, done)
	}
	// A legacy record without a generation reads as 0, never a fabricated
	// attempt.
	d.LeaseGeneration = 0
	if got := ExecutionEventDeploymentStarted(d).Attempt; got != 0 {
		t.Fatalf("legacy deployment attempt = %d, want 0", got)
	}
}

// TestMemStoreAtomicRetentionReadLatestMonotonic proves the memStore mirror
// of the atomic retention read: latest comes from the monotonic allocated
// watermark, so pruning every row cannot regress it, and the page/watermark
// are returned together.
func TestMemStoreAtomicRetentionReadLatestMonotonic(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := m.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-a", Type: "job.queued", CreatedAt: now.Add(-time.Duration(3-i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	page, cursor, retained, latest, err := m.ReadExecutionEventsRetention(ctx, 0, 100, "run-a")
	if err != nil || len(page) != 3 || cursor != 3 || retained != 0 || latest != 3 {
		t.Fatalf("initial atomic read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}
	if _, _, err := m.PruneExecutionEvents(ctx, now.Add(time.Hour), 100); err != nil {
		t.Fatal(err)
	}
	page, cursor, retained, latest, err = m.ReadExecutionEventsRetention(ctx, 3, 100, "")
	if err != nil || len(page) != 0 || cursor != 3 || retained != 3 || latest != 3 {
		t.Fatalf("all-pruned atomic read = %d cursor %d retained %d latest %d err %v", len(page), cursor, retained, latest, err)
	}
	if ExecutionEventCursorExpired(2, retained) != true || ExecutionEventCursorExpired(3, retained) != false {
		t.Fatalf("memStore expiry boundary at retained %d disagrees", retained)
	}
}

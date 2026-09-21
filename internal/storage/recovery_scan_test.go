package storage

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// recoveryScanID returns a deterministic 32-hex id from a single hex digit so
// ordering matches the SQL TEXT order exactly.
func recoveryScanID(digit string) string { return strings.Repeat(digit, 32) }

// recoveryScanSeed inserts jobs directly so insertion order is deliberately
// shuffled: ordering can only come from the discovery contract, never from
// map or insert order.
func recoveryScanSeed(m *memStore, jobs ...model.Job) {
	for _, j := range jobs {
		m.jobs[j.ID] = j
	}
}

// TestMemStoreListExpiredRunningJobsPagesDeterministically pins the memory
// discovery contract the scheduler sweep depends on: running jobs with an
// elapsed OR absent lease expiry are returned in id order, keyset-paged with
// id > afterID, exactly once per page, and live leases / other statuses never
// appear.
func TestMemStoreListExpiredRunningJobsPagesDeterministically(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	expired := now.Add(-time.Minute)
	live := now.Add(time.Minute)
	m := newMemStore()
	recoveryScanSeed(m,
		model.Job{ID: recoveryScanID("d"), Status: model.StatusRunning, LeaseExpiresAt: &expired},
		model.Job{ID: recoveryScanID("2"), Status: model.StatusRunning, LeaseExpiresAt: &live},
		model.Job{ID: recoveryScanID("a"), Status: model.StatusRunning},
		model.Job{ID: recoveryScanID("5"), Status: model.StatusRunning, LeaseExpiresAt: &expired},
		model.Job{ID: recoveryScanID("1"), Status: model.StatusQueued},
		model.Job{ID: recoveryScanID("9"), Status: model.StatusFailure, LeaseExpiresAt: &expired},
	)

	if page, err := m.ListExpiredRunningJobs(ctx(), now, "", 0); err != nil || len(page) != 0 {
		t.Fatalf("limit 0 = %d/%v, want empty/nil", len(page), err)
	}

	var got []string
	afterID := ""
	for {
		page, err := m.ListExpiredRunningJobs(ctx(), now, afterID, 1)
		if err != nil {
			t.Fatalf("page after %q: %v", afterID, err)
		}
		for _, j := range page {
			if j.ID <= afterID {
				t.Fatalf("cursor not strictly increasing: %q after %q", j.ID, afterID)
			}
			got = append(got, j.ID)
			afterID = j.ID
		}
		if len(page) < 1 {
			break
		}
	}
	want := []string{recoveryScanID("5"), recoveryScanID("a"), recoveryScanID("d")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paged ids = %v, want %v", got, want)
	}
}

// TestMemStoreListQueueTimedOutJobsPagesDeterministically pins the queue
// discovery contract: queued/waiting jobs whose EFFECTIVE deadline elapsed are
// returned in id order with keyset paging; future deadlines, terminal jobs,
// and deadline-less jobs never appear; the compiled-payload queue_timeout
// fallback is honored.
func TestMemStoreListQueueTimedOutJobsPagesDeterministically(t *testing.T) {
	now := time.Unix(10_000, 0).UTC()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	fallback := model.Job{
		ID:        recoveryScanID("b"),
		Status:    model.StatusQueued,
		CreatedAt: now.Add(-time.Hour),
		CompiledJobPayload: &model.CompiledJobPayload{
			EffectiveJob: []byte(`{"job":{"queue_timeout":"5m"}}`),
		},
	}
	if dl := QueueDeadlineFor(fallback); dl == nil || dl.After(now) {
		t.Fatalf("fallback fixture does not derive an elapsed deadline: %v", dl)
	}
	m := newMemStore()
	recoveryScanSeed(m,
		model.Job{ID: recoveryScanID("f"), Status: model.StatusQueued, QueueDeadline: &past},
		model.Job{ID: recoveryScanID("3"), Status: model.StatusWaitingApproval, QueueDeadline: &past},
		model.Job{ID: recoveryScanID("8"), Status: model.StatusQueued, QueueDeadline: &future},
		model.Job{ID: recoveryScanID("c"), Status: model.StatusQueued},
		model.Job{ID: recoveryScanID("e"), Status: model.StatusCancelled, QueueDeadline: &past},
		fallback,
	)

	var got []string
	afterID := ""
	for {
		page, err := m.ListQueueTimedOutJobs(ctx(), now, afterID, 2)
		if err != nil {
			t.Fatalf("page after %q: %v", afterID, err)
		}
		for _, j := range page {
			if j.ID <= afterID {
				t.Fatalf("cursor not strictly increasing: %q after %q", j.ID, afterID)
			}
			got = append(got, j.ID)
			afterID = j.ID
		}
		if len(page) < 2 {
			break
		}
	}
	want := []string{recoveryScanID("3"), recoveryScanID("b"), recoveryScanID("f")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paged ids = %v, want %v", got, want)
	}
}

// TestMemStoreReleaseOutboxClaimsBatch pins the batch claim release: exactly
// the matching claimed rows are cleared, other claimers' rows are untouched,
// the affected count is returned, and replay is idempotent.
func TestMemStoreReleaseOutboxClaimsBatch(t *testing.T) {
	m := newMemStore()
	for _, id := range []string{"o1", "o2", "o3"} {
		if err := m.OutboxAppend(ctx(), OutboxItem{ID: id}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	if claimed, err := m.ClaimOutbox(ctx(), "flusher-a", 2); err != nil || len(claimed) != 2 {
		t.Fatalf("claim a = %d/%v", len(claimed), err)
	}
	if claimed, err := m.ClaimOutbox(ctx(), "flusher-b", 3); err != nil || len(claimed) != 1 {
		t.Fatalf("claim b = %d/%v", len(claimed), err)
	}

	n, err := m.ReleaseOutboxClaims(ctx(), []string{"o1", "o2", "o3", "missing"}, "flusher-a")
	if err != nil || n != 2 {
		t.Fatalf("batch release = %d/%v, want 2/nil", n, err)
	}
	m.mu.Lock()
	_, a1 := m.outboxClaims["o1"]
	_, a2 := m.outboxClaims["o2"]
	b3, b3ok := m.outboxClaims["o3"]
	m.mu.Unlock()
	if a1 || a2 {
		t.Fatalf("flusher-a claims survived: o1=%v o2=%v", a1, a2)
	}
	if !b3ok || b3.claimer != "flusher-b" {
		t.Fatalf("flusher-b claim on o3 was cleared: %+v", b3)
	}

	// Replay is a no-op: nothing left to release, count stays 0.
	if n, err := m.ReleaseOutboxClaims(ctx(), []string{"o1", "o2"}, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("replayed batch release = %d/%v, want 0/nil", n, err)
	}
	// An empty id list is a no-op.
	if n, err := m.ReleaseOutboxClaims(ctx(), nil, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("empty batch release = %d/%v, want 0/nil", n, err)
	}
}

// TestMemStoreReleaseOutboxClaimsConcurrentReclaim proves the claimer match is
// the concurrency guard: a row re-claimed by another flusher in the meantime
// is never cleared by the original claimer's batch release.
func TestMemStoreReleaseOutboxClaimsConcurrentReclaim(t *testing.T) {
	m := newMemStore()
	if err := m.OutboxAppend(ctx(), OutboxItem{ID: "o1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ClaimOutbox(ctx(), "flusher-a", 1); err != nil {
		t.Fatal(err)
	}
	// Simulate the TTL reclaim by another flusher racing the cleanup.
	m.mu.Lock()
	m.outboxClaims["o1"] = outboxClaim{claimer: "flusher-b", at: time.Now().UTC()}
	m.mu.Unlock()

	if n, err := m.ReleaseOutboxClaims(ctx(), []string{"o1"}, "flusher-a"); err != nil || n != 0 {
		t.Fatalf("release after reclaim = %d/%v, want 0/nil", n, err)
	}
	m.mu.Lock()
	c, ok := m.outboxClaims["o1"]
	m.mu.Unlock()
	if !ok || c.claimer != "flusher-b" {
		t.Fatalf("new claim was cleared: %+v ok=%v", c, ok)
	}
}

// TestMemStoreReleaseOutboxClaimsRacesWithReclaim drives the batch release
// and a reclaim of the same id concurrently (run under -race): a claim that
// exists at any observation point is the OTHER claimer's, because the release
// can never clear a claim it does not own and therefore can never strand or
// clobber a newer claim.
func TestMemStoreReleaseOutboxClaimsRacesWithReclaim(t *testing.T) {
	m := newMemStore()
	if err := m.OutboxAppend(ctx(), OutboxItem{ID: "o1"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := m.ClaimOutbox(ctx(), "flusher-a", 1); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = m.ReleaseOutboxClaims(ctx(), []string{"o1"}, "flusher-a")
		}()
		go func() {
			defer wg.Done()
			m.mu.Lock()
			m.outboxClaims["o1"] = outboxClaim{claimer: "flusher-b", at: time.Now().UTC()}
			m.mu.Unlock()
		}()
		wg.Wait()
		m.mu.Lock()
		c, ok := m.outboxClaims["o1"]
		m.mu.Unlock()
		if ok && c.claimer != "flusher-b" {
			t.Fatalf("iteration %d left claim %+v, want flusher-b or none", i, c)
		}
	}
}

// TestFenceReleaseContextIsBoundedAndDetached pins the release helper: a nil
// or already-canceled origin still yields a usable context, and the deadline
// is always the fresh bound, never the origin's.
func TestFenceReleaseContextIsBoundedAndDetached(t *testing.T) {
	origin, cancelOrigin := context.WithCancel(context.Background())
	cancelOrigin()
	got, cancel := fenceReleaseContext(origin, 25*time.Millisecond)
	defer cancel()
	if err := got.Err(); err != nil {
		t.Fatalf("canceled origin leaked cancellation into the release context: %v", err)
	}
	deadline, ok := got.Deadline()
	if !ok || time.Until(deadline) > time.Second {
		t.Fatalf("release context deadline = %v ok=%v, want a fresh short bound", deadline, ok)
	}
	nilCtx, nilCancel := fenceReleaseContext(nil, 25*time.Millisecond)
	defer nilCancel()
	if err := nilCtx.Err(); err != nil {
		t.Fatalf("nil origin context = %v", err)
	}
}

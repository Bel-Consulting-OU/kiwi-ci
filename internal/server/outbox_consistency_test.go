package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// outboxDispatcher records the item IDs it dispatched, thread-safely.
type outboxDispatcher struct {
	mu    sync.Mutex
	seen  []string
	calls map[string]int
	err   error
}

func newOutboxDispatcher() *outboxDispatcher {
	return &outboxDispatcher{calls: map[string]int{}}
}

func (d *outboxDispatcher) dispatch(_ context.Context, it forge.OutboxItem) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.seen = append(d.seen, it.ID)
	d.calls[it.ID]++
	return nil
}

func (d *outboxDispatcher) count(id string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[id]
}

func (d *outboxDispatcher) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

// TestOutboxDBAckFailureKeepsPendingAndRetries pins MEDIUM-16 for DB mode:
// dispatch → durable ack → local pop. An ack failure keeps the item queued
// (and durably present) and the next flush retries the SAME intent ID
// idempotently.
func TestOutboxDBAckFailureKeepsPendingAndRetries(t *testing.T) {
	f := newDBFakeStore()
	o := NewOutbox(nil)
	o.AttachDB(f)
	item := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{}`)}
	if err := o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	id := o.Pending()[0].ID

	f.mu.Lock()
	f.outboxAckErr = errors.New("ack write failed")
	f.mu.Unlock()
	d := newOutboxDispatcher()
	if _, err := o.Flush(context.Background(), d.dispatch); err == nil {
		t.Fatal("ack failure must be returned")
	}
	if got := len(o.Pending()); got != 1 {
		t.Fatalf("pending after ack failure = %d, want the item still queued", got)
	}
	f.mu.Lock()
	durable := len(f.outboxItems)
	f.mu.Unlock()
	if durable != 1 {
		t.Fatalf("durable rows after ack failure = %d, want 1", durable)
	}

	// Clear the ack fault: the retry dispatches the SAME stable intent ID
	// and the successful ack removes it exactly once.
	f.mu.Lock()
	f.outboxAckErr = nil
	f.mu.Unlock()
	n, err := o.Flush(context.Background(), d.dispatch)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(o.Pending()) != 0 {
		t.Fatalf("retry flush n=%d pending=%d", n, len(o.Pending()))
	}
	if got := d.count(id); got != 2 {
		t.Fatalf("dispatch calls for the intent = %d, want 2 (idempotent retry of the same ID)", got)
	}
	f.mu.Lock()
	remaining := len(f.outboxItems)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("durable rows after ack = %d, want 0", remaining)
	}
	// A third flush is a no-op: the acked item is never redispatched.
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 0 {
		t.Fatalf("post-ack flush = n=%d err=%v", n, err)
	}
	if got := d.count(id); got != 2 {
		t.Fatalf("acked intent redispatched: %d calls", got)
	}
}

// TestOutboxFSAckFailureKeepsPendingAndRetries pins the same order for the
// filesystem store: a done-file append failure leaves the intent in the
// queue for the next tick.
func TestOutboxFSAckFailureKeepsPendingAndRetries(t *testing.T) {
	dir := t.TempDir()
	o := NewOutbox(storage.New(dir))
	item := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{}`)
	if err := o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	// Break the store directory so the durable done-file append fails while
	// the local queue stays intact.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newOutboxDispatcher()
	if _, err := o.Flush(context.Background(), d.dispatch); err == nil {
		t.Fatal("done-file append failure must be returned")
	}
	if len(o.Pending()) != 1 {
		t.Fatal("ack failure lost the intent from the local queue")
	}
	// Repair the directory: the retry acks and pops.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 1 || len(o.Pending()) != 0 {
		t.Fatalf("retry flush n=%d err=%v pending=%d", n, err, len(o.Pending()))
	}
	if got := d.count(item.ID); got != 2 {
		t.Fatalf("dispatch calls = %d, want 2 with the stable ID", got)
	}
	// A restarted outbox skips the acked intent (done file committed).
	o2 := NewOutbox(storage.New(dir))
	if len(o2.Pending()) != 0 {
		t.Fatalf("replayed pending after ack = %d, want 0", len(o2.Pending()))
	}
}

// TestOutboxDBClaimBatchesDisjoint: two claimers over one durable store take
// disjoint batches; a fresh claim is invisible to the other claimer.
func TestOutboxDBClaimBatchesDisjoint(t *testing.T) {
	f := newDBFakeStore()
	for i := 0; i < 8; i++ {
		if err := f.OutboxAppend(context.Background(), storage.OutboxItem{
			ID: string(rune('a' + i)), Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}"), CreatedAt: time.Unix(int64(1000+i), 0).UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := f.ClaimOutbox(context.Background(), "flusher-a", 4)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.ClaimOutbox(context.Background(), "flusher-b", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 4 || len(b) != 4 {
		t.Fatalf("claims = %d/%d, want 4/4", len(a), len(b))
	}
	seen := map[string]string{}
	for _, it := range append(append([]storage.OutboxItem{}, a...), b...) {
		if prev, dup := seen[it.ID]; dup {
			t.Fatalf("item %s claimed by both %s and the other flusher", it.ID, prev)
		}
		seen[it.ID] = "claimed"
	}
	if c, _ := f.ClaimOutbox(context.Background(), "flusher-c", 8); len(c) != 0 {
		t.Fatalf("third flusher stole fresh claims: %d rows", len(c))
	}
}

// TestOutboxDBConcurrentFlushNoDoubleDispatch: two Outbox instances over one
// store flush concurrently; every intent is dispatched exactly once and the
// durable outbox drains.
func TestOutboxDBConcurrentFlushNoDoubleDispatch(t *testing.T) {
	f := newDBFakeStore()
	o1 := NewOutbox(nil)
	o1.AttachDB(f)
	o2 := NewOutbox(nil)
	o2.AttachDB(f)
	const items = 12
	ids := make([]string, 0, items)
	for i := 0; i < items; i++ {
		it := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{}`)}
		if err := o1.Enqueue(it); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o1.Pending()[i].ID)
	}
	var wg sync.WaitGroup
	var dispatched int
	var mu sync.Mutex
	calls := map[string]int{}
	dispatch := func(_ context.Context, it forge.OutboxItem) error {
		mu.Lock()
		defer mu.Unlock()
		dispatched++
		calls[it.ID]++
		return nil
	}
	for _, o := range []*Outbox{o1, o2} {
		wg.Add(1)
		go func(o *Outbox) {
			defer wg.Done()
			if _, err := o.Flush(context.Background(), dispatch); err != nil {
				t.Errorf("concurrent flush: %v", err)
			}
		}(o)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if calls[id] != 1 {
			t.Fatalf("intent %s dispatched %d times, want exactly 1", id, calls[id])
		}
	}
	if dispatched != items {
		t.Fatalf("dispatched %d intents, want %d", dispatched, items)
	}
	f.mu.Lock()
	remaining := len(f.outboxItems)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("durable outbox not drained: %d rows", remaining)
	}
}

// TestOutboxDBStaleClaimReclaimed: a claim older than the TTL is reclaimed
// (crash recovery), and a fresh claim is not stolen.
func TestOutboxDBStaleClaimReclaimed(t *testing.T) {
	f := newDBFakeStore()
	if err := f.OutboxAppend(context.Background(), storage.OutboxItem{ID: "stuck", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}"), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ClaimOutbox(context.Background(), "crashed-flusher", 1); err != nil {
		t.Fatal(err)
	}
	o := NewOutbox(nil)
	o.AttachDB(f)
	d := newOutboxDispatcher()
	// The fresh claim is honored: the replacement flusher gets nothing.
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 0 {
		t.Fatalf("fresh claim stolen: n=%d err=%v", n, err)
	}
	// Age the claim beyond the TTL: it becomes reclaimable.
	f.mu.Lock()
	f.outboxClaims["stuck"] = fakeOutboxClaim{claimer: "crashed-flusher", at: time.Now().UTC().Add(-2 * storage.OutboxClaimTTL)}
	f.mu.Unlock()
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 1 {
		t.Fatalf("stale claim not reclaimed: n=%d err=%v", n, err)
	}
	if d.count("stuck") != 1 {
		t.Fatalf("reclaimed intent dispatched %d times", d.count("stuck"))
	}
	f.mu.Lock()
	remaining := len(f.outboxItems)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("reclaimed intent not acked: %d rows", remaining)
	}
}

// TestOutboxDBLocalOnlyItemStillDispatched: an Enqueue whose durable append
// failed stays queued in memory and is still dispatched (no row to claim).
// TestOutboxDBAppendFailureNeverDispatches is the durable-first contract:
// when the DB append fails the intent must NOT be dispatchable from RAM — an
// external side effect that was never durably recorded can be lost forever
// on a crash. (This replaces the old local-only-dispatch expectation, which
// violated the durable-outbox model.)
func TestOutboxDBAppendFailureNeverDispatches(t *testing.T) {
	f := newDBFakeStore()
	o := NewOutbox(nil)
	o.AttachDB(f)
	f.mu.Lock()
	f.outboxAppendErr = errors.New("db down")
	f.mu.Unlock()
	if err := o.Enqueue(forge.OutboxItem{ID: "orphan", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}")}); err == nil {
		t.Fatal("Enqueue must report the durable append failure")
	}
	if got := len(o.Pending()); got != 0 {
		t.Fatalf("pending after failed append = %d, want 0 (never dispatch from RAM)", got)
	}
	d := newOutboxDispatcher()
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 0 {
		t.Fatalf("flush after failed append = n=%d err=%v, want nothing dispatched", n, err)
	}
	if d.count("orphan") != 0 {
		t.Fatalf("undurable intent dispatched %d times", d.count("orphan"))
	}
	// With the store healthy the SAME deterministic ID now records and
	// dispatches exactly once.
	f.mu.Lock()
	f.outboxAppendErr = nil
	f.mu.Unlock()
	if err := o.Enqueue(forge.OutboxItem{ID: "orphan", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 1 {
		t.Fatalf("recovery flush = n=%d err=%v", n, err)
	}
}

// TestOutboxDBReplayPrunesAckedByOtherReplica: a local copy of an intent a
// different replica acknowledged is dropped from the in-memory queue instead
// of lingering (and is never redispatched).
func TestOutboxDBReplayPrunesAckedByOtherReplica(t *testing.T) {
	f := newDBFakeStore()
	o := NewOutbox(nil)
	o.AttachDB(f)
	it := forge.OutboxItem{ID: "shared", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}")}
	if err := o.Enqueue(it); err != nil {
		t.Fatal(err)
	}
	// Another replica wins the claim and acks before our flush starts.
	if err := f.OutboxAck(context.Background(), "shared"); err != nil {
		t.Fatal(err)
	}
	d := newOutboxDispatcher()
	// A claim finds nothing; prune drops the stale local copy.
	if n, err := o.Flush(context.Background(), d.dispatch); err != nil || n != 0 {
		t.Fatalf("flush after remote ack = n=%d err=%v", n, err)
	}
	if got := len(o.Pending()); got != 0 {
		t.Fatalf("stale local copy not pruned: %d items", got)
	}
	if d.total() != 0 {
		t.Fatalf("acked intent redispatched: %v", d.seen)
	}
}

// TestGitHubCheckRetryPatchesInsteadOfDuplicating is the lost-ACK regression:
// the first publish POSTs and the returned check-run ID is persisted; when the
// outbox retries the same logical check (remote success, local ACK failure),
// dispatch must PATCH that ID — a second POST would duplicate the check.
func TestGitHubCheckRetryPatchesInsteadOfDuplicating(t *testing.T) {
	var posts, patches int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
			return
		case http.MethodPost:
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": 4242}`))
		case http.MethodPatch:
			patches++
			if !strings.HasSuffix(r.URL.Path, "/check-runs/4242") {
				t.Errorf("PATCH path = %s, want /check-runs/4242", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": 4242}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer api.Close()

	s := New("secret")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = api.URL
	item := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: mustJSON(t, forge.CheckPayload{
		RunID: "run-1", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "abc", Name: "Pipeline",
		Status: "completed", Conclusion: "success", Summary: "ok",
	})}
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	// Retry the SAME intent (ACK failure replays it).
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("retry dispatch: %v", err)
	}
	if posts != 1 {
		t.Fatalf("POSTs = %d, want exactly 1 (retry must not create a duplicate check)", posts)
	}
	if patches != 1 {
		t.Fatalf("PATCHes = %d, want 1", patches)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGitHubCheckRunMappingPersistedReadPropagated covers the two state
// failures the sequential retry test cannot see: a mapping READ error must
// fail the dispatch (never POST a duplicate), and a mapping WRITE error must
// fail the dispatch (never ACK away the remote ID).
func TestGitHubCheckRunMappingPersistErrorsFailDispatch(t *testing.T) {
	var posts int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": 77}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()

	item := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: mustJSON(t, forge.CheckPayload{
		RunID: "run-x", ForgeKind: "github", RepoFullName: "acme/backend", SHA: "abc",
		Name: "Pipeline", Status: "completed", Conclusion: "success",
	})}

	// Write failure: dispatch must fail (no ACK) and retry later.
	fs := &fcStoreWriteFail{dbFakeStore: newDBFakeStore()}
	s := New("secret")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = api.URL
	if err := s.SwitchToDB(fs); err != nil {
		t.Fatal(err)
	}
	if err := s.dispatchOutbox(context.Background(), item); err == nil {
		t.Fatal("mapping write failure must fail the dispatch (the remote ID would be lost)")
	}
	// Read failure: dispatch must fail instead of POSTing again.
	fs.failGet = true
	if err := s.dispatchOutbox(context.Background(), item); err == nil {
		t.Fatal("mapping read failure must fail the dispatch")
	}
}

type fcStoreWriteFail struct {
	*dbFakeStore
	failGet bool
}

func (f *fcStoreWriteFail) PutCheckRun(ctx context.Context, key, id string) error {
	return errors.New("mapping store down")
}

func (f *fcStoreWriteFail) GetCheckRun(ctx context.Context, key string) (string, bool, error) {
	if f.failGet {
		return "", false, errors.New("mapping read down")
	}
	return f.dbFakeStore.GetCheckRun(ctx, key)
}

package server

// Unit coverage for the aggregate outbox claim cleanup. The deferred sweep at
// the end of flushDBBatch must clear a claimed-but-unACKed batch with ONE
// ReleaseOutboxClaims call under ONE fresh bounded deadline when the store
// implements storage.OutboxClaimBatchStore, and only fall back to the per-row
// loop for stores that do not (test doubles/legacy stores; every shipped
// durable store implements the batch contract).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// outboxReleaseProbeKey marks the flush context so the probe can prove the
// cleanup context is DERIVED from it (values preserved through boundedDetach)
// while its cancellation is dropped.
type outboxReleaseProbeKey struct{}

// outboxBatchReleaseCall records one ReleaseOutboxClaims invocation.
type outboxBatchReleaseCall struct {
	ids             []string
	claimer         string
	enteredAt       time.Time
	ctxErrAtEntry   error
	hasDeadline     bool
	deadline        time.Time
	originValueSeen bool
}

// outboxBatchProbeStore is a counting/blocking storage.OutboxClaimBatchStore
// over dbFakeStore. With a non-nil gate the aggregate release blocks until the
// test closes it (an unresponsive/slow release path) or the shared cleanup
// deadline expires; every per-row ReleaseOutboxClaim is recorded separately so
// the test can prove the fallback was NOT taken.
type outboxBatchProbeStore struct {
	*dbFakeStore
	gate    chan struct{}
	entered chan struct{}
	// releaseErr, when non-nil, is returned by ReleaseOutboxClaims without
	// clearing any claim (the logged-failure contract).
	releaseErr error

	mu          sync.Mutex
	batchCalls  []outboxBatchReleaseCall
	perRowCalls []string
}

var _ storage.OutboxClaimBatchStore = (*outboxBatchProbeStore)(nil)

func (s *outboxBatchProbeStore) ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error) {
	deadline, hasDeadline := ctx.Deadline()
	call := outboxBatchReleaseCall{
		ids:             append([]string(nil), ids...),
		claimer:         claimer,
		enteredAt:       time.Now(),
		ctxErrAtEntry:   ctx.Err(),
		hasDeadline:     hasDeadline,
		deadline:        deadline,
		originValueSeen: ctx.Value(outboxReleaseProbeKey{}) == "flush-origin",
	}
	s.mu.Lock()
	s.batchCalls = append(s.batchCalls, call)
	err := s.releaseErr
	s.mu.Unlock()
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if err != nil {
		return 0, err
	}
	// Emulate the aggregate statement: the whole slice is cleared through the
	// inner store (the per-row method of THIS probe is not used, so the
	// per-row counter stays a pure fallback detector).
	for _, id := range ids {
		_ = s.dbFakeStore.ReleaseOutboxClaim(ctx, id, claimer)
	}
	return len(ids), nil
}

func (s *outboxBatchProbeStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	s.mu.Lock()
	s.perRowCalls = append(s.perRowCalls, id)
	s.mu.Unlock()
	return s.dbFakeStore.ReleaseOutboxClaim(ctx, id, claimer)
}

func (s *outboxBatchProbeStore) snapshot() ([]outboxBatchReleaseCall, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]outboxBatchReleaseCall(nil), s.batchCalls...), append([]string(nil), s.perRowCalls...)
}

// TestOutboxFlushDBBatchClaimCleanupOneBatchRelease drives a full
// storage.OutboxClaimBatch (64) claim whose dispatch fails for every row (the
// pathological case the batch primitive exists for), with the aggregate
// release path held open to emulate a slow/unresponsive store. It proves the
// deferred cleanup issued exactly ONE ReleaseOutboxClaims call for the whole
// batch, under ONE fresh bounded deadline that outlives the cancelled dispatch
// context: no per-row fallback, no per-row deadline, no second call.
func TestOutboxFlushDBBatchClaimCleanupOneBatchRelease(t *testing.T) {
	inner := newDBFakeStore()
	probe := &outboxBatchProbeStore{dbFakeStore: inner, gate: make(chan struct{}), entered: make(chan struct{}, 1)}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	want := map[string]bool{}
	for i := 0; i < storage.OutboxClaimBatch; i++ {
		id := fmt.Sprintf("batch-%02d", i)
		want[id] = true
		if err := inner.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	s := New("token")
	if err := s.SwitchToDB(probe); err != nil {
		t.Fatal(err)
	}

	origin := context.WithValue(ctx, outboxReleaseProbeKey{}, "flush-origin")
	flushCtx, cancel := context.WithCancel(origin)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.outbox.Flush(flushCtx, func(context.Context, forge.OutboxItem) error {
			return errors.New("dispatch down")
		})
		done <- err
	}()
	// Cancel while the batch is still dispatching: the cleanup must not ride
	// this context (it would reach PostgreSQL already cancelled).
	cancel()

	select {
	case <-probe.entered:
	case err := <-done:
		t.Fatalf("flush returned before the claim cleanup ran: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("claim cleanup never ran")
	}

	// The slow release is still held: exactly one aggregate call is in
	// flight, the compatibility loop was not touched, and the call carries
	// the single shared bounded deadline.
	calls, perRow := probe.snapshot()
	if len(calls) != 1 || len(perRow) != 0 {
		t.Fatalf("cleanup calls while the slow release is held: batch=%d per-row=%d, want 1/0", len(calls), len(perRow))
	}
	if held, _ := probe.snapshot(); len(held) != 1 {
		t.Fatalf("a second cleanup call appeared while the first was held: %d", len(held))
	}
	call := calls[0]
	if len(call.ids) != len(want) {
		t.Fatalf("aggregate release ids = %d, want the whole %d-row batch", len(call.ids), len(want))
	}
	for _, id := range call.ids {
		if !want[id] {
			t.Fatalf("unexpected id in the aggregate release: %q", id)
		}
	}
	if call.ctxErrAtEntry != nil {
		t.Fatalf("cleanup rode the cancelled dispatch context: %v", call.ctxErrAtEntry)
	}
	if flushCtx.Err() == nil {
		t.Fatal("test setup: the dispatch context must be cancelled by now")
	}
	if !call.originValueSeen {
		t.Fatal("cleanup context dropped the origin values (boundedDetach must preserve them)")
	}
	if !call.hasDeadline {
		t.Fatal("cleanup context carries no deadline (the detach is not bounded)")
	}
	// One context, one call: the deadline is the fresh
	// outboxClaimReleaseTimeout window created by boundedDetach, not a
	// remnant of an inherited one. The generous slack only tolerates
	// scheduler delay between context creation and method entry.
	if !call.deadline.After(call.enteredAt) {
		t.Fatalf("cleanup deadline %s already expired at method entry %s", call.deadline, call.enteredAt)
	}
	if remaining := call.deadline.Sub(call.enteredAt); remaining > outboxClaimReleaseTimeout ||
		remaining <= outboxClaimReleaseTimeout-2*time.Second {
		t.Fatalf("cleanup deadline window = %s, want the shared %s bound", remaining, outboxClaimReleaseTimeout)
	}

	close(probe.gate)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the per-row dispatch failures must fail the flush")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("flush never returned after the release was unblocked")
	}
	calls, perRow = probe.snapshot()
	if len(calls) != 1 || len(perRow) != 0 {
		t.Fatalf("cleanup calls after the flush: batch=%d per-row=%d, want 1/0", len(calls), len(perRow))
	}
}

// TestOutboxFlushDBBatchClaimCleanupFailureLogged pins the batch-failure
// contract: a failing aggregate release is logged with the stranded count and
// the error (never discarded) and does not change the flush's own error.
func TestOutboxFlushDBBatchClaimCleanupFailureLogged(t *testing.T) {
	inner := newDBFakeStore()
	probe := &outboxBatchProbeStore{dbFakeStore: inner, releaseErr: errors.New("batch release down")}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	for i, id := range []string{"br-a", "br-b", "br-c"} {
		if err := inner.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := New("token")
	if err := s.SwitchToDB(probe); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLog)

	n, err := s.outbox.Flush(ctx, func(context.Context, forge.OutboxItem) error {
		return errors.New("dispatch down")
	})
	if err == nil {
		t.Fatal("the per-row dispatch failures must fail the flush")
	}
	if n != 0 {
		t.Fatalf("dispatched = %d, want 0", n)
	}
	calls, perRow := probe.snapshot()
	if len(calls) != 1 || len(perRow) != 0 {
		t.Fatalf("cleanup calls = batch %d / per-row %d, want 1/0", len(calls), len(perRow))
	}
	logged := buf.String()
	if !strings.Contains(logged, "batch release of 3 claim(s)") || !strings.Contains(logged, "batch release down") {
		t.Fatalf("aggregate release failure not logged with count and error: %q", logged)
	}
}

// outboxPerRowProbeStore has NO ReleaseOutboxClaims: it exercises the
// compatibility fallback for stores without the batch contract. OutboxRetry is
// a no-op so the claims can only be cleared by the release path, making the
// fallback's correctness observable.
type outboxPerRowProbeStore struct {
	*dbFakeStore
	mu       sync.Mutex
	released []string
}

func (s *outboxPerRowProbeStore) OutboxRetry(context.Context, string, error, int) error {
	return nil
}

func (s *outboxPerRowProbeStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	s.mu.Lock()
	s.released = append(s.released, id)
	s.mu.Unlock()
	return s.dbFakeStore.ReleaseOutboxClaim(ctx, id, claimer)
}

func (s *outboxPerRowProbeStore) releasedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.released...)
}

// TestOutboxFlushDBClaimCleanupFallbackWithoutBatchStore pins the fallback:
// a store without storage.OutboxClaimBatchStore still releases every claimed
// row exactly once through the per-row loop, the claims are cleared, and the
// missing contract is reported with the store type.
func TestOutboxFlushDBClaimCleanupFallbackWithoutBatchStore(t *testing.T) {
	inner := newDBFakeStore()
	probe := &outboxPerRowProbeStore{dbFakeStore: inner}
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Minute)
	want := []string{"cb-a", "cb-b", "cb-c"}
	for i, id := range want {
		if err := inner.OutboxAppend(ctx, storage.OutboxItem{
			ID: id, Kind: storage.OutboxKindUsageAccount, Payload: []byte(`{"job_id":"gone"}`),
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := New("token")
	if err := s.SwitchToDB(probe); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLog)

	n, err := s.outbox.Flush(ctx, func(context.Context, forge.OutboxItem) error {
		return errors.New("dispatch down")
	})
	if err == nil {
		t.Fatal("the per-row dispatch failures must fail the flush")
	}
	if n != 0 {
		t.Fatalf("dispatched = %d, want 0", n)
	}
	released := probe.releasedIDs()
	sort.Strings(released)
	if strings.Join(released, ",") != strings.Join(want, ",") {
		t.Fatalf("per-row releases = %v, want each of %v exactly once", released, want)
	}
	inner.mu.Lock()
	claimsLeft := len(inner.outboxClaims)
	inner.mu.Unlock()
	if claimsLeft != 0 {
		t.Fatalf("claims left after the fallback sweep = %d, want 0", claimsLeft)
	}
	logged := buf.String()
	if !strings.Contains(logged, "lacks storage.OutboxClaimBatchStore") ||
		!strings.Contains(logged, "outboxPerRowProbeStore") ||
		!strings.Contains(logged, "3 claim(s) row by row") {
		t.Fatalf("fallback not logged with the store type and count: %q", logged)
	}
}

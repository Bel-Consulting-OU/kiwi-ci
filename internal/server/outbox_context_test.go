package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// This file pins the context-coupling contract of the outbox/enroll paths:
//
//   - request-coupled durable operations thread the caller's context and a
//     cancellation aborts BEFORE anything is persisted or ACKed;
//   - operations that deliberately outlive their origin go through
//     boundedDetach (context.WithoutCancel + an explicit timeout), never a
//     bare context.Background();
//   - TestOwnedFilesPinContextCoupling encodes the classification as a
//     source-level guard so future reviews can check it mechanically.

// ctxAwareOutboxStore wraps dbFakeStore and makes the durable outbox writes
// observe the caller's context. With a non-nil gate and a never-closed gate
// channel a write waits until the context ends; closing the gate lets it
// proceed, which is how a bounded detach's survival is proven. With a nil
// gate the write waits for the context unconditionally (the bound test).
type ctxAwareOutboxStore struct {
	*dbFakeStore
	gate    chan struct{}
	entered chan struct{}
}

func (c *ctxAwareOutboxStore) blocked(ctx context.Context) error {
	if c.entered != nil {
		select {
		case c.entered <- struct{}{}:
		default:
		}
	}
	if c.gate != nil {
		select {
		case <-c.gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (c *ctxAwareOutboxStore) OutboxAppend(ctx context.Context, e storage.OutboxItem) error {
	if err := c.blocked(ctx); err != nil {
		return err
	}
	return c.dbFakeStore.OutboxAppend(ctx, e)
}

func (c *ctxAwareOutboxStore) OutboxEnqueueVersioned(ctx context.Context, e storage.OutboxItem) (storage.VersionedEnqueueOutcome, error) {
	if err := c.blocked(ctx); err != nil {
		return storage.VersionedEnqueued, err
	}
	return c.dbFakeStore.OutboxEnqueueVersioned(ctx, e)
}

// ctxHonoringOutboxStore mirrors the SQL store's fail-closed behavior for a
// canceled context: ClaimOutbox refuses (with the context error) instead of
// pretending the durable outbox is empty.
type ctxHonoringOutboxStore struct {
	*dbFakeStore
	mu       sync.Mutex
	claimErr error
}

func (c *ctxHonoringOutboxStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]storage.OutboxItem, error) {
	if err := ctx.Err(); err != nil {
		c.mu.Lock()
		c.claimErr = err
		c.mu.Unlock()
		return nil, err
	}
	return c.dbFakeStore.ClaimOutbox(ctx, claimer, limit)
}

// ctxAwareGrantStore wraps dbFakeStore so the durable grant reads observe the
// caller's context. A non-nil, never-closed gate blocks the read until the
// context ends; closing it lets the read proceed.
type ctxAwareGrantStore struct {
	*dbFakeStore
	gate    chan struct{}
	entered chan struct{}
}

func (c *ctxAwareGrantStore) GetEnrollGrant(ctx context.Context, digest string) (storage.EnrollGrantRecord, bool, error) {
	if c.entered != nil {
		select {
		case c.entered <- struct{}{}:
		default:
		}
	}
	if c.gate != nil {
		select {
		case <-c.gate:
			return c.dbFakeStore.GetEnrollGrant(ctx, digest)
		case <-ctx.Done():
			return storage.EnrollGrantRecord{}, false, ctx.Err()
		}
	}
	<-ctx.Done()
	return storage.EnrollGrantRecord{}, false, ctx.Err()
}

// TestOutboxEnqueueHonorsCanceledRequestContext is (a): a canceled request
// context reaching a mutating Enqueue must abort, leaving no durable row and
// no dispatchable local copy — for plain and for versioned (forge-check)
// intents alike.
func TestOutboxEnqueueHonorsCanceledRequestContext(t *testing.T) {
	store := &ctxAwareOutboxStore{
		dbFakeStore: newDBFakeStore(),
		gate:        make(chan struct{}),
		entered:     make(chan struct{}, 1),
	}
	o := NewOutbox(nil)
	o.AttachDB(store)

	canceledEnqueue(t, o, store, forge.OutboxItem{
		ID: "plain-cancel", Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}"),
	})
	canceledEnqueue(t, o, store, forge.OutboxItem{
		ID: "logical#1", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}"),
		LogicalKey: "logical", StateVersion: 1,
	})

	store.mu.Lock()
	rows := len(store.outboxItems)
	store.mu.Unlock()
	if rows != 0 {
		t.Fatalf("canceled enqueues left %d durable row(s); want 0 (no half-persisted intent)", rows)
	}
	if got := o.Pending(); len(got) != 0 {
		t.Fatalf("canceled enqueues left %d local item(s); want 0", len(got))
	}
}

// TestOutboxVersionedEnqueueCanceledKeepsExistingRow is the supersede-side of
// (a): a canceled newer version must not delete or replace the older durable
// row, so the fs/DB watermark ordering is never advanced by a request that
// never persisted.
func TestOutboxVersionedEnqueueCanceledKeepsExistingRow(t *testing.T) {
	store := &ctxAwareOutboxStore{dbFakeStore: newDBFakeStore()}
	o := NewOutbox(nil)
	o.AttachDB(store)
	older := storage.OutboxItem{
		ID: "logical#1", Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{"state":"queued"}`),
		LogicalKey: "logical", StateVersion: 1,
	}
	if _, err := store.dbFakeStore.OutboxEnqueueVersioned(context.Background(), older); err != nil {
		t.Fatal(err)
	}

	// Block the durable write for the newer version, then cancel it.
	store.gate = make(chan struct{})
	store.entered = make(chan struct{}, 1)
	canceledEnqueue(t, o, store, forge.OutboxItem{
		ID: "logical#2", Kind: forge.OutboxKindGitHubCheck, Payload: []byte(`{"state":"completed"}`),
		LogicalKey: "logical", StateVersion: 2,
	})

	store.mu.Lock()
	rows := append([]storage.OutboxItem(nil), store.outboxItems...)
	store.mu.Unlock()
	if len(rows) != 1 || rows[0].ID != older.ID {
		t.Fatalf("durable rows after canceled supersede = %+v; want the surviving %s", rows, older.ID)
	}
	if pending := o.Pending(); len(pending) != 0 {
		t.Fatalf("local queue after canceled supersede = %+v; want none", pending)
	}
}

// canceledEnqueue drives one Enqueue on ctx and cancels the context once the
// durable write is entered, asserting the abort contract.
func canceledEnqueue(t *testing.T, o *Outbox, store *ctxAwareOutboxStore, item forge.OutboxItem) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- o.Enqueue(ctx, item) }()
	select {
	case <-store.entered:
	case err := <-done:
		t.Fatalf("Enqueue(%s) returned before the durable write: %v", item.ID, err)
	case <-time.After(2 * time.Second):
		t.Fatalf("Enqueue(%s) never reached the durable write", item.ID)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Enqueue(%s) = %v; want context.Canceled", item.ID, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Enqueue(%s) ignored the canceled context", item.ID)
	}
}

// TestOutboxFlushCanceledContextNeverAcks is (a) for the dispatch side: a
// canceled flush context must fail closed at the durable claim, dispatching
// nothing and ACKing nothing.
func TestOutboxFlushCanceledContextNeverAcks(t *testing.T) {
	store := &ctxHonoringOutboxStore{dbFakeStore: newDBFakeStore()}
	o := NewOutbox(nil)
	o.AttachDB(store)
	item := forge.OutboxItem{ID: "durable-1", Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}")}
	if err := o.Enqueue(context.Background(), item); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dispatched := 0
	if _, err := o.Flush(ctx, func(context.Context, forge.OutboxItem) error {
		dispatched++
		return nil
	}); err == nil {
		t.Fatal("flush with a canceled context must fail closed")
	}
	if dispatched != 0 {
		t.Fatalf("canceled flush dispatched %d intent(s); want 0", dispatched)
	}
	store.mu.Lock()
	acked := len(store.outboxAcked)
	rows := len(store.outboxItems)
	store.mu.Unlock()
	if acked != 0 || rows != 1 {
		t.Fatalf("canceled flush acked=%d durable rows=%d; want 0/1 (never ACK without persistence)", acked, rows)
	}
}

// TestEnrollGrantConsumeHonorsCanceledRequestContext is (a) for the enroll
// path: a canceled enroll request must fail the durable read/consume and
// leave the single-use grant consumable, never issuing a certificate off a
// consumption that did not persist.
func TestEnrollGrantConsumeHonorsCanceledRequestContext(t *testing.T) {
	store := &ctxAwareGrantStore{
		dbFakeStore: newDBFakeStore(),
		gate:        make(chan struct{}),
		entered:     make(chan struct{}, 1),
	}
	s := New("token")
	s.DB = store
	digest := auth.TokenDigest("grant-tok")
	if err := store.dbFakeStore.PutEnrollGrant(context.Background(), digest, time.Now().UTC().Add(time.Hour), []string{"container"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.consumeEnrollGrant(ctx, "grant-tok", []string{"container"}) }()
	select {
	case <-store.entered:
	case err := <-done:
		t.Fatalf("consumeEnrollGrant returned before the durable read: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("consumeEnrollGrant never reached the durable read")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("consumeEnrollGrant = %v; want a wrapped context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consumeEnrollGrant ignored the canceled context")
	}

	rec, ok, err := store.dbFakeStore.GetEnrollGrant(context.Background(), digest)
	if err != nil || !ok {
		t.Fatalf("grant after canceled consume: ok=%v err=%v; want still stored", ok, err)
	}
	if rec.Consumed {
		t.Fatal("canceled consume mutated the grant; it must stay consumable")
	}
}

// TestEnrollGrantOKRejectsCanceledRequest pins the auth-tier contract: a
// canceled request is never validated against the durable grant store. The
// plain fake ignores contexts, so the false result can only come from the
// early ctx guard in enrollGrantOK itself.
func TestEnrollGrantOKRejectsCanceledRequest(t *testing.T) {
	store := newDBFakeStore()
	s := New("token")
	s.DB = store
	digest := auth.TokenDigest("live-tok")
	if err := store.PutEnrollGrant(context.Background(), digest, time.Now().UTC().Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if !s.enrollGrantOK(context.Background(), "live-tok") {
		t.Fatal("live grant must validate with a live context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.enrollGrantOK(ctx, "live-tok") {
		t.Fatal("enrollGrantOK validated a canceled request")
	}
}

// TestBoundedDetachPersistsWhenOriginCanceled is (b): the sanctioned detach
// keeps the durable write alive after the origin context is canceled, and the
// write still persists. The store only proceeds once released, proving the
// operation was held by the detach rather than by a race.
func TestBoundedDetachPersistsWhenOriginCanceled(t *testing.T) {
	store := &ctxAwareOutboxStore{
		dbFakeStore: newDBFakeStore(),
		gate:        make(chan struct{}),
		entered:     make(chan struct{}, 1),
	}
	o := NewOutbox(nil)
	o.AttachDB(store)

	origin, cancelOrigin := context.WithCancel(context.Background())
	cancelOrigin()
	detached, cancelDetach := boundedDetach(origin, 5*time.Second)
	defer cancelDetach()

	done := make(chan error, 1)
	go func() {
		done <- o.Enqueue(detached, forge.OutboxItem{
			ID: "detached-1", Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}"),
		})
	}()
	select {
	case <-store.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("detached enqueue never reached the durable write")
	}
	if !errors.Is(origin.Err(), context.Canceled) {
		t.Fatalf("origin = %v; want canceled", origin.Err())
	}
	if err := detached.Err(); err != nil {
		t.Fatalf("detached context inherited the origin cancellation: %v", err)
	}
	close(store.gate)
	if err := <-done; err != nil {
		t.Fatalf("detached enqueue = %v; want persisted", err)
	}
	store.mu.Lock()
	rows := len(store.outboxItems)
	store.mu.Unlock()
	if rows != 1 {
		t.Fatalf("detached enqueue persisted %d row(s); want 1 despite the canceled origin", rows)
	}
}

// TestBoundedDetachIsBounded proves the other half of (b): the detach carries
// its own deadline, so a stalled store ends the operation instead of pinning
// it forever, and the timed-out write leaves nothing behind.
func TestBoundedDetachIsBounded(t *testing.T) {
	store := &ctxAwareOutboxStore{dbFakeStore: newDBFakeStore()} // nil gate: waits for the context
	o := NewOutbox(nil)
	o.AttachDB(store)

	origin, cancelOrigin := context.WithCancel(context.Background())
	cancelOrigin()
	detached, cancelDetach := boundedDetach(origin, 50*time.Millisecond)
	defer cancelDetach()

	start := time.Now()
	err := o.Enqueue(detached, forge.OutboxItem{
		ID: "bounded-1", Kind: forge.OutboxKindGitHubStatus, Payload: []byte("{}"),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded enqueue = %v; want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bounded detach took %s; the bound was not enforced", elapsed)
	}
	store.mu.Lock()
	rows := len(store.outboxItems)
	store.mu.Unlock()
	if rows != 0 {
		t.Fatalf("timed-out enqueue persisted %d row(s); want 0", rows)
	}
}

// claimProbeStore records whether the flush passed it a live context.
type claimProbeStore struct {
	*dbFakeStore
	mu       sync.Mutex
	claimErr error
}

func (p *claimProbeStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]storage.OutboxItem, error) {
	if err := ctx.Err(); err != nil {
		p.mu.Lock()
		p.claimErr = err
		p.mu.Unlock()
		return nil, err
	}
	return p.dbFakeStore.ClaimOutbox(ctx, claimer, limit)
}

// TestFlushOutboxDetachesFromCanceledMaintainContext pins that the production
// flush cycle (boundedDetach inside flushOutbox) does not hand the maintain
// loop's cancellation to the durable store: a regression to a direct ctx pass
// would make every claim fail the moment the tick context ends.
func TestFlushOutboxDetachesFromCanceledMaintainContext(t *testing.T) {
	probe := &claimProbeStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	s.outbox.AttachDB(probe)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.flushOutbox(ctx)

	probe.mu.Lock()
	err := probe.claimErr
	probe.mu.Unlock()
	if err != nil {
		t.Fatalf("flushOutbox passed the canceled maintain context into the store: %v", err)
	}
}

// TestPublishForgeStatusHonorsCanceledRequestContext is the FAIL-before shape:
// on the detached (background) enqueue path a canceled request could not
// reach the durable write. publishForgeStatus now threads its ctx into
// Enqueue, so the cancellation aborts the loop and nothing is recorded.
func TestPublishForgeStatusHonorsCanceledRequestContext(t *testing.T) {
	store := &ctxAwareOutboxStore{
		dbFakeStore: newDBFakeStore(),
		gate:        make(chan struct{}),
		entered:     make(chan struct{}, 1),
	}
	defer close(store.gate)
	s := New("token")
	s.GitHubToken = "tok"
	s.outbox.AttachDB(store)
	run := model.Run{
		ID: "run-ctx", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha", Status: model.StatusQueued,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.publishForgeStatus(ctx, run) }()
	select {
	case <-store.entered:
	case err := <-done:
		t.Fatalf("publishForgeStatus returned before the durable write: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("publishForgeStatus never reached the durable write")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("publishForgeStatus = %v; want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publishForgeStatus ignored the canceled request context and stayed blocked in a detached durable write")
	}
	if got := s.outbox.Pending(); len(got) != 0 {
		t.Fatalf("canceled publish left %d local item(s); want 0", len(got))
	}
	store.mu.Lock()
	rows := len(store.outboxItems)
	store.mu.Unlock()
	if rows != 0 {
		t.Fatalf("canceled publish left %d durable row(s); want 0", rows)
	}
}

// backgroundAllowMarker is the inline justification a bare
// context.Background()/context.TODO() must carry in the files this fix owns.
const backgroundAllowMarker = "allow-background:"

// TestOwnedFilesPinContextCoupling is (c): the encoded classification. Every
// context.Background()/context.TODO() in the owned files must be annotated as
// a sanctioned detach root, and the server.go call sites this fix touched
// must keep threading a real caller context or the bounded detach. The
// enqueue plumbing and the audit-first path are additionally scanned per
// function body: neither may contain a bare Background/TODO at all, so the
// only detach root on those paths is boundedDetach's own (annotated) one.
//
// Documented checklist for the reviewer (the same list is asserted below):
//
//	threaded caller context (abort on cancellation):
//	  server.go   s.enrollGrantOK(r.Context(), tok)
//	  server.go   s.repairCompletionIntents(r.Context(), ...)
//	  server.go   s.reconcileCompletionEffects(r.Context(), ...)
//	  server.go   s.enqueueCompletionEffects(r.Context(), j, run)
//	  server.go   s.recordDownstreamIntents(r.Context(), j, run)
//	  runnerpki.go s.consumeEnrollGrant(r.Context(), tok, in.Labels)
//	  github_status.go / completion_effects.go / downstream.go: Enqueue(ctx, ...)
//	  server.go   s.startSpan(ctx, "server.enqueue")
//	  server.go   s.enqueue(r.Context(), in)                [submit/rerun]
//	  server.go   s.enqueueID(ctx, in, "")                  [enqueue wrapper]
//	  server.go   s.enqueueDB(ctx, in, run, ...)            [DB run creation]
//	  server.go   s.auditFirstLocked(r.Context(), ...)      [admin mutations]
//	  github.go / hooks.go: s.enqueue(r.Context(), in)      [webhooks]
//	  schedules.go: s.enqueueID(ctx, in, preID)             [schedule firing]
//	  downstream.go: s.enqueueID(ctx, SubmitRun{...})       [outbox re-enqueue]
//	bounded detach (intentionally outlives the request, bounded by timeout):
//	  server.go   s.publishForgeStatus(pubCtx, run)   [run already durable]
//	  server.go   auditLocked -> boundedDetach(nil, auditDetachTimeout)
//	  outbox.go   flushOutbox(ctx) -> boundedDetach(ctx, outboxFlushTimeout)
//	  outbox.go   releaseOutboxClaimCleanup (claim cleanup)
func TestOwnedFilesPinContextCoupling(t *testing.T) {
	owned := []string{"outbox.go", "enroll_grants.go", "completion_effects.go", "github_status.go", "server.go"}
	for _, name := range owned {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, "context.Background()") && !strings.Contains(line, "context.TODO()") {
				continue
			}
			if !strings.Contains(line, backgroundAllowMarker) {
				t.Errorf("%s:%d uses context.Background/TODO without an %q justification: %s",
					name, i+1, backgroundAllowMarker, strings.TrimSpace(line))
			}
		}
	}

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, want := range []string{
		"s.enrollGrantOK(r.Context(), tok)",
		"s.repairCompletionIntents(r.Context(), jobID, in.LeaseGeneration)",
		"s.enqueueCompletionEffects(r.Context(), j, run)",
		"s.recordDownstreamIntents(r.Context(), j, run)",
		"s.publishForgeStatus(pubCtx, run)",
		"s.flushOutbox(ctx)",
		"s.startSpan(ctx, \"server.enqueue\")",
		"s.enqueue(r.Context(), in)",
		"s.enqueue(r.Context(), SubmitRun{",
		"s.enqueueID(ctx, in, \"\")",
		"s.enqueueDB(ctx, in, run, created, jobContracts, group,",
		"s.auditFirstLocked(r.Context(), \"runner.drain\",",
		"s.auditFirstLocked(r.Context(), \"runner.disable\",",
		"s.auditFirstLocked(r.Context(), \"runner.enable\",",
		"s.auditFirstLocked(r.Context(), \"job.approved\",",
		"s.auditFirstLocked(r.Context(), \"run.cancelled\",",
		"s.auditFirstLocked(ctx, \"job.approved\",",
		"s.auditFirstLocked(ctx, \"run.cancelled\",",
		"boundedDetach(ctx, outboxDetachTimeout)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("server.go: missing context-threaded call site %q", want)
		}
	}
	for _, banned := range []string{
		"s.repairCompletionIntents(context.Background()",
		"s.enqueueCompletionEffects(context.Background()",
		"s.recordDownstreamIntents(context.Background()",
		"s.enrollGrantOK(context.Background()",
		"s.consumeEnrollGrant(context.Background()",
		"s.publishForgeStatus(context.Background()",
		"s.flushOutbox()",
		"startSpan(context.Background(), \"server.enqueue\")",
		"s.enqueue(in)",
		"s.enqueueID(in,",
		"s.enqueueDB(in,",
		"s.auditFirstLocked(\"",
		"s.DB.AppendAudit(context.Background(",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("server.go: request-coupled call site regressed to a bare context: %q", banned)
		}
	}

	// The out-of-server.go production callers thread their own request or
	// maintenance context; pin the exact call shape (and the unthreaded
	// regression) in each file.
	for _, tc := range []struct{ file, want, banned string }{
		{"github.go", "s.enqueue(r.Context(), in)", "s.enqueue(in)"},
		{"hooks.go", "s.enqueue(r.Context(), in)", "s.enqueue(in)"},
		{"schedules.go", "s.enqueueID(ctx, in, preID)", "s.enqueueID(in,"},
		{"downstream.go", "s.enqueueID(ctx, SubmitRun{", "s.enqueueID(in,"},
	} {
		bs, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(bs), tc.want) {
			t.Errorf("%s: missing context-threaded call site %q", tc.file, tc.want)
		}
		if strings.Contains(string(bs), tc.banned) {
			t.Errorf("%s: enqueue call site regressed to a bare context: %q", tc.file, tc.banned)
		}
	}

	// The enqueue plumbing and the audit-first path are the defect surface of
	// this fix: pin their function bodies to hold NO context root at all. The
	// only sanctioned root reachable from them is boundedDetach's own.
	for _, sig := range []string{
		"func (s *Server) enqueue(ctx context.Context,",
		"func (s *Server) enqueueID(ctx context.Context,",
		"func (s *Server) enqueueDB(ctx context.Context,",
		"func (s *Server) auditFirstLocked(ctx context.Context,",
		"func (s *Server) auditLocked(",
	} {
		fn, ok := functionBody(body, sig)
		if !ok {
			t.Errorf("server.go: missing threaded signature %q", sig)
			continue
		}
		for _, root := range []string{"context.Background()", "context.TODO()"} {
			if strings.Contains(fn, root) {
				t.Errorf("server.go: %s contains a bare %s; enqueue/audit must thread ctx or use boundedDetach", sig, root)
			}
		}
	}

	// boundedDetach (outbox.go) is the single sanctioned root: it must stay
	// nil-safe and carry the allow-marker so the server.go call paths above
	// can detach without an origin.
	ob, err := os.ReadFile("outbox.go")
	if err != nil {
		t.Fatal(err)
	}
	detach, ok := functionBody(string(ob), "func boundedDetach(")
	if !ok {
		t.Fatal("outbox.go: boundedDetach not found")
	}
	if !strings.Contains(detach, "if origin == nil {") || !strings.Contains(detach, "origin = context.Background() // allow-background:") {
		t.Fatalf("outbox.go: boundedDetach is not nil-safe with a marked root:\n%s", detach)
	}

	// releaseOutboxClaimCleanup must detach through that single sanctioned
	// helper: its former inline WithTimeout(WithoutCancel(...)) was a second,
	// undocumented detach implementation that could drift from the invariant.
	cleanup, ok := functionBody(string(ob), "func (o *Outbox) releaseOutboxClaimCleanup(")
	if !ok {
		t.Fatal("outbox.go: releaseOutboxClaimCleanup not found")
	}
	if !strings.Contains(cleanup, "boundedDetach(ctx, outboxClaimReleaseTimeout)") {
		t.Fatalf("outbox.go: releaseOutboxClaimCleanup does not use the sanctioned boundedDetach:\n%s", cleanup)
	}
	for _, raw := range []string{"context.WithoutCancel", "context.WithTimeout", "context.Background()"} {
		if strings.Contains(cleanup, raw) {
			t.Fatalf("outbox.go: releaseOutboxClaimCleanup re-implements the detach with %s:\n%s", raw, cleanup)
		}
	}
}

// functionBody returns the source of the function whose definition line starts
// with sig, up to the next top-level func definition (or EOF).
func functionBody(src, sig string) (string, bool) {
	start := strings.Index(src, sig)
	if start < 0 {
		return "", false
	}
	rest := src[start:]
	if end := strings.Index(rest[1:], "\nfunc "); end >= 0 {
		return rest[:end+1], true
	}
	return rest, true
}

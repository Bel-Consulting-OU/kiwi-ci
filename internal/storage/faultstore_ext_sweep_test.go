package storage

// Extension-surface sweep for the in-memory store and the fault-injection
// wrapper: the clock/liveness contracts, versioned outbox enqueue/guard/retry,
// deployment start/finish, lease-fenced test-report delivery, enrollment-grant
// liveness, the recovery fault-injection stages and the pure overlay helpers.
// Every test asserts observable behavior (returned errors, persisted state,
// emitted audit/execution events), not merely that a line ran.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestMemStoreClockLivenessAndRetentionSurface exercises the clock/liveness
// reads the extension contracts expose: Now, LeaseLive (miss/wrong-holder/
// expired/live), TouchRunnerLastSeen, the execution-event watermark/prune and
// the log high-water, plus the schema floor.
func TestMemStoreClockLivenessAndRetentionSurface(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()

	if got, err := m.Now(ctx); err != nil || !got.After(time.Time{}) {
		t.Fatalf("Now = (%v, %v), want a real instant", got, err)
	}
	if floor, err := m.SchemaCompatibilityFloor(ctx); err != nil || floor != 0 {
		t.Fatalf("SchemaCompatibilityFloor = (%d, %v), want (0, nil)", floor, err)
	}

	// LeaseLive: unknown job, live lease, expired lease, wrong generation.
	if live, err := m.LeaseLive(ctx, testJob.ID, testRunner.ID, 1); err != nil || live {
		t.Fatalf("LeaseLive(unknown) = (%v, %v), want false/nil", live, err)
	}
	seedRunAndJob(m)
	if err := m.UpsertRunner(ctx, model.Runner{ID: testRunner.ID, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	if _, err := m.AcquireLease(ctx, testJob.ID, testRunner.ID, []byte{1}, 3, future); err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if live, err := m.LeaseLive(ctx, testJob.ID, testRunner.ID, 3); err != nil || !live {
		t.Fatalf("LeaseLive(live) = (%v, %v), want true/nil", live, err)
	}
	if live, err := m.LeaseLive(ctx, testJob.ID, testRunner.ID, 4); err != nil || live {
		t.Fatalf("LeaseLive(wrong generation) = (%v, %v), want false/nil", live, err)
	}
	if live, err := m.LeaseLive(ctx, testJob.ID, strings.Repeat("9", 32), 3); err != nil || live {
		t.Fatalf("LeaseLive(wrong runner) = (%v, %v), want false/nil", live, err)
	}
	m.mu.Lock()
	j := m.jobs[testJob.ID]
	past := time.Now().UTC().Add(-time.Minute)
	j.LeaseExpiresAt = &past
	m.jobs[testJob.ID] = j
	m.mu.Unlock()
	if live, err := m.LeaseLive(ctx, testJob.ID, testRunner.ID, 3); err != nil || live {
		t.Fatalf("LeaseLive(expired) = (%v, %v), want false/nil", live, err)
	}

	// TouchRunnerLastSeen: unknown runner fails, known runner moves the field.
	if err := m.TouchRunnerLastSeen(ctx, strings.Repeat("9", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TouchRunnerLastSeen(unknown) = %v, want ErrNotFound", err)
	}
	if err := m.TouchRunnerLastSeen(ctx, testRunner.ID); err != nil {
		t.Fatalf("TouchRunnerLastSeen: %v", err)
	}
	if r, _ := m.GetRunner(ctx, testRunner.ID); r.LastSeen.IsZero() {
		t.Fatalf("last-seen not stamped")
	}

	// LatestLogSeq reads the per-run high-water, never another run's rows.
	if seq, err := m.LatestLogSeq(ctx, "run-x"); err != nil || seq != 0 {
		t.Fatalf("LatestLogSeq(empty) = (%d, %v), want 0/nil", seq, err)
	}
	for _, e := range []model.LogEntry{{RunID: "run-x", Seq: 2}, {RunID: "run-x", Seq: 7}, {RunID: "run-y", Seq: 9}} {
		if err := m.AppendLog(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if seq, err := m.LatestLogSeq(ctx, "run-x"); err != nil || seq != 7 {
		t.Fatalf("LatestLogSeq(run-x) = (%d, %v), want 7/nil", seq, err)
	}

	// Execution-event retention: append, prune the prefix, read the watermark.
	old := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		if err := m.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-x", CreatedAt: old}); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	pending := len(m.events)
	m.mu.Unlock()
	got, err := m.ExecutionEventRetainedFrom(ctx)
	if err != nil || got != 0 {
		t.Fatalf("retainedFrom before prune = (%d, %v)", got, err)
	}
	removed, from, err := m.PruneExecutionEvents(ctx, time.Now().UTC(), 0)
	if err != nil || removed != int64(pending) || from != int64(pending) {
		t.Fatalf("PruneExecutionEvents = (%d, %d, %v), want (%d, %d, nil)", removed, from, err, pending, pending)
	}
	if got, err := m.ExecutionEventRetainedFrom(ctx); err != nil || got != int64(pending) {
		t.Fatalf("retainedFrom after prune = (%d, %v), want %d/nil", got, err, pending)
	}
	// Nothing older than the cutoff (all rows already pruned) is a no-op.
	if removed, from, err := m.PruneExecutionEvents(ctx, time.Now().UTC(), 0); err != nil || removed != 0 || from != int64(pending) {
		t.Fatalf("idempotent prune = (%d, %d, %v), want (0, %d, nil)", removed, from, err, pending)
	}

	// EnrollGrantLive: unknown, live, consumed, expired.
	if live, err := m.EnrollGrantLive(ctx, "digest-unknown"); err != nil || live {
		t.Fatalf("EnrollGrantLive(unknown) = (%v, %v)", live, err)
	}
	if _, err := m.PutEnrollGrantWithTTL(ctx, "digest-live", time.Hour, []string{"linux"}); err != nil {
		t.Fatal(err)
	}
	if live, err := m.EnrollGrantLive(ctx, "digest-live"); err != nil || !live {
		t.Fatalf("EnrollGrantLive(live) = (%v, %v)", live, err)
	}
	if _, err := m.ConsumeEnrollGrant(ctx, "digest-live", "runner-1"); err != nil {
		t.Fatal(err)
	}
	if live, err := m.EnrollGrantLive(ctx, "digest-live"); err != nil || live {
		t.Fatalf("EnrollGrantLive(consumed) = (%v, %v), want false/nil", live, err)
	}
	if _, err := m.PutEnrollGrantWithTTL(ctx, "digest-expired", time.Nanosecond, nil); err != nil {
		t.Fatal(err)
	}
	if live, err := m.EnrollGrantLive(ctx, "digest-expired"); err != nil || live {
		t.Fatalf("EnrollGrantLive(expired) = (%v, %v), want false/nil", live, err)
	}
}

// TestFaultyStoreClockAndRetentionParity pins the wrapper contract of the
// clock/liveness/retention delegates: pass-through reaches the inner store, an
// armed fault surfaces before any state is touched, and a minimal inner store
// fails closed with the typed missing-interface error.
func TestFaultyStoreClockAndRetentionParity(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	seedRunAndJob(inner)
	if err := inner.UpsertRunner(ctx, model.Runner{ID: testRunner.ID, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	if _, err := inner.AcquireLease(ctx, testJob.ID, testRunner.ID, []byte{1}, 2, future); err != nil {
		t.Fatal(err)
	}
	fs := &FaultyStore{Inner: inner}
	if now, err := fs.Now(ctx); err != nil || now.IsZero() {
		t.Fatalf("Now pass-through = (%v, %v)", now, err)
	}
	if live, err := fs.LeaseLive(ctx, testJob.ID, testRunner.ID, 2); err != nil || !live {
		t.Fatalf("LeaseLive pass-through = (%v, %v)", live, err)
	}
	if err := fs.TouchRunnerLastSeen(ctx, testRunner.ID); err != nil {
		t.Fatalf("TouchRunnerLastSeen pass-through: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := fs.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: testRun.ID, CreatedAt: time.Now().UTC().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	inner.mu.Lock()
	pending := len(inner.events)
	inner.mu.Unlock()
	if removed, from, err := fs.PruneExecutionEvents(ctx, time.Now().UTC(), 10); err != nil || removed != int64(pending) || from != int64(pending) {
		t.Fatalf("PruneExecutionEvents pass-through = (%d, %d, %v), want (%d, _, nil)", removed, from, err, pending)
	}
	if from, err := fs.ExecutionEventRetainedFrom(ctx); err != nil || from != int64(pending) {
		t.Fatalf("ExecutionEventRetainedFrom pass-through = (%d, %v)", from, err)
	}

	armed := func() *FaultyStore { return &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom} }
	if _, err := armed().Now(ctx); !errors.Is(err, errBoom) {
		t.Fatalf("armed Now = %v, want injected", err)
	}
	if _, err := armed().LeaseLive(ctx, testJob.ID, testRunner.ID, 2); !errors.Is(err, errBoom) {
		t.Fatalf("armed LeaseLive = %v, want injected", err)
	}
	if err := armed().TouchRunnerLastSeen(ctx, testRunner.ID); !errors.Is(err, errBoom) {
		t.Fatalf("armed TouchRunnerLastSeen = %v, want injected", err)
	}
	if err := armed().AppendExecutionEvent(ctx, model.ExecutionEvent{}); !errors.Is(err, errBoom) {
		t.Fatalf("armed AppendExecutionEvent = %v, want injected", err)
	}

	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.Now(ctx); err == nil {
		t.Fatal("Now without ClockStore succeeded")
	}
	if _, err := missing.LeaseLive(ctx, testJob.ID, testRunner.ID, 2); err == nil {
		t.Fatal("LeaseLive without LiveLeaseStore succeeded")
	}
	if err := missing.TouchRunnerLastSeen(ctx, testRunner.ID); err == nil {
		t.Fatal("TouchRunnerLastSeen without RunnerHeartbeatStore succeeded")
	}
	if err := missing.AppendExecutionEvent(ctx, model.ExecutionEvent{}); err == nil {
		t.Fatal("AppendExecutionEvent without ExecutionEventStore succeeded")
	}
	if _, _, err := missing.PruneExecutionEvents(ctx, time.Now(), 1); err == nil {
		t.Fatal("PruneExecutionEvents without RetentionExecutionEventStore succeeded")
	}
	if _, err := missing.ExecutionEventRetainedFrom(ctx); err == nil {
		t.Fatal("ExecutionEventRetainedFrom without RetentionExecutionEventStore succeeded")
	}
}

// TestFaultyStoreRegisterRunnerAndRevokeLeasesParity covers the transactional
// registration swap wrapper: pass-through delegates, an armed fault aborts
// before the inner store is touched, and a minimal store fails closed.
func TestFaultyStoreRegisterRunnerAndRevokeLeasesParity(t *testing.T) {
	ctx := context.Background()
	inner := &registrationFakeStore{}
	fs := &FaultyStore{Inner: inner}
	runner := model.Runner{ID: strings.Repeat("7", 32), Name: "r7", Capacity: 1}
	revoked, err := fs.RegisterRunnerAndRevokeLeases(ctx, runner, "replaced")
	if err != nil || len(revoked) != 1 || revoked[0] != "revoked-job" {
		t.Fatalf("register pass-through = (%v, %v)", revoked, err)
	}
	if len(inner.registered) != 1 || inner.registered[0].Name != "r7" || inner.reason != "replaced" {
		t.Fatalf("registration did not reach the inner store: %+v", inner)
	}
	armed := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	if _, err := armed.RegisterRunnerAndRevokeLeases(ctx, model.Runner{ID: runner.ID, Name: "r7-new"}, "replaced"); !errors.Is(err, errBoom) {
		t.Fatalf("armed register = %v, want injected", err)
	}
	if len(inner.registered) != 1 {
		t.Fatalf("faulted registration reached the inner store: %+v", inner.registered)
	}
	// memStore deliberately does not implement the transactional registration
	// swap, so the wrapper must fail closed rather than fake a success.
	if _, err := (&FaultyStore{Inner: newMemStore()}).RegisterRunnerAndRevokeLeases(ctx, runner, "x"); err == nil {
		t.Fatal("register over a store without RunnerRegistrationStore succeeded")
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).RegisterRunnerAndRevokeLeases(ctx, runner, "x"); err == nil {
		t.Fatal("register without RunnerRegistrationStore succeeded")
	}
}

// registrationFakeStore is the minimal inner that implements exactly the
// transactional RunnerRegistrationStore contract over the inert Store stub.
type registrationFakeStore struct {
	storeOnlyInner
	registered []model.Runner
	reason     string
}

func (f *registrationFakeStore) RegisterRunnerAndRevokeLeases(_ context.Context, runner model.Runner, reason string) ([]string, error) {
	f.registered = append(f.registered, runner)
	f.reason = reason
	return []string{"revoked-job"}, nil
}

// TestMemStoreOutboxVersionedGuardAndRetry exercises the versioned forge-state
// surface: enqueue supersede semantics (including dead-letter preservation and
// equal-version supersede), the guard's alive/delivered/newer-pending
// predicate, the delivered watermark, the claim-guarded retry/dead-letter
// transition and the batch claim release.
func TestMemStoreOutboxVersionedGuardAndRetry(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	item := func(id string, version int64) OutboxItem {
		return OutboxItem{ID: id, Kind: "github_check", Payload: []byte(`{"v":1}`), CreatedAt: time.Now().UTC(), LogicalKey: "lk", StateVersion: version}
	}

	// Input contract: a logical key and positive version are required.
	if _, err := m.OutboxEnqueueVersioned(ctx, OutboxItem{ID: "no-key"}); err == nil {
		t.Fatal("enqueue without logical key succeeded")
	}
	if _, err := m.OutboxEnqueueVersioned(ctx, OutboxItem{ID: "no-ver", LogicalKey: "lk"}); err == nil {
		t.Fatal("enqueue without version succeeded")
	}
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#1", 1)); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue v1 = (%v, %v)", out, err)
	}
	// A newer enqueue supersedes the older pending row (and its claim).
	if _, err := m.ClaimOutbox(ctx, "flusher-a", 10); err != nil {
		t.Fatalf("ClaimOutbox: %v", err)
	}
	m.mu.Lock()
	_, claimedBefore := m.outboxClaims["lk#1"]
	m.mu.Unlock()
	if !claimedBefore {
		t.Fatal("setup: v1 not claimed")
	}
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#2", 2)); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue v2 = (%v, %v)", out, err)
	}
	m.mu.Lock()
	_, stale := m.outboxClaims["lk#1"]
	_, oldRow := m.outboxMeta["lk#1"]
	n := len(m.outbox)
	m.mu.Unlock()
	if stale || oldRow {
		t.Fatal("superseded row kept its claim/meta")
	}
	if n != 1 {
		t.Fatalf("outbox rows = %d, want 1 after supersede", n)
	}
	// An older version is superseded once a newer one is pending.
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#1b", 1)); err != nil || out != VersionedSuperseded {
		t.Fatalf("enqueue stale v1 = (%v, %v)", out, err)
	}
	// Guard: invalid identity is a permissive no-op; alive+not-delivered+
	// no-newer-pending admits; a live newer row blocks; a missing row refuses.
	if ok, err := m.OutboxVersionGuard(ctx, "lk#2", "", 0); err != nil || !ok {
		t.Fatalf("guard without identity = (%v, %v), want true", ok, err)
	}
	if ok, err := m.OutboxVersionGuard(ctx, "lk#2", "lk", 6); err != nil || !ok {
		t.Fatalf("guard v6 pending = (%v, %v), want true", ok, err)
	}
	if ok, err := m.OutboxVersionGuard(ctx, "missing", "lk", 6); err != nil || ok {
		t.Fatalf("guard missing row = (%v, %v), want false", ok, err)
	}
	// Plant a live newer pending row directly (the versioned enqueue would
	// supersede lk#2): the guard must refuse while a live newer row exists.
	m.mu.Lock()
	blocker := item("lk#zz", 9)
	m.outbox = append(m.outbox, blocker)
	m.mu.Unlock()
	if ok, err := m.OutboxVersionGuard(ctx, "lk#2", "lk", 6); err != nil || ok {
		t.Fatalf("guard v6 with live newer pending = (%v, %v), want false", ok, err)
	}
	m.mu.Lock()
	m.outbox = m.outbox[:len(m.outbox)-1]
	m.mu.Unlock()

	// Dead-letter a row, then prove the dead row neither blocks a future
	// enqueue nor counts as newer pending in the guard, and that an
	// equal-version dead row supersedes instead of duplicating.
	if err := m.OutboxRetry(ctx, "lk#2", errors.New("dispatch failed"), 1); err != nil {
		t.Fatalf("OutboxRetry: %v", err)
	}
	m.mu.Lock()
	meta := m.outboxMeta["lk#2"]
	m.mu.Unlock()
	if meta.deadAt.IsZero() || meta.attempts != 1 {
		t.Fatalf("retry did not dead-letter: %+v", meta)
	}
	if pending, err := m.OutboxPending(ctx); err != nil || len(pending) != 0 {
		t.Fatalf("dead rows still pending: %v %v", pending, err)
	}
	// Replaying the equal-version dead row's ID supersedes instead of
	// duplicating (the dead letter is terminal and operator-visible).
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#2", 2)); err != nil || out != VersionedSuperseded {
		t.Fatalf("replay dead equal version = (%v, %v), want superseded", out, err)
	}
	// Enqueue v3 with a newer DEAD row present: the pending check skips the
	// dead row and the supersede loop preserves it.
	m.mu.Lock()
	deadNewer := item("lk#d", 7)
	deadNewer.CreatedAt = time.Now().UTC()
	m.outbox = append(m.outbox, deadNewer)
	m.outboxMeta[deadNewer.ID] = outboxMeta{deadAt: time.Now().UTC()}
	m.mu.Unlock()
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#3", 3)); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue v3 after dead rows = (%v, %v)", out, err)
	}
	m.mu.Lock()
	_, keptDead := m.outboxMeta["lk#d"]
	m.mu.Unlock()
	if !keptDead {
		t.Fatal("supersede deleted a dead letter")
	}
	// The guard must ignore the DEAD newer row; the live v3 row still counts
	// as newer than v2.
	if ok, err := m.OutboxVersionGuard(ctx, "lk#2", "lk", 4); err != nil || !ok {
		t.Fatalf("guard v4 with newer dead row = (%v, %v), want true", ok, err)
	}
	if ok, err := m.OutboxVersionGuard(ctx, "lk#2", "lk", 2); err != nil || ok {
		t.Fatalf("guard v2 with live newer v3 = (%v, %v), want false", ok, err)
	}

	// A DELIVERED watermark suppresses even an equal version.
	if err := m.OutboxMarkDelivered(ctx, "lk", 5); err != nil {
		t.Fatalf("OutboxMarkDelivered: %v", err)
	}
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#5", 5)); err != nil || out != VersionedSuperseded {
		t.Fatalf("enqueue delivered v5 = (%v, %v)", out, err)
	}

	// OutboxMarkDelivered input contract and monotonic watermark.
	if err := m.OutboxMarkDelivered(ctx, "", 1); err == nil {
		t.Fatal("mark delivered without key succeeded")
	}
	if err := m.OutboxMarkDelivered(ctx, "lk-fresh", 2); err != nil {
		t.Fatalf("mark delivered on nil map: %v", err)
	}
	if err := m.OutboxMarkDelivered(ctx, "lk-fresh", 1); err != nil {
		t.Fatalf("mark delivered backwards: %v", err)
	}
	m.mu.Lock()
	watermark := m.forgeState["lk-fresh"]
	m.mu.Unlock()
	if watermark != 2 {
		t.Fatalf("watermark = %d, want 2 (never moves backwards)", watermark)
	}

	// Claim-guarded retry: a foreign claimer must not clear another's claim.
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#9", 9)); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue v9 = (%v, %v)", out, err)
	}
	if _, err := m.ClaimOutbox(ctx, "owner-a", 10); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxRetryClaimed(ctx, "lk#9", "owner-b", errors.New("nope"), 3); err != nil {
		t.Fatalf("foreign claimer retry = %v, want silent no-op", err)
	}
	m.mu.Lock()
	owner := m.outboxClaims["lk#9"]
	m.mu.Unlock()
	if owner.claimer != "owner-a" {
		t.Fatalf("foreign retry stole the claim: %+v", owner)
	}
	if err := m.OutboxRetryClaimed(ctx, "lk#9", "owner-a", errors.New("boom"), 3); err != nil {
		t.Fatalf("owner retry: %v", err)
	}
	m.mu.Lock()
	_, stillClaimed := m.outboxClaims["lk#9"]
	afterMeta := m.outboxMeta["lk#9"]
	m.mu.Unlock()
	if stillClaimed || afterMeta.attempts != 1 {
		t.Fatalf("owner retry did not clear claim/bump attempts: claimed=%v meta=%+v", stillClaimed, afterMeta)
	}
	// Unknown row is a no-op.
	if err := m.OutboxRetryClaimed(ctx, "does-not-exist", "", nil, 3); err != nil {
		t.Fatalf("unknown retry = %v", err)
	}

	// Batch claim release: a foreign claimer releases nothing, the owner
	// releases exactly its matching row.
	if out, err := m.OutboxEnqueueVersioned(ctx, item("lk#11", 11)); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue v11 = (%v, %v)", out, err)
	}
	claimed, err := m.ClaimOutbox(ctx, "owner-c", 10)
	if err != nil || len(claimed) != 1 || claimed[0].ID != "lk#11" {
		t.Fatalf("claim owner-c = (%v, %v), want exactly lk#11", claimed, err)
	}
	if n, err := m.ReleaseOutboxClaims(ctx, []string{"lk#11"}, "owner-d"); err != nil || n != 0 {
		t.Fatalf("foreign batch release = (%d, %v), want 0/nil", n, err)
	}
	if n, err := m.ReleaseOutboxClaims(ctx, []string{"lk#11", "ghost"}, "owner-c"); err != nil || n != 1 {
		t.Fatalf("owner batch release = (%d, %v), want 1/nil", n, err)
	}
}

// TestFaultyStoreOutboxVersionedParity covers the wrapper delegates for the
// versioned outbox surface: pass-through, armed faults and fail-closed
// minimal inner stores.
func TestFaultyStoreOutboxVersionedParity(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	fs := &FaultyStore{Inner: inner}
	it := OutboxItem{ID: "lk#1", Kind: "github_check", Payload: []byte(`{}`), CreatedAt: time.Now().UTC(), LogicalKey: "lk", StateVersion: 1}
	if out, err := fs.OutboxEnqueueVersioned(ctx, it); err != nil || out != VersionedEnqueued {
		t.Fatalf("enqueue pass-through = (%v, %v)", out, err)
	}
	if ok, err := fs.OutboxVersionGuard(ctx, it.ID, "lk", 1); err != nil || !ok {
		t.Fatalf("guard pass-through = (%v, %v)", ok, err)
	}
	if err := fs.OutboxMarkDelivered(ctx, "lk2", 2); err != nil {
		t.Fatalf("mark delivered pass-through: %v", err)
	}
	if err := fs.OutboxRetryClaimed(ctx, it.ID, "", errors.New("x"), 3); err != nil {
		t.Fatalf("retry pass-through: %v", err)
	}
	if _, err := fs.ReleaseOutboxClaims(ctx, []string{it.ID}, "owner"); err != nil {
		t.Fatalf("release claims pass-through: %v", err)
	}
	armed := func() *FaultyStore { return &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom} }
	if _, err := armed().OutboxEnqueueVersioned(ctx, it); !errors.Is(err, errBoom) {
		t.Fatalf("armed enqueue = %v", err)
	}
	if err := armed().OutboxMarkDelivered(ctx, "lk3", 3); !errors.Is(err, errBoom) {
		t.Fatalf("armed mark delivered = %v", err)
	}
	if _, err := armed().ReleaseOutboxClaims(ctx, []string{it.ID}, "owner"); !errors.Is(err, errBoom) {
		t.Fatalf("armed release claims = %v", err)
	}
	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.OutboxEnqueueVersioned(ctx, it); err == nil {
		t.Fatal("enqueue without ForgeCheckStateStore succeeded")
	}
	if _, err := missing.OutboxVersionGuard(ctx, it.ID, "lk", 1); err == nil {
		t.Fatal("guard without ForgeCheckStateStore succeeded")
	}
	if err := missing.OutboxMarkDelivered(ctx, "lk", 1); err == nil {
		t.Fatal("mark delivered without ForgeCheckStateStore succeeded")
	}
}

// TestMemStoreDeploymentStartFinishSurface drives the deployment start/finish
// contracts: creation with audit, idempotent replay with no second audit,
// identity conflict, missing-row finish and exactly-once completion.
func TestMemStoreDeploymentStartFinishSurface(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	d := model.Deployment{ID: pgITNewID(t), RunID: pgITNewID(t), JobID: pgITNewID(t), Environment: "prod", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	audit := model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started"}

	started, created, err := m.StartDeployment(ctx, d, audit)
	if err != nil || !created || started.ID != d.ID {
		t.Fatalf("StartDeployment = (%+v, %v, %v)", started, created, err)
	}
	if again, created, err := m.StartDeployment(ctx, d, model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started"}); err != nil || created || again.ID != d.ID {
		t.Fatalf("replayed start = (%+v, %v, %v), want stored/false/nil", again, created, err)
	}
	conflict := d
	conflict.Environment = "staging"
	if _, _, err := m.StartDeployment(ctx, conflict, audit); !errors.Is(err, ErrDeploymentIdentityConflict) {
		t.Fatalf("conflicting start = %v, want ErrDeploymentIdentityConflict", err)
	}
	if _, _, err := m.StartDeployment(ctx, model.Deployment{ID: "bad"}, audit); err == nil {
		t.Fatal("malformed deployment id accepted")
	}
	if _, _, err := m.StartDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: "bad"}, audit); err == nil {
		t.Fatal("malformed run id accepted")
	}

	finished, err := m.FinishDeploymentOnce(ctx, d.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{ID: pgITNewID(t), Action: "deployment.finished"})
	if err != nil || !finished {
		t.Fatalf("FinishDeploymentOnce = (%v, %v)", finished, err)
	}
	if again, err := m.FinishDeploymentOnce(ctx, d.ID, model.StatusFailure, time.Now().UTC(), model.AuditEvent{ID: pgITNewID(t)}); err != nil || again {
		t.Fatalf("replayed finish = (%v, %v), want false/nil", again, err)
	}
	if _, err := m.FinishDeploymentOnce(ctx, "bad", model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err == nil {
		t.Fatal("malformed finish id accepted")
	}
	if _, err := m.FinishDeploymentOnce(ctx, pgITNewID(t), model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finish unknown = %v, want ErrNotFound", err)
	}
	// Audit count: creation event + finish event exactly once each.
	events, _ := m.ReadAudit(ctx, 100)
	startedAudits, finishedAudits := 0, 0
	for _, e := range events {
		if e.Action == "deployment.started" {
			startedAudits++
		}
		if e.Action == "deployment.finished" {
			finishedAudits++
		}
	}
	if startedAudits != 1 || finishedAudits != 1 {
		t.Fatalf("audit events started=%d finished=%d, want 1/1 (replay must not re-append)", startedAudits, finishedAudits)
	}

	// InsertDeploymentOnce keeps its own contract: replay returns stored, a
	// conflicting identity fails closed.
	other := model.Deployment{ID: pgITNewID(t), RunID: pgITNewID(t), Environment: "dev", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
	if _, created, err := m.InsertDeploymentOnce(ctx, other); err != nil || !created {
		t.Fatalf("InsertDeploymentOnce = (%v, %v)", created, err)
	}
	if stored, created, err := m.InsertDeploymentOnce(ctx, other); err != nil || created || stored.ID != other.ID {
		t.Fatalf("InsertDeploymentOnce replay = (%+v, %v, %v)", stored, created, err)
	}
	clash := other
	clash.Environment = "prod"
	if _, _, err := m.InsertDeploymentOnce(ctx, clash); !errors.Is(err, ErrDeploymentIdentityConflict) {
		t.Fatalf("InsertDeploymentOnce conflict = %v", err)
	}
	if _, _, err := m.InsertDeploymentOnce(ctx, model.Deployment{ID: "bad"}); err == nil {
		t.Fatal("InsertDeploymentOnce malformed id accepted")
	}
}

// TestFaultyStoreDeploymentParity covers the StartDeployment/FinishDeploymentOnce
// wrapper delegates: pass-through, armed fault, fail-closed minimal store.
func TestFaultyStoreDeploymentParity(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	fs := &FaultyStore{Inner: inner}
	d := model.Deployment{ID: pgITNewID(t), RunID: pgITNewID(t), Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	if _, created, err := fs.StartDeployment(ctx, d, model.AuditEvent{}); err != nil || !created {
		t.Fatalf("start pass-through = (%v, %v)", created, err)
	}
	if ok, err := fs.FinishDeploymentOnce(ctx, d.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err != nil || !ok {
		t.Fatalf("finish pass-through = (%v, %v)", ok, err)
	}
	armed := func() *FaultyStore { return &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom} }
	if _, _, err := armed().StartDeployment(ctx, d, model.AuditEvent{}); !errors.Is(err, errBoom) {
		t.Fatalf("armed start = %v", err)
	}
	if _, err := armed().FinishDeploymentOnce(ctx, d.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); !errors.Is(err, errBoom) {
		t.Fatalf("armed finish = %v", err)
	}
	if _, _, err := (&FaultyStore{Inner: storeOnlyInner{}}).StartDeployment(ctx, d, model.AuditEvent{}); err == nil {
		t.Fatal("start without DeploymentStore succeeded")
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).FinishDeploymentOnce(ctx, d.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err == nil {
		t.Fatal("finish without DeploymentStore succeeded")
	}
}

// TestMemStoreLeaseFencedReportDelivery drives the lease-fenced report commit:
// every identity guard, the lost-lease refusal, the empty job-key/repo fill,
// the first-insert rebuild, the incremental fold (including the skipped-case
// policy) and the delivery replay/conflict outcomes.
func TestMemStoreLeaseFencedReportDelivery(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	runner := strings.Repeat("1", 32)
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, runner, 4, time.Now().UTC().Add(time.Hour))
	job, err := m.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	repoID := RepoIDForJob(job)

	report := func(id string, at time.Time, skipped bool) model.TestReport {
		return model.TestReport{ID: id, RunID: runID, JobID: jobID, JobKey: "build", CreatedAt: at,
			Cases: []model.TestResult{{Name: "test_a", Class: "unit", Passed: true, Duration: 0.1}, {Name: "test_skip", Class: "unit", Skipped: skipped}}}
	}
	delivery := func(id, digest string) TestReportDelivery {
		return TestReportDelivery{JobID: jobID, LeaseGeneration: 4, DeliveryID: id, ContentDigest: digest}
	}

	// Input guards: malformed key, delivery identity mismatch, lost lease.
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, -1, report(pgITNewID(t), time.Now().UTC(), false), repoID, delivery("d0", "x")); err == nil {
		t.Fatal("negative generation accepted")
	}
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, report(pgITNewID(t), time.Now().UTC(), false), repoID, TestReportDelivery{JobID: "other", LeaseGeneration: 4, DeliveryID: "d1", ContentDigest: "x"}); err == nil {
		t.Fatal("mismatched delivery identity accepted")
	}
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, strings.Repeat("2", 32), 4, report(pgITNewID(t), time.Now().UTC(), false), repoID, delivery("d2", "x")); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("lost lease = %v, want ErrLeaseLost", err)
	}
	// Report identity guards.
	badRun := report(pgITNewID(t), time.Now().UTC(), false)
	badRun.RunID = pgITNewID(t)
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, badRun, repoID, delivery("d3", "x")); err == nil {
		t.Fatal("mismatched report run accepted")
	}
	badKey := report(pgITNewID(t), time.Now().UTC(), false)
	badKey.JobKey = "other-key"
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, badKey, repoID, delivery("d4", "x")); err == nil {
		t.Fatal("mismatched report job key accepted")
	}
	badRepo := pgITNewID(t)
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, report(pgITNewID(t), time.Now().UTC(), false), badRepo, delivery("d5", "x")); err == nil {
		t.Fatal("mismatched repository accepted")
	}

	// Happy path: empty job key and repoID are filled from the verified lease.
	first := report(pgITNewID(t), time.Now().UTC().Add(-time.Minute), false)
	first.JobKey = ""
	out, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, first, "", delivery("d6", "digest-1"))
	if err != nil || out.Replay || out.Version != 1 {
		t.Fatalf("first delivery = (%+v, %v), want version 1", out, err)
	}
	if out.ReportID != first.ID {
		t.Fatalf("report id = %s, want %s", out.ReportID, first.ID)
	}
	// Replay: identical delivery ID + digest returns the ORIGINAL identity.
	replay, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, report(pgITNewID(t), time.Now().UTC(), false), repoID, delivery("d6", "digest-1"))
	if err != nil || !replay.Replay || replay.ReportID != first.ID {
		t.Fatalf("replayed delivery = (%+v, %v), want original %s", replay, err, first.ID)
	}
	// Same delivery ID, different digest is a conflict.
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, report(pgITNewID(t), time.Now().UTC(), false), repoID, delivery("d6", "digest-2")); !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("conflicting delivery = %v, want ErrTestReportDeliveryConflict", err)
	}

	// Incremental fold: a newer report for the same repository folds without
	// a rebuild and excludes skipped cases from the aggregate.
	newer := report(pgITNewID(t), time.Now().UTC(), false)
	if out, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, newer, repoID, delivery("d7", "digest-3")); err != nil || out.Replay || out.Version != 2 {
		t.Fatalf("incremental delivery = (%+v, %v), want version 2", out, err)
	}
	version, stats, err := m.LoadRepoTestHistory(ctx, repoID)
	if err != nil || version != 2 || len(stats) == 0 {
		t.Fatalf("LoadRepoTestHistory = (%d, %d bytes, %v)", version, len(stats), err)
	}
	// An out-of-order (older) report forces the rebuild path.
	older := report(pgITNewID(t), time.Now().UTC().Add(-2*time.Hour), false)
	if out, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 4, older, repoID, delivery("d8", "digest-4")); err != nil || out.Version != 3 {
		t.Fatalf("out-of-order delivery = (%+v, %v), want version 3", out, err)
	}
	if v, _, err := m.LoadRepoTestHistory(ctx, repoID); err != nil || v != 3 {
		t.Fatalf("LoadRepoTestHistory after rebuild = (%d, %v)", v, err)
	}
	// Unknown repository reads back empty, never an error.
	if v, stats, err := m.LoadRepoTestHistory(ctx, pgITNewID(t)); err != nil || v != 0 || stats != nil {
		t.Fatalf("LoadRepoTestHistory(unknown) = (%d, %v, %v)", v, stats, err)
	}
	// Rebuild input contract.
	if _, err := m.RebuildRepoTestHistory(ctx, ""); err == nil {
		t.Fatal("rebuild without repository succeeded")
	}
	if v, err := m.RebuildRepoTestHistory(ctx, repoID); err != nil || v != 4 {
		t.Fatalf("RebuildRepoTestHistory = (%d, %v), want version 4", v, err)
	}

	// Legacy non-delivery entry point: valid and invalid repository.
	if _, err := m.InsertTestReportWithHistory(ctx, report(pgITNewID(t), time.Now().UTC(), false), ""); err == nil {
		t.Fatal("legacy insert without repository succeeded")
	}
	if _, err := m.InsertTestReportWithHistory(ctx, report(pgITNewID(t), time.Now().UTC(), false), repoID); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	// Context cancellation is honored before any write.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.InsertTestReportWithHistoryDelivery(canceled, report(pgITNewID(t), time.Now().UTC(), false), repoID, TestReportDelivery{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delivery = %v, want context.Canceled", err)
	}
	// A context error surfaces through the lease-fenced path too (the lease
	// check runs before delegation, so use a repository-less delivery).
	if _, err := m.InsertTestReportWithHistoryDelivery(canceled, report(pgITNewID(t), time.Now().UTC(), false), "", TestReportDelivery{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled plain delivery = %v, want context.Canceled", err)
	}
}

// TestFaultyStoreLeaseReportDeliveryParity covers the lease-fenced report
// wrapper: pass-through, armed fault, fail-closed minimal store.
func TestFaultyStoreLeaseReportDeliveryParity(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	runner := strings.Repeat("3", 32)
	jobID, runID := leaseCommitSeed(t, inner, model.StatusRunning, runner, 2, time.Now().UTC().Add(time.Hour))
	job, _ := inner.GetJob(ctx, jobID)
	repoID := RepoIDForJob(job)
	rep := model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: job.Key, CreatedAt: time.Now().UTC()}
	del := TestReportDelivery{JobID: jobID, LeaseGeneration: 2, DeliveryID: "dr", ContentDigest: "d"}
	fs := &FaultyStore{Inner: inner}
	if out, err := fs.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 2, rep, repoID, del); err != nil || out.ReportID != rep.ID {
		t.Fatalf("for-lease pass-through = (%+v, %v)", out, err)
	}
	armed := func() *FaultyStore { return &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom} }
	if _, err := armed().InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 2, rep, repoID, TestReportDelivery{JobID: jobID, LeaseGeneration: 2, DeliveryID: "dr2", ContentDigest: "d2"}); !errors.Is(err, errBoom) {
		t.Fatalf("armed for-lease = %v", err)
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runner, 2, rep, repoID, del); err == nil {
		t.Fatal("for-lease without LeaseTestReportStore succeeded")
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).InsertTestReportWithHistoryDelivery(ctx, rep, repoID, del); err == nil {
		t.Fatal("delivery without TestReportDeliveryStore succeeded")
	}
	// Legacy non-delivery wrapper pass-through and fault.
	if _, err := fs.InsertTestReportWithHistory(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}, repoID); err != nil {
		t.Fatalf("legacy wrapper: %v", err)
	}
	if _, err := armed().InsertTestReportWithHistory(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}, repoID); !errors.Is(err, errBoom) {
		t.Fatalf("armed legacy = %v", err)
	}
	// Rebuild/load pass-through.
	if _, err := fs.RebuildRepoTestHistory(ctx, repoID); err != nil {
		t.Fatalf("rebuild pass-through: %v", err)
	}
	if _, _, err := fs.LoadRepoTestHistory(ctx, repoID); err != nil {
		t.Fatalf("load pass-through: %v", err)
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).RebuildRepoTestHistory(ctx, repoID); err == nil {
		t.Fatal("rebuild without TestHistoryAggregateStore succeeded")
	}
}

// TestMemStoreRecoveryFaultStageSweep injects a failure after every staged
// overlay write of the transactional recovery/revocation/expiry paths and
// proves each one aborts with the injected error and leaves committed state
// byte-identical: the in-memory mirror of every rollback boundary.
func TestMemStoreRecoveryFaultStageSweep(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	sweep := func(t *testing.T, stages int, mutate func(*memStore), call func(*memStore) error) {
		t.Helper()
		failures := 0
		for op := 1; op <= stages+2; op++ {
			m := newMemStore()
			recSeedLeased(t, m, 1, 2)
			mutate(m)
			baseline := m.snapshot()
			m.recoveryFaultOps = op
			m.recoveryFaultErr = errBoom
			err := call(m)
			if err == nil {
				continue
			}
			failures++
			if !errors.Is(err, errBoom) {
				t.Fatalf("op %d: err = %v, want injected failure", op, err)
			}
			if got := m.snapshot(); !equalSnapshots(got, baseline) {
				t.Fatalf("op %d: partial state leaked", op)
			}
		}
		if failures != stages {
			t.Fatalf("failure stages hit = %d, want %d", failures, stages)
		}
	}

	t.Run("RevokeRunnerLeases", func(t *testing.T) {
		sweep(t, 6, func(*memStore) {}, func(m *memStore) error {
			_, err := m.RevokeRunnerLeases(ctx, recRunner1, "runner disabled")
			return err
		})
	})
	t.Run("RecoverExpiredLease", func(t *testing.T) {
		sweep(t, 6, func(m *memStore) {
			m.mu.Lock()
			j := m.jobs[recJobRet]
			expired := now.Add(-time.Minute)
			j.LeaseExpiresAt = &expired
			m.jobs[recJobRet] = j
			m.mu.Unlock()
		}, func(m *memStore) error {
			return m.RecoverExpiredLease(ctx, recJobRet, 2, now)
		})
	})
	t.Run("ExpireQueuedJob", func(t *testing.T) {
		sweep(t, 5, func(m *memStore) {
			m.mu.Lock()
			j := m.jobs[recDepID]
			expired := now.Add(-time.Minute)
			j.QueueDeadline = &expired
			m.jobs[recDepID] = j
			m.mu.Unlock()
		}, func(m *memStore) error {
			return m.ExpireQueuedJob(ctx, recDepID, now.Add(-time.Minute))
		})
	})
}

// TestRecoveryOverlayHelpers pins the pure overlay helpers: quota clamping at
// zero on both counters, the runner-slot release fallback when the runner is
// missing or the released job was the current one, and the default recovery
// fault when no error is configured.
func TestRecoveryOverlayHelpers(t *testing.T) {
	// adjustQuotaMap clamps negative running/queued counters at zero.
	quotas := map[string]quotaCounts{}
	adjustQuotaMap(quotas, "github.com/o/r", -5, -5)
	for _, key := range QuotaKeys("github.com/o/r") {
		if c := quotas[key]; c.running != 0 || c.queued != 0 {
			t.Fatalf("quota %s = %+v, want clamped zeros", key, c)
		}
	}
	adjustQuotaMap(quotas, "github.com/o/r", 2, 3)
	for _, key := range QuotaKeys("github.com/o/r") {
		if c := quotas[key]; c.running != 2 || c.queued != 3 {
			t.Fatalf("quota %s = %+v, want 2/3", key, c)
		}
	}

	// releaseRunnerSlotMap: unknown runner is a no-op; releasing the current
	// job promotes the next active job; releasing the last job clears it.
	runners := map[string]model.Runner{}
	releaseRunnerSlotMap(runners, "missing", "job")
	if len(runners) != 0 {
		t.Fatal("missing runner mutated the map")
	}
	runners["r1"] = model.Runner{ID: "r1", Capacity: 3, ActiveJobs: []string{"a", "b"}, CurrentJob: "a"}
	releaseRunnerSlotMap(runners, "r1", "a")
	if got := runners["r1"]; got.CurrentJob != "b" || len(got.ActiveJobs) != 1 || got.Busy {
		t.Fatalf("promoted runner = %+v, want current b", got)
	}
	releaseRunnerSlotMap(runners, "r1", "b")
	if got := runners["r1"]; got.CurrentJob != "" || len(got.ActiveJobs) != 0 {
		t.Fatalf("drained runner = %+v, want empty current", got)
	}

	// recoveryBump: disabled, below the threshold, and the default injected
	// error when no error is supplied.
	ops, staged := 0, 0
	if err := recoveryBump(&ops, new(error), &staged); err != nil {
		t.Fatalf("disabled bump = %v", err)
	}
	ops, errp, staged := 2, error(nil), 0
	if err := recoveryBump(&ops, &errp, &staged); err != nil || staged != 1 {
		t.Fatalf("first bump = (%v, staged %d), want nil/1", err, staged)
	}
	err := recoveryBump(&ops, &errp, &staged)
	if err == nil || !strings.Contains(err.Error(), "injected recovery failure") {
		t.Fatalf("second bump = %v, want default injected failure", err)
	}
	if ops != 0 {
		t.Fatalf("one-shot ops = %d, want 0", ops)
	}
}

// TestMemStoreDisableRunnerAndRevokeCertSurface covers the atomic
// disable+revocation mirror: validation, missing runner, the revoked-lease
// requeue path, the cert-serial revocation record and the idempotent replay.
func TestMemStoreDisableRunnerAndRevokeCertSurface(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	if _, err := m.DisableRunnerAndRevokeCert(ctx, "bad", "", "admin"); err == nil {
		t.Fatal("malformed runner id accepted")
	}
	if _, err := m.DisableRunnerAndRevokeCert(ctx, strings.Repeat("1", 32), "", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown runner = %v, want ErrNotFound", err)
	}
	recSeedLeased(t, m, 1, 2)
	serial := "serial-123"
	n, err := m.DisableRunnerAndRevokeCert(ctx, recRunner1, serial, "admin")
	if err != nil || n != 1 {
		t.Fatalf("disable = (%d, %v), want 1 lease revoked", n, err)
	}
	if revoked, err := m.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("CertRevoked = (%v, %v), want true", revoked, err)
	}
	r, _ := m.GetRunner(ctx, recRunner1)
	if !r.Disabled || r.RevokedAt == nil {
		t.Fatalf("runner not disabled/revoked: %+v", r)
	}
	j, _ := m.GetJob(ctx, recJobRet)
	if j.Status != model.StatusQueued {
		t.Fatalf("leased job = %s, want requeued", j.Status)
	}
	// Replay: no remaining running leases, runner already revoked; the second
	// call must not re-stamp RevokedAt and must return zero.
	first := *r.RevokedAt
	n, err = m.DisableRunnerAndRevokeCert(ctx, recRunner1, serial, "admin")
	if err != nil || n != 0 {
		t.Fatalf("replay = (%d, %v), want 0/nil", n, err)
	}
	r, _ = m.GetRunner(ctx, recRunner1)
	if !r.RevokedAt.Equal(first) {
		t.Fatalf("replay re-stamped revocation: %v -> %v", first, r.RevokedAt)
	}
	// Without a cert serial the runner is disabled but nothing is revoked.
	other := strings.Repeat("5", 32)
	if err := m.UpsertRunner(ctx, model.Runner{ID: other, Name: "r5", Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if n, err := m.DisableRunnerAndRevokeCert(ctx, other, "", "admin"); err != nil || n != 0 {
		t.Fatalf("disable without serial = (%d, %v)", n, err)
	}
	if r, _ := m.GetRunner(ctx, other); !r.Disabled || r.RevokedAt != nil {
		t.Fatalf("runner without serial = %+v, want disabled/unrevoked", r)
	}
}

// TestEffectiveMaxInfraRetriesClamp pins the defense-in-depth clamp of the
// persisted retry budget at the pipeline admission cap.
func TestEffectiveMaxInfraRetriesClamp(t *testing.T) {
	if got := effectiveMaxInfraRetries(model.Job{MaxInfraRetries: 1}); got != 1 {
		t.Fatalf("in-range budget = %d, want 1", got)
	}
	if got := effectiveMaxInfraRetries(model.Job{MaxInfraRetries: pipeline.MaxInfraRetries + 100}); got != pipeline.MaxInfraRetries {
		t.Fatalf("oversized budget = %d, want clamp to %d", got, pipeline.MaxInfraRetries)
	}
}

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestLeaderFenceMemStoreFailsClosed documents and pins the in-memory
// store's fencing semantics: the single-process store models a replica that
// always holds the claim (retained epoch 1), so every leader-fenced operation
// runs; clearing the epoch simulates loss and every fenced operation must
// then fail closed with ErrStaleLeader and mutate nothing, exactly like the
// SQL store. Restoring an epoch re-admits the operations.
func TestLeaderFenceMemStoreFailsClosed(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	now := time.Now().UTC()
	deadline := now.Add(-time.Minute)
	expired := now.Add(-time.Minute)
	oldReserved := now.Add(-2 * time.Hour)

	expiredID := strings.Repeat("a", 32)
	queuedID := strings.Repeat("b", 32)
	runID := strings.Repeat("c", 32)
	sidecarJob := strings.Repeat("d", 32)
	m.mu.Lock()
	m.jobs[expiredID] = model.Job{
		ID: expiredID, RunID: runID, Key: "build", Status: model.StatusRunning,
		LeaseGeneration: 1, LeaseExpiresAt: &expired, MaxInfraRetries: 2, CreatedAt: now,
	}
	m.jobs[queuedID] = model.Job{
		ID: queuedID, RunID: runID, Key: "build", Status: model.StatusQueued,
		QueueDeadline: &deadline, CreatedAt: now,
	}
	m.outbox = append(m.outbox, OutboxItem{ID: "o1", Kind: "test"})
	m.pendingSidecars[pendingSidecarKey(sidecarJob, 3, "bin", ArtifactSidecarKindSBOM)] = pendingSidecar{
		digest: strings.Repeat("a", 64), createdAt: now.Add(-2 * time.Hour),
	}
	m.downstream[sidecarJob+"\x00link"] = DownstreamLink{
		ParentJobID: sidecarJob, TargetRepo: "r", TargetRef: "ref",
		Reserved: true, ReservedAt: &oldReserved,
	}
	m.schedules["s1"] = Schedule{ID: "s1", Enabled: true}
	m.mu.Unlock()

	if epoch, ok := m.LeaderEpoch(); !ok || epoch != 1 {
		t.Fatalf("memStore initial epoch = %d/%v; want 1/true", epoch, ok)
	}
	// The initial (always-leader) semantics admit the operations.
	if err := m.ExpireQueuedJob(ctx, queuedID, deadline); err != nil {
		t.Fatalf("admitted ExpireQueuedJob = %v", err)
	}
	m.mu.Lock()
	if got := m.jobs[queuedID].Status; got != model.StatusCancelled {
		m.mu.Unlock()
		t.Fatalf("admitted queue timeout left status %s", got)
	}
	m.jobs[queuedID] = model.Job{
		ID: queuedID, RunID: runID, Key: "build", Status: model.StatusQueued,
		QueueDeadline: &deadline, CreatedAt: now,
	}
	m.mu.Unlock()

	// Loss: every fenced operation class fails closed and mutates nothing.
	m.ClearLeaderEpoch()
	if _, ok := m.LeaderEpoch(); ok {
		t.Fatal("ClearLeaderEpoch left an epoch retained")
	}
	wantStale := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, ErrStaleLeader) {
			t.Fatalf("%s with a cleared epoch = %v; want ErrStaleLeader", op, err)
		}
	}
	wantStale("RecoverExpiredLease", m.RecoverExpiredLease(ctx, expiredID, 1, now))
	wantStale("ExpireQueuedJob", m.ExpireQueuedJob(ctx, queuedID, deadline))
	wantStale("OutboxAck", m.OutboxAck(ctx, "o1"))
	if _, err := m.ClaimOutbox(ctx, "flusher", 10); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("ClaimOutbox with a cleared epoch = %v; want ErrStaleLeader", err)
	}
	wantStale("ReleaseOutboxClaim", m.ReleaseOutboxClaim(ctx, "o1", "flusher"))
	if _, err := m.ReleaseOutboxClaims(ctx, []string{"o1"}, "flusher"); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("ReleaseOutboxClaims with a cleared epoch = %v; want ErrStaleLeader", err)
	}
	if _, err := m.PrunePendingSidecars(ctx, now.Add(-time.Hour)); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("PrunePendingSidecars with a cleared epoch = %v; want ErrStaleLeader", err)
	}
	if _, err := m.ExpireDownstreamReservations(ctx, now.Add(-time.Hour)); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("ExpireDownstreamReservations with a cleared epoch = %v; want ErrStaleLeader", err)
	}
	if ok, err := m.ClaimScheduleOccurrence(ctx, "s1", now, strings.Repeat("b", 32)); !errors.Is(err, ErrStaleLeader) || ok {
		t.Fatalf("ClaimScheduleOccurrence with a cleared epoch = %v/%v; want false/ErrStaleLeader", ok, err)
	}
	wantStale("AdvanceScheduleLastRun", m.AdvanceScheduleLastRun(ctx, "s1", now))
	wantStale("InsertCompiledRun(schedule claim)", m.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:           model.Run{ID: strings.Repeat("c", 32), Status: model.StatusQueued},
		Jobs:          map[string]model.Job{strings.Repeat("d", 32): {ID: strings.Repeat("d", 32), RunID: strings.Repeat("c", 32), Key: "build", Status: model.StatusQueued}},
		ScheduleClaim: &ScheduleClaim{ScheduleID: "s1", Nominal: now},
	}))

	m.mu.Lock()
	defer m.mu.Unlock()
	if got := m.jobs[expiredID].Status; got != model.StatusRunning {
		t.Fatalf("stale RecoverExpiredLease mutated status to %s", got)
	}
	if got := m.jobs[queuedID].Status; got != model.StatusQueued {
		t.Fatalf("stale ExpireQueuedJob mutated status to %s", got)
	}
	if len(m.outbox) != 1 || len(m.outboxClaims) != 0 {
		t.Fatalf("stale outbox operations mutated the queue: %d rows, %d claims", len(m.outbox), len(m.outboxClaims))
	}
	if len(m.pendingSidecars) != 1 {
		t.Fatalf("stale PrunePendingSidecars removed %d rows", 1-len(m.pendingSidecars))
	}
	if l := m.downstream[sidecarJob+"\x00link"]; !l.Reserved {
		t.Fatal("stale ExpireDownstreamReservations cleared the reservation")
	}
	if len(m.occurrences) != 0 {
		t.Fatalf("stale occurrence claim inserted %d schedules' rows", len(m.occurrences))
	}
	if sc := m.schedules["s1"]; sc.LastRun != nil {
		t.Fatalf("stale AdvanceScheduleLastRun moved last_run to %v", sc.LastRun)
	}
	if _, ok := m.runs[strings.Repeat("c", 32)]; ok {
		t.Fatal("stale schedule enqueue inserted the run")
	}
}

// TestLeaderFenceFaultyStoreInjection pins the fault wrapper's stale-leader
// contract: FailFencedWith makes every leader-fenced operation return exactly
// the injected error without touching Inner, non-fenced operations still
// delegate, and clearing the injection restores delegation (where the inner
// store's own fence then governs).
func TestLeaderFenceFaultyStoreInjection(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	f := &FaultyStore{Inner: inner}

	// The wrapper's fence view is Inner's.
	if epoch, ok := f.LeaderEpoch(); !ok || epoch != 1 {
		t.Fatalf("wrapper epoch = %d/%v; want the inner store's 1", epoch, ok)
	}
	f.FailFencedWith(ErrStaleLeader)
	if err := f.RecoverExpiredLease(ctx, "job", 1, time.Now()); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected RecoverExpiredLease = %v", err)
	}
	if err := f.OutboxAck(ctx, "o"); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected OutboxAck = %v", err)
	}
	if _, err := f.ClaimOutbox(ctx, "flusher", 1); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected ClaimOutbox = %v", err)
	}
	if err := f.ReleaseOutboxClaim(ctx, "o", "flusher"); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected ReleaseOutboxClaim = %v", err)
	}
	if _, err := f.ReleaseOutboxClaims(ctx, []string{"o"}, "flusher"); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected ReleaseOutboxClaims = %v", err)
	}
	if _, err := f.PrunePendingSidecars(ctx, time.Now()); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected PrunePendingSidecars = %v", err)
	}
	if _, err := f.ExpireDownstreamReservations(ctx, time.Now()); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected ExpireDownstreamReservations = %v", err)
	}
	if ok, err := f.ClaimScheduleOccurrence(ctx, "s", time.Now(), "r"); !errors.Is(err, ErrStaleLeader) || ok {
		t.Fatalf("injected ClaimScheduleOccurrence = %v/%v", ok, err)
	}
	if err := f.AdvanceScheduleLastRun(ctx, "s", time.Now()); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected AdvanceScheduleLastRun = %v", err)
	}
	if err := f.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:           model.Run{ID: strings.Repeat("a", 32)},
		ScheduleClaim: &ScheduleClaim{ScheduleID: "s", Nominal: time.Now()},
	}); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("injected schedule enqueue = %v", err)
	}
	// Ordinary (non-leader) submissions are not fenced by the injection.
	if err := f.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: strings.Repeat("b", 32), Status: model.StatusQueued},
		Jobs: map[string]model.Job{},
	}); err != nil {
		t.Fatalf("ordinary enqueue under stale-leader injection = %v", err)
	}
	inner.mu.Lock()
	if _, ok := inner.runs[strings.Repeat("a", 32)]; ok {
		inner.mu.Unlock()
		t.Fatal("injected schedule enqueue reached Inner")
	}
	inner.mu.Unlock()

	// Clearing the injection delegates again; the inner store's fence (now
	// cleared through the wrapper) then rejects on its own.
	f.FailFencedWith(nil)
	f.ClearLeaderEpoch()
	if _, ok := f.LeaderEpoch(); ok {
		t.Fatal("wrapper ClearLeaderEpoch did not reach Inner")
	}
	if err := f.OutboxAck(ctx, "o"); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("delegated OutboxAck after clearing the inner epoch = %v", err)
	}
	f.SetLeaderEpoch(1)
	if err := f.OutboxAck(ctx, "o"); err != nil {
		t.Fatalf("delegated OutboxAck after restoring the epoch = %v", err)
	}
}

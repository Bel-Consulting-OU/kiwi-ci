package storage

// In-memory and fault-injection parity tests for the corrupt-payload recovery
// contract: a job whose persisted payload cannot be decoded must never keep a
// runner active slot, a lease or a quota reservation. The real-PostgreSQL
// counterparts live in postgres_recovery_corrupt_it_test.go.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// recMarkUndecodable flips the memStore corruption seam for one job under the
// store lock, modelling a persisted payload json.Unmarshal cannot read.
func recMarkUndecodable(m *memStore, jobID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.undecodableJobs[jobID] = true
}

// recSetLeaseExpiry rewrites one in-memory job's lease expiry under the lock.
func recSetLeaseExpiry(m *memStore, jobID string, exp time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.jobs[jobID]
	j.LeaseExpiresAt = &exp
	m.jobs[jobID] = j
}

// recAuditActions returns the audit action set of one in-memory store.
func recAuditActions(t *testing.T, m *memStore) map[string]int {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, e := range m.audit {
		out[e.Action]++
	}
	return out
}

// TestMemStoreRecoverCorruptPayloadFreesCapacity is the in-memory mirror of
// test (a): an expired running lease with an undecodable payload is
// force-recovered terminally (never requeued, even with retry budget left),
// the runner active slot and failure counter move, the running quota
// reservation is released, the dependent and run aggregation are recomputed,
// and the corruption audit is written exactly once.
func TestMemStoreRecoverCorruptPayloadFreesCapacity(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)

	m := newMemStore()
	// attempts 1 with budget 2: a decodable payload WOULD requeue; the corrupt
	// payload must fail terminally instead (retry fields are untrusted).
	recSeedLeased(t, m, 1, 2)
	recMarkUndecodable(m, recJobRet)
	recSetLeaseExpiry(m, recJobRet, expired)

	if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("RecoverExpiredLease (corrupt): %v", err)
	}
	j, err := m.GetJob(ctx, recJobRet)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusFailure || j.Error != CorruptLeaseRecoveryReason || j.FinishedAt == nil {
		t.Fatalf("corrupt job = %s/%q finished=%v, want failure/corruption reason", j.Status, j.Error, j.FinishedAt)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("corrupt job lease not cleared: %+v", j)
	}
	ri, _ := m.GetRunner(ctx, recRunner1)
	if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" || ri.Failed != 8 {
		t.Fatalf("runner after corrupt recovery = active=%v busy=%v current=%q failed=%d, want empty/false//8", ri.ActiveJobs, ri.Busy, ri.CurrentJob, ri.Failed)
	}
	// running released, queued unchanged: the corrupt job is NOT re-queued.
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after corrupt recovery = %d/%d, want 0/1", running, queued)
	}
	dep, _ := m.GetJob(ctx, recDepID)
	if dep.Status != model.StatusBlocked || dep.DependencyStatus != model.StatusFailure {
		t.Fatalf("dependent of a corrupt-failed job = %s/%s, want blocked/failure", dep.Status, dep.DependencyStatus)
	}
	actions := recAuditActions(t, m)
	if actions["job.corrupt_payload_recovered"] != 1 {
		t.Fatalf("corruption audits = %d, want exactly 1 (%v)", actions["job.corrupt_payload_recovered"], actions)
	}

	// Replay is a no-op: capacity moves exactly once.
	if err := m.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("replayed corrupt recovery: %v", err)
	}
	if running, queued, _ := m.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after replay = %d/%d, want unchanged 0/1", running, queued)
	}
	if ri, _ := m.GetRunner(ctx, recRunner1); ri.Failed != 8 {
		t.Fatalf("runner failed after replay = %d, want 8", ri.Failed)
	}
	if actions := recAuditActions(t, m); actions["job.corrupt_payload_recovered"] != 1 {
		t.Fatalf("replayed corruption audits = %d, want still 1", actions["job.corrupt_payload_recovered"])
	}

	// Contrast (test (d)): the SAME shape with a decodable payload keeps the
	// existing retry-policy behavior and requeues.
	normal := newMemStore()
	recSeedLeased(t, normal, 1, 2)
	recSetLeaseExpiry(normal, recJobRet, expired)
	if err := normal.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("RecoverExpiredLease (normal): %v", err)
	}
	nj, _ := normal.GetJob(ctx, recJobRet)
	if nj.Status != model.StatusQueued || nj.Error != "runner lease expired; retrying" {
		t.Fatalf("normal job = %s/%q, want queued/retrying", nj.Status, nj.Error)
	}
	if running, queued, _ := normal.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after normal recovery = %d/%d, want 0/2", running, queued)
	}
}

// TestFaultyStoreRecoverCorruptPayloadFreesCapacity proves the corruption
// path passes through the fault-injection wrapper untouched (parity with the
// raw memStore), so a wrapped store releases the same capacity.
func TestFaultyStoreRecoverCorruptPayloadFreesCapacity(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)

	inner := newMemStore()
	recSeedLeased(t, inner, 1, 2)
	recMarkUndecodable(inner, recJobRet)
	recSetLeaseExpiry(inner, recJobRet, expired)
	f := &FaultyStore{Inner: inner}

	if err := f.RecoverExpiredLease(ctx, recJobRet, 2, now); err != nil {
		t.Fatalf("FaultyStore.RecoverExpiredLease (corrupt): %v", err)
	}
	j, _ := f.GetJob(ctx, recJobRet)
	if j.Status != model.StatusFailure || j.Error != CorruptLeaseRecoveryReason {
		t.Fatalf("corrupt job through wrapper = %s/%q, want failure/corruption reason", j.Status, j.Error)
	}
	if running, queued, _ := f.QuotaCounts(ctx, recRepoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota through wrapper = %d/%d, want 0/1", running, queued)
	}
	if ri, _ := f.GetRunner(ctx, recRunner1); len(ri.ActiveJobs) != 0 || ri.Failed != 8 {
		t.Fatalf("runner through wrapper = %+v, want released slot/8 failures", ri)
	}
	if actions := recAuditActions(t, inner); actions["job.corrupt_payload_recovered"] != 1 {
		t.Fatalf("wrapper corruption audits = %d, want 1", actions["job.corrupt_payload_recovered"])
	}
}

// TestMemStoreExpireCorruptQueuedJobReleasesReservation is the in-memory
// mirror of test (b): a queued job with an undecodable payload and an elapsed
// PERSISTED deadline expires terminally with the corruption reason and
// releases the queued reservation; without a persisted deadline the payload
// cannot invent one and the row is left alone (no provable timeout).
func TestMemStoreExpireCorruptQueuedJobReleasesReservation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	repoID := RepoIDFor("", recRepo, "o/r")

	newQueued := func(m *memStore, jobID string, deadline *time.Time, compiled bool) {
		if err := m.InsertRun(ctx, model.Run{ID: "run-" + jobID, Repo: recRepo, RepoFullName: "o/r", Status: model.StatusRunning, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		j := model.Job{ID: jobID, RunID: "run-" + jobID, Key: "build", RepoURL: recRepo, RepoFullName: "o/r",
			Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: deadline}
		if compiled {
			j.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: json.RawMessage(`{"job":{"queue_timeout":"5m"}}`)}
		}
		if err := m.InsertJob(ctx, j); err != nil {
			t.Fatal(err)
		}
		m.adjustQuotaLocked(repoID, 0, 1)
	}

	// (b) persisted deadline proves the timeout: terminal expiry + release.
	m := newMemStore()
	newQueued(m, recDepID, &past, false)
	recMarkUndecodable(m, recDepID)
	if err := m.ExpireQueuedJob(ctx, recDepID, past); err != nil {
		t.Fatalf("ExpireQueuedJob (corrupt, column deadline): %v", err)
	}
	j, _ := m.GetJob(ctx, recDepID)
	if j.Status != model.StatusCancelled || j.Error != CorruptQueueExpiryReason || j.FinishedAt == nil {
		t.Fatalf("corrupt queued job = %s/%q, want cancelled/corruption reason", j.Status, j.Error)
	}
	if running, queued, _ := m.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 0 {
		t.Fatalf("quota after corrupt expiry = %d/%d, want 0/0", running, queued)
	}
	actions := recAuditActions(t, m)
	if actions["job.corrupt_payload_expired"] != 1 {
		t.Fatalf("corruption expiry audits = %d, want 1 (%v)", actions["job.corrupt_payload_expired"], actions)
	}

	// A corrupt payload with NO persisted deadline cannot derive one from its
	// compiled fallback: the row stays queued (nothing provable to expire).
	noDeadline := newMemStore()
	newQueued(noDeadline, recDepID, nil, true)
	recMarkUndecodable(noDeadline, recDepID)
	if err := noDeadline.ExpireQueuedJob(ctx, recDepID, time.Time{}); err != nil {
		t.Fatalf("ExpireQueuedJob (corrupt, no deadline): %v", err)
	}
	if j, _ := noDeadline.GetJob(ctx, recDepID); j.Status != model.StatusQueued {
		t.Fatalf("corrupt deadline-less job = %s, want queued (no invented deadline)", j.Status)
	}
	if running, queued, _ := noDeadline.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after corrupt no-deadline expiry = %d/%d, want 0/1", running, queued)
	}

	// The same legacy payload WITHOUT corruption still expires through the
	// compiled fallback, preserving the pre-existing behavior.
	legacy := newMemStore()
	newQueued(legacy, recDepID, nil, true)
	if err := legacy.ExpireQueuedJob(ctx, recDepID, time.Time{}); err != nil {
		t.Fatalf("ExpireQueuedJob (legacy fallback): %v", err)
	}
	if j, _ := legacy.GetJob(ctx, recDepID); j.Status != model.StatusCancelled || j.Error != "queue timeout" {
		t.Fatalf("legacy deadline job = %s/%q, want cancelled/queue timeout", j.Status, j.Error)
	}
	if running, queued, _ := legacy.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 0 {
		t.Fatalf("quota after legacy expiry = %d/%d, want 0/0", running, queued)
	}
}

// TestFaultyStoreExpireCorruptQueuedJobReleasesReservation proves the corrupt
// queue expiry passes through the fault-injection wrapper.
func TestFaultyStoreExpireCorruptQueuedJobReleasesReservation(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	repoID := RepoIDFor("", recRepo, "o/r")

	inner := newMemStore()
	if err := inner.InsertRun(ctx, model.Run{ID: recRunID, Repo: recRepo, RepoFullName: "o/r", Status: model.StatusRunning, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := inner.InsertJob(ctx, model.Job{ID: recDepID, RunID: recRunID, Key: "build", RepoURL: recRepo, RepoFullName: "o/r",
		Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past}); err != nil {
		t.Fatal(err)
	}
	inner.adjustQuotaLocked(repoID, 0, 1)
	recMarkUndecodable(inner, recDepID)
	f := &FaultyStore{Inner: inner}

	if err := f.ExpireQueuedJob(ctx, recDepID, past); err != nil {
		t.Fatalf("FaultyStore.ExpireQueuedJob (corrupt): %v", err)
	}
	j, _ := f.GetJob(ctx, recDepID)
	if j.Status != model.StatusCancelled || j.Error != CorruptQueueExpiryReason {
		t.Fatalf("corrupt queued job through wrapper = %s/%q, want cancelled/corruption reason", j.Status, j.Error)
	}
	if running, queued, _ := f.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 0 {
		t.Fatalf("quota through wrapper = %d/%d, want 0/0", running, queued)
	}
	if actions := recAuditActions(t, inner); actions["job.corrupt_payload_expired"] != 1 {
		t.Fatalf("wrapper corruption expiry audits = %d, want 1", actions["job.corrupt_payload_expired"])
	}
}

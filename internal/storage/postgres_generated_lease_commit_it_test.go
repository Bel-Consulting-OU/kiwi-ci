package storage

// Real-PostgreSQL integration tests for the storage-owned generated-fragment
// lease predicate: InsertGeneratedFragmentTx locks the parent row, samples the
// DATABASE clock after the lock and decides lease liveness itself, so a
// replica whose own clock lags can never admit children of an expired lease.
// Gated on KIWI_TEST_POSTGRES_URL like the other storage integration tests.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// fragITLeasedJob enqueues one run with one job and acquires a lease with the
// given TTL, returning the authoritative stored parent.
func fragITLeasedJob(t *testing.T, st *PostgresStore, ttl time.Duration) (runID, runnerID string, parent model.Job) {
	t.Helper()
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: job},
	}
	if err := st.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID = pgITNewID(t)
	leased, err := st.AcquireLease(ctx, jobID, runnerID, []byte("fragment-lease-hash"), 1, time.Now().UTC().Add(ttl))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	return runID, runnerID, leased
}

// fragITRequest builds a one-child fragment presenting the parent's lease.
func fragITRequest(t *testing.T, parent model.Job, fragmentID string) GeneratedFragmentRequest {
	t.Helper()
	child := pgITNewID(t)
	return GeneratedFragmentRequest{
		ParentJobID:     parent.ID,
		RunnerID:        parent.LeaseRunnerID,
		LeaseGeneration: parent.LeaseGeneration,
		LeaseTokenHash:  parent.LeaseTokenHash,
		Depth:           1,
		FragmentID:      fragmentID,
		Jobs:            map[string]model.Job{child: pgITJob(parent.RunID, child, pgITRepo)},
		Children:        []GeneratedFragmentChild{{Key: "child", ID: child}},
	}
}

// TestIntegrationGeneratedFragmentBarrierLeaseExpiry is the clock-domain race
// regression on real PostgreSQL: the request was admitted while the lease was
// live, then the fragment commit stalls on the parent row lock (a concurrent
// slow transaction) until AFTER the lease expiry, with the row otherwise
// unchanged. The blocked commit must judge the expiry at the DATABASE clock
// sampled after the lock, refuse, and write neither jobs nor a receipt. A
// target-list clock_timestamp() (evaluated below LockRows) would have accepted
// the fragment against the stale timestamp.
func TestIntegrationGeneratedFragmentBarrierLeaseExpiry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, _, parent := fragITLeasedJob(t, st, 500*time.Millisecond)
	req := fragITRequest(t, parent, "frag-barrier")

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, parent.ID); err != nil {
		t.Fatalf("lock parent row: %v", err)
	}
	commitStarted := make(chan struct{})
	commitDone := make(chan error, 1)
	go func() {
		close(commitStarted)
		_, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil)
		commitDone <- err
	}()
	<-commitStarted
	// Hold the lock past the lease expiry: only the wall clock changes.
	select {
	case err := <-commitDone:
		t.Fatalf("fragment commit finished before the lease expired: %v", err)
	case <-time.After(800 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("release the parent lock: %v", err)
	}
	if err := <-commitDone; err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("fragment commit after the lease expired = %v, want a lease-expired refusal", err)
	}
	if _, ok, _ := st.GetGeneratedFragment(ctx, parent.ID, parent.LeaseGeneration, "frag-barrier"); ok {
		t.Fatal("expired fragment left a receipt")
	}
	if _, err := st.GetJob(ctx, req.Children[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired fragment inserted children: %v", err)
	}
}

// TestIntegrationGeneratedFragmentLeaseIdentityEnforced proves the STORE (not
// the request handler's callback) is the lease authority: the verifier is nil
// and a request presenting the wrong runner, generation or token is refused
// with zero rows.
func TestIntegrationGeneratedFragmentLeaseIdentityEnforced(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, _, parent := fragITLeasedJob(t, st, time.Hour)

	cases := []struct {
		name   string
		mutate func(*GeneratedFragmentRequest)
		substr string
	}{
		{"runner", func(r *GeneratedFragmentRequest) { r.RunnerID = pgITNewID(t) }, "runner"},
		{"generation", func(r *GeneratedFragmentRequest) { r.LeaseGeneration = parent.LeaseGeneration + 1 }, "generation"},
		{"token", func(r *GeneratedFragmentRequest) { r.LeaseTokenHash = []byte("wrong") }, "token"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := fragITRequest(t, parent, "frag-identity-"+tc.name)
			tc.mutate(&req)
			if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("mismatched %s = %v, want a %q refusal", tc.name, err, tc.substr)
			}
			if _, err := st.GetJob(ctx, req.Children[0].ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("refused fragment inserted children: %v", err)
			}
			_ = i
		})
	}
	// The unmodified request is accepted and the verifier receives the
	// storage clock.
	accepted := fragITRequest(t, parent, "frag-identity-ok")
	var seen time.Time
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, accepted, func(_ model.Job, _ int, commitNow time.Time) error {
		seen = commitNow
		return nil
	}); err != nil {
		t.Fatalf("matching lease = %v", err)
	}
	if seen.IsZero() {
		t.Fatal("verifier did not receive the storage commit clock")
	}
}

// TestGeneratedParentLeasePredicate pins the predicate edges deterministically
// (shared by the SQL transaction and the memory store).
func TestGeneratedParentLeasePredicate(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	exp := now.Add(time.Minute)
	parent := model.Job{
		ID: "p", Status: model.StatusRunning,
		LeaseRunnerID: "r1", LeaseGeneration: 3, LeaseTokenHash: []byte{1, 2, 3},
		LeaseExpiresAt: &exp,
	}
	req := GeneratedFragmentRequest{ParentJobID: "p", RunnerID: "r1", LeaseGeneration: 3, LeaseTokenHash: []byte{1, 2, 3}}
	if err := ValidateGeneratedParentLease(parent, req, now); err != nil {
		t.Fatalf("valid lease = %v", err)
	}
	eq := now
	parentEq := parent
	parentEq.LeaseExpiresAt = &eq
	if err := ValidateGeneratedParentLease(parentEq, req, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry exactly at the storage clock = %v, want a strict refusal", err)
	}
	cases := []struct {
		name   string
		mutate func(*model.Job)
		substr string
	}{
		{"not running", func(j *model.Job) { j.Status = model.StatusQueued }, "not running"},
		{"runner", func(j *model.Job) { j.LeaseRunnerID = "r2" }, "runner"},
		{"generation", func(j *model.Job) { j.LeaseGeneration = 4 }, "generation"},
		{"token empty stored", func(j *model.Job) { j.LeaseTokenHash = nil }, "token"},
		{"token mismatch", func(j *model.Job) { j.LeaseTokenHash = []byte{9} }, "token"},
		{"expiry nil", func(j *model.Job) { j.LeaseExpiresAt = nil }, "expired"},
		{"expiry past", func(j *model.Job) { p := now.Add(-time.Second); j.LeaseExpiresAt = &p }, "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := parent
			tc.mutate(&j)
			if err := ValidateGeneratedParentLease(j, req, now); err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Fatalf("predicate = %v, want a %q refusal", err, tc.substr)
			}
		})
	}
	mismatch := req
	mismatch.LeaseTokenHash = nil
	if err := ValidateGeneratedParentLease(parent, mismatch, now); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("empty presented token = %v, want a token refusal", err)
	}
}

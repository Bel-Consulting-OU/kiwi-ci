package storage

// Real-PostgreSQL integration tests for the storage-owned generated-fragment
// lease predicate and its canonical mutation identity: InsertGeneratedFragmentTx
// locks the parent row, samples the DATABASE clock after the lock and decides
// lease liveness itself, so a replica whose own clock lags can never admit
// children of an expired lease. The mutation identity is (parent job, fragment
// id) — the lease generation authorizes an upload but never defines it — so an
// infrastructure retry of the same logical parent under a new generation
// replays the ORIGINAL children instead of inserting a duplicate graph.
// Gated on KIWI_TEST_POSTGRES_URL like the other storage integration tests.

import (
	"context"
	"errors"
	"strings"
	"sync"
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
	if _, ok, _ := st.GetGeneratedFragment(ctx, parent.ID, "frag-barrier"); ok {
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

// fragITLeasedRetryJob enqueues one job with an infrastructure-retry budget
// and leases it under generation 1 with the given (short) TTL, returning the
// authoritative parent. Unlike fragITLeasedJob the retry budget is non-zero,
// so the real recovery transition requeues the job instead of failing it.
func fragITLeasedRetryJob(t *testing.T, st *PostgresStore, ttl time.Duration) (runID, jobID, runnerID string, parent model.Job) {
	t.Helper()
	ctx := context.Background()
	runID, jobID = pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: job},
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID = pgITNewID(t)
	leased, err := st.AcquireLease(ctx, jobID, runnerID, []byte("frag-retry-token-gen1"), 1, time.Now().UTC().Add(ttl))
	if err != nil {
		t.Fatalf("lease gen1: %v", err)
	}
	return runID, jobID, runnerID, leased
}

// fragITReclaimGeneration simulates an infrastructure retry of the SAME
// logical parent: it waits out the short previous lease, replays the real
// recovery transition that requeues the job, and re-leases it under the next
// generation, returning the new generation number.
func fragITReclaimGeneration(t *testing.T, st *PostgresStore, jobID string, expiredGeneration int64, runnerID string, token []byte) (generation int64) {
	t.Helper()
	ctx := context.Background()
	time.Sleep(400 * time.Millisecond)
	if err := st.RecoverExpiredLease(ctx, jobID, expiredGeneration, time.Now().UTC()); err != nil {
		t.Fatalf("recover expired gen%d lease: %v", expiredGeneration, err)
	}
	generation = expiredGeneration + 1
	if _, err := st.AcquireLease(ctx, jobID, runnerID, token, generation, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("lease gen%d: %v", generation, err)
	}
	return generation
}

// fragITThreeChildFragment fills a request with three children in canonical
// (sorted key) order and returns the child IDs in the same order.
func fragITThreeChildFragment(t *testing.T, req GeneratedFragmentRequest, runID string) (GeneratedFragmentRequest, []string) {
	t.Helper()
	req.Jobs = map[string]model.Job{}
	req.Children = nil
	ids := make([]string, 0, 3)
	for _, key := range []string{"child-a", "child-b", "child-c"} {
		id := pgITNewID(t)
		req.Jobs[id] = pgITJob(runID, id, pgITRepo)
		req.Children = append(req.Children, GeneratedFragmentChild{Key: key, ID: id})
		ids = append(ids, id)
	}
	return req, ids
}

// fragITRunJobIDs lists the run's job IDs, so tests can prove a replay
// inserted no new rows.
func fragITRunJobIDs(t *testing.T, st *PostgresStore, runID string) map[string]bool {
	t.Helper()
	rows, err := st.pool.Query(context.Background(), `SELECT id FROM jobs WHERE run_id=$1`, runID)
	if err != nil {
		t.Fatalf("list run jobs: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan job id: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// TestGeneratedFragmentReplaysAcrossInfrastructureRetry is the P1 regression
// on real PostgreSQL: parent gen1 admits fragment F (children A/B/C); an
// infrastructure retry requeues the same logical parent and claims gen2;
// re-submitting the identical F must replay A/B/C — not insert a duplicate
// graph with fresh random child IDs — and a CHANGED fragment under gen2 must
// still insert new children.
func TestGeneratedFragmentReplaysAcrossInfrastructureRetry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runner1, parent1 := fragITLeasedRetryJob(t, st, 200*time.Millisecond)
	gen1 := GeneratedFragmentRequest{ParentJobID: jobID, RunnerID: runner1, LeaseGeneration: parent1.LeaseGeneration, LeaseTokenHash: parent1.LeaseTokenHash}

	gen1, firstIDs := fragITThreeChildFragment(t, gen1, runID)
	gen1.FragmentID = "frag-first"
	first, replayed, err := st.InsertGeneratedFragmentTx(ctx, gen1, nil)
	if err != nil || replayed {
		t.Fatalf("gen1 fragment = %+v replayed=%v err=%v", first, replayed, err)
	}
	if len(first.Children) != 3 {
		t.Fatalf("gen1 children = %d, want 3", len(first.Children))
	}
	for i, c := range first.Children {
		if c.ID != firstIDs[i] {
			t.Fatalf("gen1 child %d = %s, want %s", i, c.ID, firstIDs[i])
		}
	}
	before := fragITRunJobIDs(t, st, runID)

	// Infrastructure retry: the same logical parent is requeued and re-leased
	// under the NEXT generation (a DIFFERENT runner here), then the identical
	// fragment is re-submitted.
	token2 := []byte("frag-retry-token-gen2")
	runner2 := pgITNewID(t)
	gen2num := fragITReclaimGeneration(t, st, jobID, parent1.LeaseGeneration, runner2, token2)
	gen2 := GeneratedFragmentRequest{ParentJobID: jobID, RunnerID: runner2, LeaseGeneration: gen2num, LeaseTokenHash: token2}
	gen2, _ = fragITThreeChildFragment(t, gen2, runID)
	gen2.FragmentID = gen1.FragmentID
	replay, replayed, err := st.InsertGeneratedFragmentTx(ctx, gen2, nil)
	if err != nil || !replayed {
		t.Fatalf("gen2 identical fragment = %+v replayed=%v err=%v", replay, replayed, err)
	}
	if len(replay.Children) != len(first.Children) {
		t.Fatalf("replay children = %d, want %d", len(replay.Children), len(first.Children))
	}
	for i := range first.Children {
		if replay.Children[i].ID != first.Children[i].ID || replay.Children[i].Key != first.Children[i].Key {
			t.Fatalf("replay children differ at %d: %+v vs %+v", i, replay.Children[i], first.Children[i])
		}
	}
	afterReplay := fragITRunJobIDs(t, st, runID)
	if len(afterReplay) != len(before) {
		t.Fatalf("replay changed the run job count: before=%d after=%d", len(before), len(afterReplay))
	}
	for _, c := range replay.Children {
		if !afterReplay[c.ID] {
			t.Fatalf("replayed child %s is not present in the run", c.ID)
		}
	}
	var receipts int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*) FROM generated_fragments WHERE parent_job_id=$1 AND fragment_id=$2`, jobID, gen1.FragmentID).Scan(&receipts); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 1 {
		t.Fatalf("receipt rows = %d, want 1", receipts)
	}

	// A CHANGED fragment under gen2 is a new mutation: new children.
	gen2b, changedIDs := fragITThreeChildFragment(t, gen2, runID)
	gen2b.FragmentID = "frag-changed"
	changed, replayed, err := st.InsertGeneratedFragmentTx(ctx, gen2b, nil)
	if err != nil || replayed {
		t.Fatalf("changed fragment = %+v replayed=%v err=%v", changed, replayed, err)
	}
	afterChanged := fragITRunJobIDs(t, st, runID)
	if len(afterChanged) != len(before)+3 {
		t.Fatalf("changed fragment job count = %d, want %d", len(afterChanged), len(before)+3)
	}
	for _, id := range changedIDs {
		if !afterChanged[id] {
			t.Fatalf("changed-fragment child %s missing", id)
		}
	}
	for _, c := range first.Children {
		if !afterChanged[c.ID] {
			t.Fatalf("original child %s disappeared", c.ID)
		}
	}
}

// TestGeneratedFragmentStaleGenerationCannotReplay: after gen2 is leased, a
// request presenting the STALE gen1 identity (even with the old token) is
// rejected by authorization and never observes the receipt children, while
// the current gen2 identity replays the original children.
func TestGeneratedFragmentStaleGenerationCannotReplay(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runner1, parent1 := fragITLeasedRetryJob(t, st, 200*time.Millisecond)
	gen1 := GeneratedFragmentRequest{ParentJobID: jobID, RunnerID: runner1, LeaseGeneration: parent1.LeaseGeneration, LeaseTokenHash: parent1.LeaseTokenHash}

	gen1, _ = fragITThreeChildFragment(t, gen1, runID)
	gen1.FragmentID = "frag-stale"
	first, replayed, err := st.InsertGeneratedFragmentTx(ctx, gen1, nil)
	if err != nil || replayed {
		t.Fatalf("gen1 fragment = %+v replayed=%v err=%v", first, replayed, err)
	}
	before := fragITRunJobIDs(t, st, runID)

	// The infrastructure retry re-leases the parent under gen2 with the SAME
	// runner but a fresh token, so the stale request below is refused for its
	// GENERATION (not for a runner change).
	token2 := []byte("frag-retry-token-gen2")
	gen2num := fragITReclaimGeneration(t, st, jobID, parent1.LeaseGeneration, runner1, token2)

	// Stale generation: authorization must reject BEFORE the receipt replay.
	stale, replayed, err := st.InsertGeneratedFragmentTx(ctx, gen1, nil)
	if err == nil {
		t.Fatalf("stale gen1 replay = %+v replayed=%v, want a generation refusal", stale, replayed)
	}
	if !strings.Contains(err.Error(), "generation") {
		t.Fatalf("stale gen1 refusal = %v, want a generation refusal", err)
	}
	if replayed || len(stale.Children) != 0 {
		t.Fatalf("stale gen1 returned receipt children: %+v replayed=%v", stale, replayed)
	}
	afterStale := fragITRunJobIDs(t, st, runID)
	if len(afterStale) != len(before) {
		t.Fatalf("stale request changed the run job count: before=%d after=%d", len(before), len(afterStale))
	}

	// The receipt itself survived; the current generation replays it.
	got, ok, err := st.GetGeneratedFragment(ctx, jobID, gen1.FragmentID)
	if err != nil || !ok || len(got.Children) != 3 {
		t.Fatalf("receipt read = %+v ok=%v err=%v", got, ok, err)
	}
	current := GeneratedFragmentRequest{ParentJobID: jobID, RunnerID: runner1, LeaseGeneration: gen2num, LeaseTokenHash: token2}
	current, _ = fragITThreeChildFragment(t, current, runID)
	current.FragmentID = gen1.FragmentID
	replay, replayed, err := st.InsertGeneratedFragmentTx(ctx, current, nil)
	if err != nil || !replayed {
		t.Fatalf("gen2 replay = %+v replayed=%v err=%v", replay, replayed, err)
	}
	for i := range first.Children {
		if replay.Children[i].ID != first.Children[i].ID {
			t.Fatalf("gen2 replay children differ: %+v vs %+v", replay.Children, first.Children)
		}
	}
}

// TestGeneratedFragmentConcurrentReplayParity: concurrent uploads of the SAME
// fragment id (distinct random child IDs) under the SAME lease commit exactly
// one graph; every loser returns the winner's receipt and inserts nothing.
func TestGeneratedFragmentConcurrentReplayParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, _, parent := fragITLeasedJob(t, st, time.Hour)
	runID := parent.RunID

	const workers = 2
	type outcome struct {
		rec      GeneratedFragmentReceipt
		replayed bool
		err      error
	}
	outcomes := make([]outcome, workers)
	// Build every request in the test goroutine (no t.Fatalf from workers);
	// each carries the SAME fragment id but distinct random child IDs, the
	// exact shape of two concurrent uploads of one fragment.
	reqs := make([]GeneratedFragmentRequest, workers)
	for i := 0; i < workers; i++ {
		reqs[i] = GeneratedFragmentRequest{
			ParentJobID:     parent.ID,
			RunnerID:        parent.LeaseRunnerID,
			LeaseGeneration: parent.LeaseGeneration,
			LeaseTokenHash:  parent.LeaseTokenHash,
			FragmentID:      "frag-concurrent",
		}
		reqs[i], _ = fragITThreeChildFragment(t, reqs[i], runID)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcomes[i].rec, outcomes[i].replayed, outcomes[i].err = st.InsertGeneratedFragmentTx(ctx, reqs[i], nil)
		}(i)
	}
	wg.Wait()
	winners, replays := 0, 0
	var winner GeneratedFragmentReceipt
	var replaysSeen []GeneratedFragmentReceipt
	for i, o := range outcomes {
		if o.err != nil {
			t.Fatalf("worker %d: %v", i, o.err)
		}
		if o.replayed {
			replays++
			replaysSeen = append(replaysSeen, o.rec)
			continue
		}
		winners++
		winner = o.rec
	}
	if winners != 1 || replays != workers-1 {
		t.Fatalf("concurrent same-fragment inserts = %d winners/%d replays, want 1/%d", winners, replays, workers-1)
	}
	for i, rec := range replaysSeen {
		if len(rec.Children) != len(winner.Children) {
			t.Fatalf("replay %d children = %d, want %d", i, len(rec.Children), len(winner.Children))
		}
		for j := range winner.Children {
			if rec.Children[j].ID != winner.Children[j].ID || rec.Children[j].Key != winner.Children[j].Key {
				t.Fatalf("replay %d children differ from the winner's at %d", i, j)
			}
		}
	}
	jobs := fragITRunJobIDs(t, st, runID)
	if len(jobs) != 1+len(winner.Children) {
		t.Fatalf("run jobs = %d, want parent + %d winner children", len(jobs), len(winner.Children))
	}
	for _, c := range winner.Children {
		if !jobs[c.ID] {
			t.Fatalf("winner child %s missing from the run", c.ID)
		}
	}
	var receipts int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*) FROM generated_fragments WHERE parent_job_id=$1 AND fragment_id=$2`, parent.ID, "frag-concurrent").Scan(&receipts); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 1 {
		t.Fatalf("receipt rows = %d, want 1", receipts)
	}
}

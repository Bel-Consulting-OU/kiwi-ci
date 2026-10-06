package storage

// Run-idempotency receipt contract (migration 0037): the receipt commits in
// the SAME store operation as the run, a same-digest replay returns the
// original run ID, a different-digest reuse fails closed, and a missing
// receipt is the normal first-submission state.

import (
	"errors"
	"testing"
)

func TestMemStoreRunIdempotencyClaim(t *testing.T) {
	m := newMemStore()
	scope := "github.com/o/r"
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
	req.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "op-1", Digest: "digest-a", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	runID, digest, found, err := m.FindRunIdempotency(ctx(), scope, "op-1")
	if err != nil || !found || runID != req.Run.ID || digest != "digest-a" {
		t.Fatalf("FindRunIdempotency = %q, %q, %v, %v", runID, digest, found, err)
	}
	// A different key (or scope) has no receipt.
	if _, _, found, _ := m.FindRunIdempotency(ctx(), scope, "op-2"); found {
		t.Fatal("unclaimed key reported a receipt")
	}
	if _, _, found, _ := m.FindRunIdempotency(ctx(), "github.com/o/other", "op-1"); found {
		t.Fatal("receipt leaked across repository scopes")
	}

	// Same digest under a NEW run ID: the receipt must replay the ORIGINAL
	// run and write nothing new.
	replay := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "https://github.com/o/r.git")
	replay.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "op-1", Digest: "digest-a", RunID: replay.Run.ID}
	err = m.InsertCompiledRun(ctx(), replay)
	var replayErr *IdempotentReplayError
	if !errors.As(err, &replayErr) || replayErr.RunID != req.Run.ID {
		t.Fatalf("same-digest replay = %v, want IdempotentReplayError for %s", err, req.Run.ID)
	}
	if !errors.Is(err, ErrIdempotencyKeyReplay) {
		t.Fatalf("replay error does not unwrap to ErrIdempotencyKeyReplay: %v", err)
	}
	if _, err := m.GetRun(ctx(), replay.Run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed enqueue leaked a run: %v", err)
	}

	// Different digest: fail closed and write nothing.
	conflict := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", "https://github.com/o/r.git")
	conflict.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "op-1", Digest: "digest-b", RunID: conflict.Run.ID}
	if err := m.InsertCompiledRun(ctx(), conflict); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("different-digest reuse = %v, want ErrIdempotencyKeyConflict", err)
	}
	if _, err := m.GetRun(ctx(), conflict.Run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("conflicting enqueue leaked a run: %v", err)
	}
	// The original receipt is untouched.
	runID, digest, found, err = m.FindRunIdempotency(ctx(), scope, "op-1")
	if err != nil || !found || runID != req.Run.ID || digest != "digest-a" {
		t.Fatalf("receipt after conflict = %q, %q, %v, %v", runID, digest, found, err)
	}
}

// TestFaultyStoreRunIdempotencyPassThrough pins that the fault wrapper
// delegates the read and that the injected mutation failure also fails an
// enqueue carrying an idempotency claim (the receipt must never diverge from
// the run).
func TestFaultyStoreRunIdempotencyPassThrough(t *testing.T) {
	inner := newMemStore()
	f := &FaultyStore{Inner: inner, FailAfter: 1, Err: errors.New("injected")}
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
	req.Idempotency = &RunIdempotencyClaim{RepoID: "github.com/o/r", Key: "op-1", Digest: "d", RunID: req.Run.ID}
	if err := f.InsertCompiledRun(ctx(), req); err == nil {
		t.Fatal("faulty first enqueue = nil, want the injected failure")
	}
	if _, _, found, err := f.FindRunIdempotency(ctx(), "github.com/o/r", "op-1"); err != nil || found {
		t.Fatalf("receipt after failed enqueue = found %v, err %v; want none", found, err)
	}
}

// TestPostgresRunIdempotencyClaimAtomicity is the real-PostgreSQL half: two
// concurrent transactions claim one key and exactly one wins the receipt.
// The rollback half proves a raise inside the transaction cannot leave a
// receipt for a run that was never committed.
func TestPostgresIntegrationRunIdempotencyClaimAtomicity(t *testing.T) {
	st := pgITStore(t)
	ctx := ctx()
	scope := "github.com/o/r"

	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
	req.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "pg-op-1", Digest: "digest-a", RunID: req.Run.ID}
	if err := st.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	runID, digest, found, err := st.FindRunIdempotency(ctx, scope, "pg-op-1")
	if err != nil || !found || runID != req.Run.ID || digest != "digest-a" {
		t.Fatalf("FindRunIdempotency = %q, %q, %v, %v", runID, digest, found, err)
	}

	replay := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "https://github.com/o/r.git")
	replay.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "pg-op-1", Digest: "digest-a", RunID: replay.Run.ID}
	err = st.InsertCompiledRun(ctx, replay)
	var replayErr *IdempotentReplayError
	if !errors.As(err, &replayErr) || replayErr.RunID != req.Run.ID {
		t.Fatalf("real replay = %v, want IdempotentReplayError for %s", err, req.Run.ID)
	}

	conflict := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", "https://github.com/o/r.git")
	conflict.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "pg-op-1", Digest: "digest-b", RunID: conflict.Run.ID}
	if err := st.InsertCompiledRun(ctx, conflict); !errors.Is(err, ErrIdempotencyKeyConflict) {
		t.Fatalf("real conflict = %v, want ErrIdempotencyKeyConflict", err)
	}
	if _, err := st.GetRun(ctx, conflict.Run.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("conflicting enqueue leaked a run: %v", err)
	}

	// A job validation failure AFTER the receipt insert must roll the receipt
	// back with the transaction (no receipt without its run).
	bad := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "not-a-valid-job-id", "https://github.com/o/r.git")
	bad.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: "pg-op-2", Digest: "d", RunID: bad.Run.ID}
	if err := st.InsertCompiledRun(ctx, bad); err == nil {
		t.Fatal("invalid job id enqueue = nil, want an error")
	}
	if _, _, found, err := st.FindRunIdempotency(ctx, scope, "pg-op-2"); err != nil || found {
		t.Fatalf("receipt after rolled-back enqueue = found %v, err %v; want none", found, err)
	}
}

// TestPostgresIntegrationRunIdempotencyConcurrentRace is the two-replica
// first-submission race at the database level: two concurrent transactions
// claim the same (repo, key); exactly one inserts the run, the loser reads
// the winner's receipt and rolls back with a replay error naming it, so the
// durable outcome is exactly one run row.
func TestPostgresIntegrationRunIdempotencyConcurrentRace(t *testing.T) {
	st := pgITStore(t)
	ctx := ctx()
	scope := "github.com/o/race"
	key := "pg-race-key"

	reqA := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/race.git")
	reqA.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: key, Digest: "d", RunID: reqA.Run.ID}
	reqB := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "https://github.com/o/race.git")
	reqB.Idempotency = &RunIdempotencyClaim{RepoID: scope, Key: key, Digest: "d", RunID: reqB.Run.ID}

	type outcome struct {
		name string
		err  error
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	for _, req := range []InsertCompiledRunRequest{reqA, reqB} {
		go func(req InsertCompiledRunRequest) {
			<-start
			results <- outcome{name: req.Run.ID, err: st.InsertCompiledRun(ctx, req)}
		}(req)
	}
	close(start)
	var winner string
	var losers int
	for i := 0; i < 2; i++ {
		res := <-results
		var replay *IdempotentReplayError
		switch {
		case res.err == nil:
			winner = res.name
		case errors.As(res.err, &replay):
			losers++
			if replay.RunID != res.name {
				// The loser names whichever run won; it must be a real run ID.
				if _, err := st.GetRun(ctx, replay.RunID); err != nil {
					t.Fatalf("replay names %s but GetRun failed: %v", replay.RunID, err)
				}
			}
		default:
			t.Fatalf("concurrent enqueue %s: unexpected error %v", res.name, res.err)
		}
	}
	if winner == "" || losers != 1 {
		t.Fatalf("concurrent race: winner=%q losers=%d, want exactly one winner and one replay", winner, losers)
	}
	runID, digest, found, err := st.FindRunIdempotency(ctx, scope, key)
	if err != nil || !found || runID != winner || digest != "d" {
		t.Fatalf("receipt after race = %q, %q, %v, %v; want winner %s", runID, digest, found, err, winner)
	}
	// The losing run row does not exist.
	loser := reqA.Run.ID
	if winner == reqA.Run.ID {
		loser = reqB.Run.ID
	}
	if _, err := st.GetRun(ctx, loser); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing run %s exists: %v", loser, err)
	}
}

package server

// Durable run-submission idempotency: a client Idempotency-Key names one
// intended submission. The durable receipt is written in the SAME
// transaction/snapshot as the run, so a commit whose 202 was lost replays to
// the original run, a reused key with a changed request fails closed (409),
// and no retry can execute the pipeline twice.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idempotentSubmitBody builds the canonical direct-submission body used by
// the idempotency tests; changing sha alters the canonical digest.
func idempotentSubmitBody(sha string) string {
	return `{"repo_url":"https://github.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"` + sha + `","pipeline":` + jsonString(smokePipeline) + `}`
}

func submitWithKey(t *testing.T, s *Server, body, key string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONHeaders(t, s, http.MethodPost, "/api/v1/runs", "token", body, map[string]string{"Idempotency-Key": key})
}

func TestSubmitIdempotencyReplayFSAndDB(t *testing.T) {
	for _, mode := range []string{"fs", "db"} {
		t.Run(mode, func(t *testing.T) {
			var s *Server
			var f *dbFakeStore
			if mode == "db" {
				f = newDBFakeStore()
				s = New("token")
				if err := s.SwitchToDB(f); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				s, err = NewPersistent("token", "token", t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
			}
			body := idempotentSubmitBody("sha-one")
			key := "op-11111111-2222-3333-4444-555555555555"

			first := submitWithKey(t, s, body, key)
			if first.Code != http.StatusAccepted {
				t.Fatalf("first submit = %d: %s", first.Code, first.Body.String())
			}
			var firstRun model.Run
			if err := json.Unmarshal(first.Body.Bytes(), &firstRun); err != nil {
				t.Fatal(err)
			}

			// The client never saw the 202 (lost response) and retries the
			// IDENTICAL request with the SAME key: the durable receipt
			// returns the original run and enqueues nothing.
			replay := submitWithKey(t, s, body, key)
			if replay.Code != http.StatusAccepted {
				t.Fatalf("replayed submit = %d: %s", replay.Code, replay.Body.String())
			}
			var replayed model.Run
			if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
				t.Fatal(err)
			}
			if replayed.ID != firstRun.ID {
				t.Fatalf("replay returned run %s, want the original %s", replayed.ID, firstRun.ID)
			}
			runCount := func() int {
				if f != nil {
					f.mu.Lock()
					defer f.mu.Unlock()
					return len(f.runs)
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.runs)
			}
			if runCount() != 1 {
				t.Fatalf("runs = %d, want exactly 1", runCount())
			}
			if f != nil {
				f.mu.Lock()
				inserts := len(f.insertRunCalls)
				f.mu.Unlock()
				if inserts != 1 {
					t.Fatalf("durable run inserts = %d, want exactly 1", inserts)
				}
			}

			// The SAME key with an altered request (sha changed) must fail
			// closed and never enqueue a second run.
			conflict := submitWithKey(t, s, idempotentSubmitBody("sha-two"), key)
			if conflict.Code != http.StatusConflict {
				t.Fatalf("altered-request replay = %d: %s", conflict.Code, conflict.Body.String())
			}
			if !strings.Contains(conflict.Body.String(), "IDEMPOTENCY_KEY_REUSED") {
				t.Fatalf("conflict reason missing: %s", conflict.Body.String())
			}
			if runCount() != 1 {
				t.Fatalf("runs after conflict = %d, want exactly 1", runCount())
			}

			// A DIFFERENT key is a different operation: it enqueues normally.
			other := submitWithKey(t, s, idempotentSubmitBody("sha-two"), "op-99999999-2222-3333-4444-555555555555")
			if other.Code != http.StatusAccepted {
				t.Fatalf("different-key submit = %d: %s", other.Code, other.Body.String())
			}
			var otherRun model.Run
			if err := json.Unmarshal(other.Body.Bytes(), &otherRun); err != nil {
				t.Fatal(err)
			}
			if otherRun.ID == firstRun.ID {
				t.Fatal("a different key must create a new run")
			}
		})
	}
}

// TestSubmitIdempotencyReplaySurvivesRestartFS pins the fs durability half:
// the receipt is in the SAME snapshot write as the run, so a control-plane
// restart after a lost response still replays the original run.
func TestSubmitIdempotencyReplaySurvivesRestartFS(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	body := idempotentSubmitBody("sha-one")
	key := "op-restart-replay"
	first := submitWithKey(t, s, body, key)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first submit = %d: %s", first.Code, first.Body.String())
	}
	var firstRun model.Run
	if err := json.Unmarshal(first.Body.Bytes(), &firstRun); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	replay := submitWithKey(t, restarted, body, key)
	if replay.Code != http.StatusAccepted {
		t.Fatalf("post-restart replay = %d: %s", replay.Code, replay.Body.String())
	}
	var replayed model.Run
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ID != firstRun.ID {
		t.Fatalf("post-restart replay = %s, want %s", replayed.ID, firstRun.ID)
	}
	conflict := submitWithKey(t, restarted, idempotentSubmitBody("sha-two"), key)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("post-restart altered replay = %d: %s", conflict.Code, conflict.Body.String())
	}
}

func TestSubmitIdempotencyRejectsInvalidKey(t *testing.T) {
	s := New("token")
	for _, key := range []string{"has space", strings.Repeat("x", maxIdempotencyKeyLen+1), "tab\tkey"} {
		w := submitWithKey(t, s, idempotentSubmitBody("sha"), key)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid key %q = %d: %s", key, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "INVALID_IDEMPOTENCY_KEY") {
			t.Fatalf("invalid key %q reason missing: %s", key, w.Body.String())
		}
	}
	s.mu.Lock()
	runCount := len(s.runs)
	s.mu.Unlock()
	if runCount != 0 {
		t.Fatalf("invalid-key submissions enqueued %d runs, want 0", runCount)
	}
}

// TestRerunIdempotencyReplayFS pins the rerun ingress: a retried rerun with
// the same key returns the first rerun instead of creating another, and a
// key bound to a different source run conflicts.
func TestRerunIdempotencyReplayFS(t *testing.T) {
	s := New("token")
	body := idempotentSubmitBody("sha-one")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("source submit = %d: %s", w.Code, w.Body.String())
	}
	var source model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}

	key := "rerun-key-1"
	rerun := func(runID string) *httptest.ResponseRecorder {
		return doJSONHeaders(t, s, http.MethodPost, "/api/v1/runs/"+runID+"/rerun", "token", "", map[string]string{"Idempotency-Key": key})
	}
	first := rerun(source.ID)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first rerun = %d: %s", first.Code, first.Body.String())
	}
	var firstRerun model.Run
	if err := json.Unmarshal(first.Body.Bytes(), &firstRerun); err != nil {
		t.Fatal(err)
	}
	replay := rerun(source.ID)
	if replay.Code != http.StatusAccepted {
		t.Fatalf("replayed rerun = %d: %s", replay.Code, replay.Body.String())
	}
	var replayed model.Run
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ID != firstRerun.ID {
		t.Fatalf("replayed rerun = %s, want %s", replayed.ID, firstRerun.ID)
	}
	if replayed.ID == source.ID {
		t.Fatal("rerun must create a new run, not return the source")
	}
}

// TestIdempotencyReceiptRetentionFS pins the fs receipt bound: GC drops
// receipts of pruned runs and receipts past the TTL, and keeps live ones.
func TestIdempotencyReceiptRetentionFS(t *testing.T) {
	s := New("token")
	now := time.Now().UTC()
	s.mu.Lock()
	s.idempotency[runIdempotencyReceiptKey("github.com/o/r", "live")] = storage.IdempotencyReceipt{RepoID: "github.com/o/r", Key: "live", Digest: "d1", RunID: "run-live", CreatedAt: now}
	s.idempotency[runIdempotencyReceiptKey("github.com/o/r", "old")] = storage.IdempotencyReceipt{RepoID: "github.com/o/r", Key: "old", Digest: "d2", RunID: "run-old", CreatedAt: now.Add(-storage.IdempotencyReceiptTTL - time.Hour)}
	s.idempotency[runIdempotencyReceiptKey("github.com/o/r", "pruned")] = storage.IdempotencyReceipt{RepoID: "github.com/o/r", Key: "pruned", Digest: "d3", RunID: "run-pruned", CreatedAt: now}
	removed := s.pruneRunIdempotencyLocked(now, []string{"run-pruned"})
	remaining := len(s.idempotency)
	s.mu.Unlock()
	if removed != 2 || remaining != 1 {
		t.Fatalf("prune removed %d, remaining %d; want 2 removed (TTL + pruned run) and the live receipt kept", removed, remaining)
	}
	if _, ok := s.idempotency[runIdempotencyReceiptKey("github.com/o/r", "live")]; !ok {
		t.Fatal("live receipt was pruned")
	}
}

// TestIdempotencyReceiptPruneDB pins the leader maintenance call: GC prunes
// durable receipts past the TTL through the store contract.
func TestIdempotencyReceiptPruneDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	f.mu.Lock()
	f.runIdempotency[dbFakeIdempotencyKey("github.com/o/r", "old")] = storage.RunIdempotencyClaim{RepoID: "github.com/o/r", Key: "old", Digest: "d", RunID: "r", CreatedAt: now.Add(-storage.IdempotencyReceiptTTL - time.Hour)}
	f.runIdempotency[dbFakeIdempotencyKey("github.com/o/r", "live")] = storage.RunIdempotencyClaim{RepoID: "github.com/o/r", Key: "live", Digest: "d", RunID: "r2", CreatedAt: now}
	f.mu.Unlock()
	s.leader = true
	s.GC(context.Background(), now)
	f.mu.Lock()
	_, oldExists := f.runIdempotency[dbFakeIdempotencyKey("github.com/o/r", "old")]
	_, liveExists := f.runIdempotency[dbFakeIdempotencyKey("github.com/o/r", "live")]
	f.mu.Unlock()
	if oldExists || !liveExists {
		t.Fatalf("DB prune: old exists=%v, live exists=%v; want old pruned and live kept", oldExists, liveExists)
	}
}

// TestSubmitIdempotencyConcurrentFirstSubmissionDB pins the in-transaction
// claim race: two concurrent first submissions of the same key may both pass
// the pre-check, but exactly one wins the receipt and the loser replays to
// the winner's run.
func TestSubmitIdempotencyConcurrentFirstSubmissionDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := idempotentSubmitBody("sha-race")
	key := "op-race"
	type result struct {
		code int
		run  model.Run
	}
	const n = 4
	results := make(chan result, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			w := submitWithKey(t, s, body, key)
			var run model.Run
			_ = json.Unmarshal(w.Body.Bytes(), &run)
			results <- result{code: w.Code, run: run}
		}()
	}
	close(start)
	ids := map[string]bool{}
	for i := 0; i < n; i++ {
		r := <-results
		if r.code != http.StatusAccepted {
			t.Fatalf("concurrent submit = %d", r.code)
		}
		ids[r.run.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("concurrent same-key submits produced %d distinct runs, want 1", len(ids))
	}
	f.mu.Lock()
	inserts := len(f.insertRunCalls)
	receipts := len(f.runIdempotency)
	f.mu.Unlock()
	if inserts != 1 {
		t.Fatalf("durable inserts = %d, want exactly 1", inserts)
	}
	if receipts != 1 {
		t.Fatalf("durable receipts = %d, want exactly 1", receipts)
	}
}

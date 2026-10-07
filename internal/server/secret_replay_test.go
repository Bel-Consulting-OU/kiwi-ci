package server

// Retry-stable sealed delivery regressions (finding 7) and the fs journal
// half: an identical retry — same job, generation, secret and runner
// ephemeral public key — must return the EXACT committed envelope without
// re-resolving the broker and without a second claim or audit, in memory/fs
// and DB-fake modes alike. A retry presenting a different key stays 409.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// decodeSecretResponse decodes one 200 secret delivery body.
func decodeSecretResponse(t *testing.T, body []byte) SecretResponse {
	t.Helper()
	var out SecretResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode secret response: %v (%s)", err, body)
	}
	if out.Ciphertext == "" || out.EphemeralPublic == "" || out.Nonce == "" {
		t.Fatalf("incomplete envelope: %s", body)
	}
	return out
}

// TestSecretRetrySameKeyReplaysMemory is the memory/fs half of the retry
// contract: the identical retry is answered 200 with the stored envelope, the
// broker is NOT re-resolved, and exactly one receipt exists.
func TestSecretRetrySameKeyReplaysMemory(t *testing.T) {
	s := New("secret")
	broker := &countingBroker{}
	s.SecretBroker = broker
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}

	first := issue(t, c, jobID, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first delivery = %d: %s", first.Code, first.Body.String())
	}
	firstEnv := decodeSecretResponse(t, first.Body.Bytes())

	retry := issue(t, c, jobID, req)
	if retry.Code != http.StatusOK {
		t.Fatalf("same-key retry = %d, want 200: %s", retry.Code, retry.Body.String())
	}
	retryEnv := decodeSecretResponse(t, retry.Body.Bytes())
	if retryEnv != firstEnv {
		t.Fatalf("retry envelope = %+v, want the exact committed %+v", retryEnv, firstEnv)
	}
	if got := broker.count(); got != 1 {
		t.Fatalf("broker resolutions = %d, want 1 (a replay must not re-resolve)", got)
	}
	if got := memSecretReceipts(s, jobID); got != 1 {
		t.Fatalf("receipts = %d, want 1", got)
	}
}

// TestSecretRetryDifferentKeyConflictsMemory: the same delivery identity with
// a DIFFERENT runner public key stays 409 and never receives the stored
// envelope.
func TestSecretRetryDifferentKeyConflictsMemory(t *testing.T) {
	s := New("secret")
	broker := &countingBroker{}
	s.SecretBroker = broker
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first delivery = %d: %s", w.Code, w.Body.String())
	}

	_, otherPub := ephemeralKey(t)
	req.EphemeralPublic = otherPub
	w := issue(t, c, jobID, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("different-key retry = %d, want 409: %s", w.Code, w.Body.String())
	}
	if got := broker.count(); got != 1 {
		t.Fatalf("broker resolutions = %d, want 1 (the 409 must come from the stored record)", got)
	}
	if got := memSecretReceipts(s, jobID); got != 1 {
		t.Fatalf("receipts = %d, want 1", got)
	}
}

// TestSecretRetrySameKeyReplaysAfterJournalRestart is the full fs restart
// regression: after a compaction that evicts thousands of terminal receipts,
// a fresh server instance on the same data dir replays the live receipt's
// committed envelope from the journal — with a broker that would fail if it
// were consulted — while a different key still gets 409.
func TestSecretRetrySameKeyReplaysAfterJournalRestart(t *testing.T) {
	const value = "restart-replay-value"
	dir := t.TempDir()
	s := New("secret")
	s.dataDir = dir
	s.SecretBroker = secretbroker.StaticBroker{"tok": value}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	first := issue(t, c, jobID, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first delivery = %d: %s", first.Code, first.Body.String())
	}
	firstEnv := decodeSecretResponse(t, first.Body.Bytes())

	// Pressure: 16,384 unrelated terminal receipts make the live receipt the
	// only non-evictable record, so compaction must retain it (and its
	// envelope) rather than trimming by recency.
	s.mu.Lock()
	for i := 0; i < secretReceiptsMaxEntries; i++ {
		s.secretReceipts[fmt.Sprintf("dead-job-%06d|1|tok", i)] = secretReceipt{}
	}
	liveKey := secretReceiptKey(jobID, gen, "tok")
	if _, ok := s.secretReceipts[liveKey]; !ok {
		s.mu.Unlock()
		t.Fatal("live receipt missing before compaction")
	}
	persistErr := s.persistSecretReceiptsLocked()
	s.mu.Unlock()
	if persistErr != nil {
		t.Fatal(persistErr)
	}

	s.mu.Lock()
	_, liveRetained := s.secretReceipts[liveKey]
	receiptCount := len(s.secretReceipts)
	s.mu.Unlock()
	if !liveRetained {
		t.Fatal("compaction evicted the live sealed receipt")
	}
	if receiptCount > secretReceiptsMaxEntries {
		t.Fatalf("receipts after compaction = %d, want <= %d", receiptCount, secretReceiptsMaxEntries)
	}

	// Restart on the same data dir. The broker is armed to fail: a replay
	// that resolved the broker would answer 500 instead of replaying.
	s2 := New("secret")
	if err := s2.loadSecretReceipts(dir); err != nil {
		t.Fatal(err)
	}
	jobID2, runnerID2, token2, gen2 := seedJob(t, s2, true, []string{"tok"})
	if jobID2 != jobID || gen2 != gen {
		t.Fatalf("reseeded job identity changed: %s/%d -> %s/%d", jobID, gen, jobID2, gen2)
	}
	s2.SecretBroker = failingBroker{err: errors.New("broker must not be re-resolved for a replay")}
	c2 := newTestClient(t, s2.Handler(), "secret")
	replay := issue(t, c2, jobID, SecretRequest{RunnerID: runnerID2, LeaseToken: token2, LeaseGeneration: gen2, Name: "tok", EphemeralPublic: pubB64})
	if replay.Code != http.StatusOK {
		t.Fatalf("post-restart same-key retry = %d, want 200: %s", replay.Code, replay.Body.String())
	}
	replayEnv := decodeSecretResponse(t, replay.Body.Bytes())
	if replayEnv != firstEnv {
		t.Fatalf("post-restart envelope = %+v, want the exact committed %+v", replayEnv, firstEnv)
	}

	_, otherPub := ephemeralKey(t)
	conflict := issue(t, c2, jobID, SecretRequest{RunnerID: runnerID2, LeaseToken: token2, LeaseGeneration: gen2, Name: "tok", EphemeralPublic: otherPub})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("post-restart different-key retry = %d, want 409: %s", conflict.Code, conflict.Body.String())
	}
}

// TestSecretDBFakeSameKeyRetryReplays pins the DB-mode server path against the
// fake store: a same-key retry replays the stored envelope with no second
// broker resolution, claim or audit.
func TestSecretDBFakeSameKeyRetryReplays(t *testing.T) {
	f := newDBFakeStore()
	s := dbSecretServer(t, f)
	broker := &countingBroker{}
	s.SecretBroker = broker
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	first := issue(t, c, jobID, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first delivery = %d: %s", first.Code, first.Body.String())
	}
	firstEnv := decodeSecretResponse(t, first.Body.Bytes())

	retry := issue(t, c, jobID, req)
	if retry.Code != http.StatusOK {
		t.Fatalf("same-key retry = %d, want 200: %s", retry.Code, retry.Body.String())
	}
	if retryEnv := decodeSecretResponse(t, retry.Body.Bytes()); retryEnv != firstEnv {
		t.Fatalf("retry envelope = %+v, want the exact committed %+v", retryEnv, firstEnv)
	}
	if got := broker.count(); got != 1 {
		t.Fatalf("broker resolutions = %d, want 1", got)
	}
	if got := fakeSecretClaims(f, jobID); got != 1 {
		t.Fatalf("claims = %d, want 1", got)
	}
	if got := fakeSecretAudits(f, jobID); got != 1 {
		t.Fatalf("audits = %d, want 1", got)
	}

	// Stale generation: lease validation refuses BEFORE any replay, even
	// though the stored envelope would otherwise match.
	req.LeaseGeneration = gen + 1
	if w := issue(t, c, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("stale-generation replay = %d, want 409: %s", w.Code, w.Body.String())
	}
}

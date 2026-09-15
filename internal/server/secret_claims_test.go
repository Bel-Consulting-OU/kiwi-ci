package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// seedDBSecretJob installs a running job holding a valid lease into the
// DB-fake store (not the server's memory maps) so DB-mode issuance reads
// the store.
func seedDBSecretJob(t *testing.T, f *dbFakeStore, s *Server, declared []string) (jobID, runnerID, token string, generation int64) {
	t.Helper()
	token = "test-lease-token"
	exp := time.Now().UTC().Add(time.Minute)
	f.mu.Lock()
	f.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/kiwi/repo.git", Status: model.StatusRunning}
	f.jobs["job-1"] = model.Job{
		ID: "job-1", RunID: "run-1", Key: "build", RepoURL: "https://github.com/kiwi/repo.git",
		Status: model.StatusRunning, Trusted: true, DeclaredSecrets: declared,
		LeaseRunnerID: "runner-1", LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 7, LeaseExpiresAt: &exp,
	}
	f.mu.Unlock()
	return "job-1", "runner-1", token, 7
}

func dbSecretServer(t *testing.T, f *dbFakeStore) *Server {
	t.Helper()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	return s
}

// TestIssueSecretDBModeConcurrentSingleDelivery proves the SQL claim is the
// arbitration: two concurrent deliveries of the same (job, generation,
// name) result in exactly one 200 and one 409.
func TestIssueSecretDBModeConcurrentSingleDelivery(t *testing.T) {
	f := newDBFakeStore()
	s := dbSecretServer(t, f)
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}

	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- issue(t, c, jobID, req).Code
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	if got[http.StatusOK] != 1 || got[http.StatusConflict] != 1 {
		t.Fatalf("concurrent deliveries = %v, want exactly one 200 and one 409", got)
	}
	f.mu.Lock()
	claimed := len(f.secretClaims)
	f.mu.Unlock()
	if claimed != 1 {
		t.Fatalf("claims persisted = %d, want 1", claimed)
	}
}

// TestIssueSecretDBModeClaimErrorFailsClosed proves a claim persistence
// error returns 503 and never returns an envelope.
func TestIssueSecretDBModeClaimErrorFailsClosed(t *testing.T) {
	f := newDBFakeStore()
	s := dbSecretServer(t, f)
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
	f.mu.Lock()
	f.claimErr = errors.New("claim: injected failure")
	f.mu.Unlock()
	_, pubB64 := ephemeralKey(t)
	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("claim error: want 503, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ciphertext") {
		t.Fatalf("envelope leaked on claim failure: %s", w.Body.String())
	}
}

// TestIssueSecretDBModeClaimSurvivesRestart proves the SQL claim outlives a
// control-plane restart: a fresh server on the same store refuses the
// replay.
func TestIssueSecretDBModeClaimSurvivesRestart(t *testing.T) {
	f := newDBFakeStore()
	s1 := dbSecretServer(t, f)
	c1 := newTestClient(t, s1.Handler(), "secret")
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s1, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c1, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first issue: %d %s", w.Code, w.Body.String())
	}

	// "Restart": a fresh server instance on the same store.
	s2 := dbSecretServer(t, f)
	c2 := newTestClient(t, s2.Handler(), "secret")
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c2, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("replay after restart: want 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIssueSecretMemoryReceiptPersistenceFailsClosed proves the memory-mode
// receipt file write failure returns 500 and never returns an envelope
// (no more log-and-continue for delivery state).
func TestIssueSecretMemoryReceiptPersistenceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	// Replace the receipts file path with a directory so the atomic write
	// fails.
	if err := os.Mkdir(filepath.Join(dir, secretReceiptsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	_, pubB64 := ephemeralKey(t)
	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("receipt write failure: want 500, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ciphertext") {
		t.Fatalf("envelope leaked on receipt failure: %s", w.Body.String())
	}
	var env SecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &env); err == nil && env.Ciphertext != "" {
		t.Fatalf("envelope returned despite receipt failure: %+v", env)
	}
}

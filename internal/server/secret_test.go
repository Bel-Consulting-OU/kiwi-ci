package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// seedJob inserts a running job holding a valid lease directly into the
// server's in-memory state, reproducing the lease authorization next()
// establishes without going through submission/registration.
func seedJob(t *testing.T, s *Server, trusted bool, declared []string) (jobID, runnerID, token string, generation int64) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	jobID, runnerID = "job-1", "runner-1"
	token = "test-lease-token"
	s.jobs[jobID] = model.Job{
		ID: jobID, RunID: "run-1", Key: "build", RepoURL: "https://github.com/kiwi/repo.git",
		Status: model.StatusRunning, Trusted: trusted, DeclaredSecrets: declared,
		LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 7, LeaseExpiresAt: &exp,
	}
	s.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/kiwi/repo.git", Status: model.StatusRunning}
	return jobID, runnerID, token, 7
}

// ephemeralKey mints a fresh X25519 client keypair and returns the private
// key plus the base64-encoded public key for the request.
func ephemeralKey(t *testing.T) ([32]byte, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var arr [32]byte
	copy(arr[:], priv.Bytes())
	return arr, base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

func issue(t *testing.T, c *testClient, jobID string, in SecretRequest) *httptest.ResponseRecorder {
	t.Helper()
	return c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/secrets", in, nil)
}

func TestIssueSecretDecryptableEnvelope(t *testing.T) {
	const value = "the-ultra-secret-value"
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": value}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	priv, pubB64 := ephemeralKey(t)

	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), value) {
		t.Fatalf("plaintext secret value leaked into response: %s", w.Body.String())
	}
	var out SecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.LeaseGeneration != gen {
		t.Fatalf("lease generation = %d, want %d", out.LeaseGeneration, gen)
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := base64.StdEncoding.DecodeString(out.EphemeralPublic)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(out.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := secretbroker.OpenEnvelope(secretbroker.EncryptedDelivery{Ciphertext: ct, EphemeralPublic: ep, Nonce: nonce}, priv, secretAAD(runnerID, jobID, gen, "tok"))
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	if string(plain) != value {
		t.Fatalf("decrypted %q, want %q", plain, value)
	}
}

func TestIssueSecretNotDeclared(t *testing.T) {
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"other"})
	_, pubB64 := ephemeralKey(t)

	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for undeclared secret, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueSecretUntrustedJob(t *testing.T) {
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, false, []string{"tok"})
	_, pubB64 := ephemeralKey(t)

	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for untrusted job, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueSecretStaleLease(t *testing.T) {
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)

	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token + "x", LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusConflict {
		t.Fatalf("wrong token: want 409, got %d: %s", w.Code, w.Body.String())
	}
	w = issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen + 1, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusConflict {
		t.Fatalf("wrong generation: want 409, got %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[jobID]
	expired := time.Now().Add(-time.Minute)
	j.LeaseExpiresAt = &expired
	s.jobs[jobID] = j
	s.mu.Unlock()
	w = issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusConflict {
		t.Fatalf("expired lease: want 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueSecretBrokerNotConfigured(t *testing.T) {
	s := New("x")
	c := newTestClient(t, s.Handler(), "x")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)

	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 without broker, got %d: %s", w.Code, w.Body.String())
	}
}

func TestIssueSecretDuplicateDelivery(t *testing.T) {
	s := New("secret")
	s.SecretBroker = &secretbroker.OneTime{Inner: secretbroker.StaticBroker{"tok": "v"}}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)

	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first issue: %d %s", w.Code, w.Body.String())
	}
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("second issue: want 409, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIssueSecretReceiptServerOwned proves the durable once-only record is
// server-owned: a plain (non-OneTime) broker still gets exactly one delivery
// per (job, generation, secret), a new generation delivers again, and a
// different secret name is independent.
func TestIssueSecretReceiptServerOwned(t *testing.T) {
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok", "other"})

	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first issue: %d %s", w.Code, w.Body.String())
	}
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("replay without OneTime broker: want 409, got %d: %s", w.Code, w.Body.String())
	}
	// A different generation is a new delivery (the receipt is generation
	// scoped).
	s.mu.Lock()
	j := s.jobs[jobID]
	j.LeaseGeneration++
	s.jobs[jobID] = j
	s.mu.Unlock()
	_, pubB64 = ephemeralKey(t)
	req.LeaseGeneration = gen + 1
	req.EphemeralPublic = pubB64
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("new generation issue: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestIssueSecretReceiptSurvivesRestart proves the delivery receipt persists
// through the dataDir receipt file: replaying after a restart conflicts.
func TestIssueSecretReceiptSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s1.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s1.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s1, true, []string{"tok"})
	// seedJob writes the run/job into the memory maps only; persist them so
	// the restarted server sees the same job.
	s1.mu.Lock()
	_ = s1.persistLocked()
	s1.mu.Unlock()

	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first issue: %d %s", w.Code, w.Body.String())
	}

	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c2 := newTestClient(t, s2.Handler(), "secret")
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c2, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("replay after restart: want 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEnqueueDeclaredSecrets(t *testing.T) {
	s := New("secret")
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", Ref: "main",
		Pipeline: `version: 1
secrets: [global-a, global-b, global-a]
jobs:
  build:
    steps:
      - secrets: [step-x, global-a]
        run: echo hi
      - secrets: [step-y, step-x]
        run: echo bye
`,
		Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var got []string
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			got = j.DeclaredSecrets
		}
	}
	want := []string{"global-a", "global-b", "step-x", "step-y"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeclaredSecrets = %v, want %v", got, want)
	}
}

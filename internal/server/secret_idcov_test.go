package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// idcovDelegateBroker forwards Resolve to a wrapped broker so the OneTime
// dedupe record is reachable through the server's single-level unwrap.
type idcovDelegateBroker struct{ inner secretbroker.Broker }

func (b idcovDelegateBroker) Resolve(ctx context.Context, name string, scope secretbroker.SecretScope) (string, error) {
	return b.inner.Resolve(ctx, name, scope)
}

// idcovSeedDBJob inserts a running lease job into the fake store (DB mode
// reads the store, never the memory maps).
func idcovSeedDBJob(t *testing.T, s *Server, f *dbFakeStore, jobID, runID string, trusted bool, declared []string) (string, string, string, int64) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Minute)
	const token = "db-lease-token"
	f.mu.Lock()
	f.runs[runID] = model.Run{ID: runID, Repo: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo", RepoID: "github.com/kiwi/repo", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{
		ID: jobID, RunID: runID, Key: "build",
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Status: model.StatusRunning, Trusted: trusted, DeclaredSecrets: declared,
		LeaseRunnerID: "runner-db", LeaseTokenHash: hashLeaseToken(s.leaseKey, token),
		LeaseGeneration: 3, LeaseExpiresAt: &exp,
	}
	f.mu.Unlock()
	return jobID, "runner-db", token, 3
}

// TestIDCovLoadSecretReceiptsPaths covers the receipt file loader.
func TestIDCovLoadSecretReceiptsPaths(t *testing.T) {
	s := New("t")
	if err := s.loadSecretReceipts(""); err != nil || s.secretReceipts == nil {
		t.Fatalf("empty dir = %v (map=%v)", err, s.secretReceipts)
	}
	empty := t.TempDir()
	s2 := New("t")
	if err := s2.loadSecretReceipts(empty); err != nil || len(s2.secretReceipts) != 0 {
		t.Fatalf("missing file = %v (%v)", err, s2.secretReceipts)
	}
	// An unreadable path is an error.
	dirPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirPath, secretReceiptsFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadSecretReceipts(dirPath); err == nil {
		t.Fatal("directory as receipt file = nil error")
	}
	// A corrupt receipt file is refused.
	corrupt := t.TempDir()
	writeTestFile(t, filepath.Join(corrupt, secretReceiptsFile), []byte("{"))
	if err := New("t").loadSecretReceipts(corrupt); err == nil {
		t.Fatal("corrupt receipt file = nil error")
	}
	// Blank entries are skipped, real ones load.
	good := t.TempDir()
	writeTestFile(t, filepath.Join(good, secretReceiptsFile), []byte(`["a|1|tok","  ","","b|2|tok"]`))
	s3 := New("t")
	if err := s3.loadSecretReceipts(good); err != nil {
		t.Fatal(err)
	}
	if len(s3.secretReceipts) != 2 || !s3.secretReceipts["a|1|tok"] || !s3.secretReceipts["b|2|tok"] {
		t.Fatalf("loaded receipts = %v", s3.secretReceipts)
	}
}

// TestIDCovIssueSecretBadJSON covers the decode guard.
func TestIDCovIssueSecretBadJSON(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/j1/secrets", nil, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("empty body = %d, want 400", w.Code)
	}
	// A DTO field that does not exist is rejected by strict decoding.
	if w := c.do(http.MethodPost, "/api/v1/jobs/j1/secrets", map[string]any{"bogus": 1}, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", w.Code)
	}
}

// TestIDCovIssueSecretUnsupportedClaimStore covers the DB-mode refusal when
// the store cannot claim deliveries.
func TestIDCovIssueSecretUnsupportedClaimStore(t *testing.T) {
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	f := newDBFakeStore()
	s.DB = idcovStoreOnly{Store: f}
	jobID, runnerID, token, gen := idcovSeedDBJob(t, s, f, "job-503", "run-503", true, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	c := newTestClient(t, s.Handler(), "secret")
	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unsupported claim store = %d, want 503: %s", w.Code, w.Body.String())
	}
}

// TestIDCovResolveBrokerAlreadyDelivered covers the unwrap path and the
// OneTime ErrAlreadyDelivered passthrough.
func TestIDCovResolveBrokerAlreadyDelivered(t *testing.T) {
	s := New("t")
	static := secretbroker.StaticBroker{"tok": "v"}
	one := &secretbroker.OneTime{Inner: static}
	// The server unwraps a direct OneTime wrapper, so the ErrAlreadyDelivered
	// passthrough is observable through a broker that delegates to OneTime.
	s.SecretBroker = idcovDelegateBroker{inner: one}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	scope := secretbroker.SecretScope{Repository: "repo", Environment: "prod"}
	if _, err := s.resolveBroker(req, "tok", scope); err != nil {
		t.Fatalf("first resolve = %v", err)
	}
	if _, err := s.resolveBroker(req, "tok", scope); !errors.Is(err, secretbroker.ErrAlreadyDelivered) {
		t.Fatalf("second resolve = %v, want ErrAlreadyDelivered", err)
	}
	// The direct OneTime wrapper is unwrapped to its inner broker.
	s.SecretBroker = one
	if _, err := s.resolveBroker(req, "tok", scope); err != nil {
		t.Fatalf("unwrapped OneTime resolve = %v", err)
	}
	// A OneTime wrapper without an inner broker fails closed with a clear
	// error instead of panicking on the nil interface dispatch.
	s.SecretBroker = &secretbroker.OneTime{}
	if _, err := s.resolveBroker(req, "tok", scope); !errors.Is(err, secretbroker.ErrNilInner) {
		t.Fatalf("nil-Inner OneTime resolve = %v, want ErrNilInner", err)
	}
}

// TestIDCovDeliverSecretCommitOrdering covers the pre-commit failure branches
// and the commit-time compensation: an already-delivered broker reply, a
// receipt persistence failure (fail closed), an audit failure (the receipt is
// released), a sealing failure (nothing consumed) and an unknown job.
func TestIDCovDeliverSecretCommitOrdering(t *testing.T) {
	seed := func(t *testing.T, s *Server) (model.Job, SecretRequest, []byte) {
		t.Helper()
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		s.mu.Lock()
		job := s.jobs[jobID]
		s.mu.Unlock()
		_, pubB64 := ephemeralKey(t)
		pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			t.Fatal(err)
		}
		return job, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}, pubRaw
	}

	t.Run("broker already delivered", func(t *testing.T) {
		s := New("t")
		// The server unwraps a direct OneTime wrapper, so the delivered
		// marker is only observable through a delegating broker.
		s.SecretBroker = idcovDelegateBroker{inner: &secretbroker.OneTime{Inner: secretbroker.StaticBroker{"tok": "v"}}}
		job, req, pubRaw := seed(t, s)
		w1 := httptest.NewRecorder()
		s.deliverSecret(w1, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pubRaw)
		if w1.Code != http.StatusOK {
			t.Fatalf("first delivery = %d: %s", w1.Code, w1.Body.String())
		}
		// The broker's one-time record refuses the second retrieval before
		// any commit: 409, still exactly one receipt.
		_, pub2 := ephemeralKey(t)
		pub2Raw, err := base64.StdEncoding.DecodeString(pub2)
		if err != nil {
			t.Fatal(err)
		}
		req.EphemeralPublic = pub2
		w2 := httptest.NewRecorder()
		s.deliverSecret(w2, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pub2Raw)
		if w2.Code != http.StatusConflict {
			t.Fatalf("already-delivered delivery = %d, want 409: %s", w2.Code, w2.Body.String())
		}
		if n := memSecretReceipts(s, job.ID); n != 1 {
			t.Fatalf("receipts = %d, want 1", n)
		}
	})

	t.Run("receipt persistence failure fails closed", func(t *testing.T) {
		dir := t.TempDir()
		s := New("t")
		s.dataDir = dir
		if err := os.Mkdir(filepath.Join(dir, secretReceiptsFile), 0o700); err != nil {
			t.Fatal(err)
		}
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		job, req, pubRaw := seed(t, s)
		w := httptest.NewRecorder()
		s.deliverSecret(w, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pubRaw)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("broken receipt dir = %d, want 503: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatalf("envelope returned despite receipt failure: %s", w.Body.String())
		}
	})

	t.Run("audit failure releases the receipt", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New("t")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		job, req, pubRaw := seed(t, s)
		s.store = &storage.Repository{Root: blocker}
		w := httptest.NewRecorder()
		s.deliverSecret(w, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pubRaw)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("audit failure = %d, want 500: %s", w.Code, w.Body.String())
		}
		if n := memSecretReceipts(s, job.ID); n != 0 {
			t.Fatalf("audit failure left %d receipts behind", n)
		}
		// A healthy audit sink lets the same delivery commit.
		s.store = nil
		_, pub2 := ephemeralKey(t)
		pub2Raw, err := base64.StdEncoding.DecodeString(pub2)
		if err != nil {
			t.Fatal(err)
		}
		req.EphemeralPublic = pub2
		w2 := httptest.NewRecorder()
		s.deliverSecret(w2, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pub2Raw)
		if w2.Code != http.StatusOK {
			t.Fatalf("retry after audit recovery = %d: %s", w2.Code, w2.Body.String())
		}
	})

	t.Run("seal failure does not consume the delivery", func(t *testing.T) {
		s := New("t")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		job, req, _ := seed(t, s)
		zeros := make([]byte, 32)
		req.EphemeralPublic = base64.StdEncoding.EncodeToString(zeros)
		w := httptest.NewRecorder()
		s.deliverSecret(w, httptest.NewRequest(http.MethodPost, "/", nil), job, req, zeros)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("low-order key = %d, want 500: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "sealing secret failed") {
			t.Fatalf("wrong failure body: %s", w.Body.String())
		}
		// The claim was never taken: retrying with a valid key succeeds.
		_, pubB64 := ephemeralKey(t)
		pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			t.Fatal(err)
		}
		req.EphemeralPublic = pubB64
		w2 := httptest.NewRecorder()
		s.deliverSecret(w2, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pubRaw)
		if w2.Code != http.StatusOK {
			t.Fatalf("retry after seal failure = %d: %s", w2.Code, w2.Body.String())
		}
	})

	t.Run("unknown job refused", func(t *testing.T) {
		s := New("t")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		job := model.Job{ID: "job-missing", RunID: "run-1", RepoURL: "repo", Trusted: true, LeaseGeneration: 1, LeaseTokenHash: []byte("hash")}
		_, pubB64 := ephemeralKey(t)
		pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			t.Fatal(err)
		}
		req := SecretRequest{RunnerID: "r1", LeaseGeneration: 1, Name: "tok", EphemeralPublic: pubB64}
		w := httptest.NewRecorder()
		s.deliverSecret(w, httptest.NewRequest(http.MethodPost, "/", nil), job, req, pubRaw)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unknown job = %d, want 404: %s", w.Code, w.Body.String())
		}
	})
}

// TestIDCovIssueSecretDBClaimConflict covers the durable replay conflict.
func TestIDCovIssueSecretDBClaimConflict(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	jobID, runnerID, token, gen := idcovSeedDBJob(t, s, f, "job-db-1", "run-db-1", true, []string{"tok"})
	c := newTestClient(t, s.Handler(), "secret")
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("first DB delivery = %d: %s", w.Code, w.Body.String())
	}
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c, jobID, req); w.Code != http.StatusConflict {
		t.Fatalf("DB replay = %d, want 409: %s", w.Code, w.Body.String())
	}
}

// TestIDCovReleaseAndMarkReceiptHelpers covers markSecretDelivered's replay
// and persistence-failure branches.
func TestIDCovMarkAndReleaseReceiptHelpers(t *testing.T) {
	s := New("t")
	ok, err := s.markSecretDelivered("k1")
	if err != nil || !ok {
		t.Fatalf("first mark = %v, %v", ok, err)
	}
	if ok, err := s.markSecretDelivered("k1"); err != nil || ok {
		t.Fatalf("replay mark = %v, %v", ok, err)
	}
	if err := s.releaseSecretReceipt("k1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.markSecretDelivered("k1"); err != nil || !ok {
		t.Fatalf("mark after release = %v, %v", ok, err)
	}
	// A persistence failure rolls back the in-memory mark.
	blocker := filepath.Join(t.TempDir(), "blocker")
	writeTestFile(t, blocker, []byte("x"))
	s.dataDir = blocker
	s.secretReceipts = map[string]bool{}
	if ok, err := s.markSecretDelivered("k2"); ok || err == nil {
		t.Fatalf("failing mark = %v, %v", ok, err)
	}
	if s.secretReceipts["k2"] {
		t.Fatal("failed mark left the receipt behind")
	}
	// releaseSecretReceipt surfaces the persistence failure too.
	if err := s.releaseSecretReceipt("k2"); err == nil {
		t.Fatal("release with a broken data dir = nil error")
	}
}

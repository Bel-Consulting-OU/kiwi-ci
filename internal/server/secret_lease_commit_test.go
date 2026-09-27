package server

// P1 secret-issuance lease-revocation regressions. The broker hook below
// mutates the AUTHORITATIVE job after the handler has already authenticated the
// lease and resolved the broker value, reproducing the multi-second window the
// old claim-first flow could not close. Every case must answer 409 with no
// envelope, no claim and no audit row.

import (
	"context"
	"encoding/base64"
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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// hookBroker runs beforeFn (which mutates the authoritative job) after the
// preliminary auth but before the commit, then resolves the value.
type hookBroker struct {
	value    string
	beforeFn func()
}

func (b hookBroker) Resolve(context.Context, string, secretbroker.SecretScope) (string, error) {
	if b.beforeFn != nil {
		b.beforeFn()
	}
	return b.value, nil
}

// countingBroker records every resolution attempt.
type countingBroker struct {
	mu    sync.Mutex
	calls int
}

func (b *countingBroker) Resolve(context.Context, string, secretbroker.SecretScope) (string, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	return "v", nil
}

func (b *countingBroker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// mutateMemJob applies fn to the authoritative in-memory job.
func mutateMemJob(s *Server, jobID string, fn func(*model.Job)) func() {
	return func() {
		s.mu.Lock()
		j := s.jobs[jobID]
		fn(&j)
		s.jobs[jobID] = j
		s.mu.Unlock()
	}
}

// mutateFakeJob applies fn to the authoritative fake-store job.
func mutateFakeJob(f *dbFakeStore, jobID string, fn func(*model.Job)) func() {
	return func() {
		f.mu.Lock()
		j := f.jobs[jobID]
		fn(&j)
		f.jobs[jobID] = j
		f.mu.Unlock()
	}
}

// secretRegen inserts a fresh ephemeral key into the request.
func secretRegen(t *testing.T, in *SecretRequest) {
	t.Helper()
	_, pubB64 := ephemeralKey(t)
	in.EphemeralPublic = pubB64
}

// fakeSecretClaims counts fake-store claims for one job.
func fakeSecretClaims(f *dbFakeStore, jobID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for key := range f.secretClaims {
		if strings.HasPrefix(key, jobID+"|") {
			n++
		}
	}
	return n
}

// fakeSecretAudits counts fake-store secret.issued rows for one job.
func fakeSecretAudits(f *dbFakeStore, jobID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.audit {
		if e.Action == "secret.issued" && e.JobID == jobID {
			n++
		}
	}
	return n
}

// memSecretReceipts counts in-memory receipts for one job.
func memSecretReceipts(s *Server, jobID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key := range s.secretReceipts {
		if strings.HasPrefix(key, jobID+"|") {
			n++
		}
	}
	return n
}

// TestSecretRevokedDuringBrokerResolveReturns409 pins W1-A: a cancellation
// that lands while the broker resolves (after preliminary auth) makes the
// commit-time authority refuse with 409 and no envelope/claim/audit.
func TestSecretRevokedDuringBrokerResolveReturns409(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateMemJob(s, jobID, func(j *model.Job) { j.Status = model.StatusCancelled })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("revoked during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatalf("envelope returned after revocation: %s", w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 0 {
			t.Fatalf("revoked delivery recorded %d receipts", n)
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateFakeJob(f, jobID, func(j *model.Job) { j.Status = model.StatusCancelled })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("revoked during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatalf("envelope returned after revocation: %s", w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("revoked delivery recorded %d claims", n)
		}
		if n := fakeSecretAudits(f, jobID); n != 0 {
			t.Fatalf("revoked delivery recorded %d audits", n)
		}
	})
}

// TestSecretExpiredDuringBrokerResolveReturns409: the lease expires while the
// broker resolves; the commit's database/server clock refuses.
func TestSecretExpiredDuringBrokerResolveReturns409(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateMemJob(s, jobID, func(j *model.Job) {
			exp := time.Now().UTC().Add(-time.Second)
			j.LeaseExpiresAt = &exp
		})}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("expired during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 0 {
			t.Fatalf("expired delivery recorded %d receipts", n)
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateFakeJob(f, jobID, func(j *model.Job) {
			exp := time.Now().UTC().Add(-time.Second)
			j.LeaseExpiresAt = &exp
		})}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("expired during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("expired delivery recorded %d claims", n)
		}
	})
}

// TestSecretCompletedDuringBrokerResolveReturns409: the job completes while
// the broker resolves; no envelope may be returned.
func TestSecretCompletedDuringBrokerResolveReturns409(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateMemJob(s, jobID, func(j *model.Job) { j.Status = model.StatusSuccess })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("completed during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 0 {
			t.Fatalf("completed delivery recorded %d receipts", n)
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateFakeJob(f, jobID, func(j *model.Job) { j.Status = model.StatusSuccess })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("completed during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("completed delivery recorded %d claims", n)
		}
		if n := fakeSecretAudits(f, jobID); n != 0 {
			t.Fatalf("completed delivery recorded %d audits", n)
		}
	})
}

// TestSecretGenerationChangedBeforeCommitReturns409: a replacement lease
// (new generation) between preliminary auth and commit refuses typed, so a
// stale runner can never receive a secret under a superseded generation.
func TestSecretGenerationChangedBeforeCommitReturns409(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateMemJob(s, jobID, func(j *model.Job) { j.LeaseGeneration++ })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("generation changed during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 0 {
			t.Fatalf("stale generation recorded %d receipts", n)
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		s.SecretBroker = hookBroker{value: "v", beforeFn: mutateFakeJob(f, jobID, func(j *model.Job) { j.LeaseGeneration++ })}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
		if w.Code != http.StatusConflict {
			t.Fatalf("generation changed during resolve = %d, want 409: %s", w.Code, w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("stale generation recorded %d claims", n)
		}
	})
}

// TestSecretConcurrentRequestsOnlyOneReturnsEnvelope proves the delivery
// arbitration is the commit: concurrent requests may both retrieve from the
// broker, but exactly one commit wins and exactly one envelope is returned.
func TestSecretConcurrentRequestsOnlyOneReturnsEnvelope(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		c := newTestClient(t, s.Handler(), "secret")
		_, pub1 := ephemeralKey(t)
		_, pub2 := ephemeralKey(t)
		reqs := []SecretRequest{
			{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub1},
			{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub2},
		}
		envelopes, conflicts := runConcurrentSecretIssues(t, c, jobID, reqs)
		if envelopes != 1 || conflicts != 1 {
			t.Fatalf("concurrent memory issues = %d envelopes / %d conflicts, want 1/1", envelopes, conflicts)
		}
		if n := memSecretReceipts(s, jobID); n != 1 {
			t.Fatalf("receipts = %d, want 1", n)
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		c := newTestClient(t, s.Handler(), "secret")
		_, pub1 := ephemeralKey(t)
		_, pub2 := ephemeralKey(t)
		reqs := []SecretRequest{
			{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub1},
			{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub2},
		}
		envelopes, conflicts := runConcurrentSecretIssues(t, c, jobID, reqs)
		if envelopes != 1 || conflicts != 1 {
			t.Fatalf("concurrent db issues = %d envelopes / %d conflicts, want 1/1", envelopes, conflicts)
		}
		if n := fakeSecretClaims(f, jobID); n != 1 {
			t.Fatalf("claims = %d, want 1", n)
		}
		if n := fakeSecretAudits(f, jobID); n != 1 {
			t.Fatalf("audits = %d, want 1", n)
		}
	})
}

// runConcurrentSecretIssues fires both requests together and counts responses
// that carry a ciphertext versus those refused 409.
func runConcurrentSecretIssues(t *testing.T, c *testClient, jobID string, reqs []SecretRequest) (envelopes, conflicts int) {
	t.Helper()
	type result struct {
		code int
		body string
	}
	results := make(chan result, len(reqs))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, req := range reqs {
		wg.Add(1)
		go func(in SecretRequest) {
			defer wg.Done()
			<-start
			w := issue(t, c, jobID, in)
			results <- result{code: w.Code, body: w.Body.String()}
		}(req)
	}
	close(start)
	wg.Wait()
	close(results)
	for res := range results {
		switch res.code {
		case http.StatusOK:
			if !strings.Contains(res.body, "ciphertext") {
				t.Fatalf("200 without envelope: %s", res.body)
			}
			envelopes++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("concurrent issue = %d: %s", res.code, res.body)
		}
	}
	return envelopes, conflicts
}

// TestSecretNoEnvelopeWithoutDurableAudit proves a delivery is refused unless
// the secret.issued audit is durable: a DB transaction whose audit insert
// fails rolls the claim back, and a memory/fs server whose audit append fails
// releases the receipt; neither returns an envelope, and both allow a retry.
func TestSecretNoEnvelopeWithoutDurableAudit(t *testing.T) {
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		f.mu.Lock()
		f.auditErr = errors.New("audit: injected failure")
		f.mu.Unlock()
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
		w := issue(t, c, jobID, req)
		if w.Code == http.StatusOK {
			t.Fatalf("delivery without durable audit = %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatalf("envelope returned without durable audit: %s", w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("audit failure left %d claims behind", n)
		}
		if n := fakeSecretAudits(f, jobID); n != 0 {
			t.Fatalf("audit failure recorded %d audits", n)
		}
		f.mu.Lock()
		f.auditErr = nil
		f.mu.Unlock()
		secretRegen(t, &req)
		if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
			t.Fatalf("retry after audit recovery = %d, want 200: %s", w.Code, w.Body.String())
		}
		if n := fakeSecretClaims(f, jobID); n != 1 {
			t.Fatalf("claims after recovery = %d, want 1", n)
		}
	})
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A store root under a regular file makes the audit append fail.
		s.store = &storage.Repository{Root: blocker}
		c := newTestClient(t, s.Handler(), "secret")
		_, pubB64 := ephemeralKey(t)
		req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
		w := issue(t, c, jobID, req)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("audit failure = %d, want 500: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatalf("envelope returned without durable audit: %s", w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 0 {
			t.Fatalf("audit failure left %d receipts behind", n)
		}
		s.store = nil
		secretRegen(t, &req)
		if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
			t.Fatalf("retry after audit recovery = %d, want 200: %s", w.Code, w.Body.String())
		}
		if n := memSecretReceipts(s, jobID); n != 1 {
			t.Fatalf("receipts after recovery = %d, want 1", n)
		}
	})
}

// TestSecretInvalidEphemeralKeyRejectedBeforeBrokerWork proves request-shape
// validation happens BEFORE any broker or store work: a malformed key or
// secret name answers 400 and the broker is never called, no claim is
// attempted and no audit is written (#9).
func TestSecretInvalidEphemeralKeyRejectedBeforeBrokerWork(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 31))
	cases := []struct {
		name     string
		declared string
		reqName  string
		pub      string
		genKey   bool
	}{
		{name: "not base64", declared: "tok", reqName: "tok", pub: "%%%not-base64%%%"},
		{name: "wrong length", declared: "tok", reqName: "tok", pub: shortKey},
		{name: "empty key", declared: "tok", reqName: "tok", pub: ""},
		{name: "invalid name grammar", declared: "bad-name", reqName: "bad-name", genKey: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			broker := &countingBroker{}
			s := New("secret")
			s.SecretBroker = broker
			jobID, runnerID, token, gen := seedJob(t, s, true, []string{tc.declared})
			if tc.genKey {
				_, tc.pub = ephemeralKey(t)
			}
			c := newTestClient(t, s.Handler(), "secret")
			w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: tc.reqName, EphemeralPublic: tc.pub})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid request = %d, want 400: %s", w.Code, w.Body.String())
			}
			if got := broker.count(); got != 0 {
				t.Fatalf("broker resolved %d times before validation", got)
			}
			if n := memSecretReceipts(s, jobID); n != 0 {
				t.Fatalf("invalid request recorded %d receipts", n)
			}
		})
	}
	t.Run("db store untouched", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		broker := &countingBroker{}
		s.SecretBroker = broker
		f.mu.Lock()
		f.claimErr = errors.New("claim store must not be touched")
		f.mu.Unlock()
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		c := newTestClient(t, s.Handler(), "secret")
		w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: "not-base64"})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid key = %d, want 400: %s", w.Code, w.Body.String())
		}
		if got := broker.count(); got != 0 {
			t.Fatalf("broker resolved %d times before validation", got)
		}
		if n := fakeSecretClaims(f, jobID); n != 0 {
			t.Fatalf("invalid request recorded %d claims", n)
		}
		if n := fakeSecretAudits(f, jobID); n != 0 {
			t.Fatalf("invalid request recorded %d audits", n)
		}
	})
}
